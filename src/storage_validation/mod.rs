//! VSL-driven validation of persistent bytecode writes.
//!
//! This module deliberately does not infer a replacement storage layout. It
//! compares EVMole's recovered write variables against the canonical VSL that
//! Compose supplies for the full diamond.

mod types;
mod vsl;
mod write_effect;

use crate::{
    Slot,
    arguments::function_arguments,
    selectors::function_selectors,
    storage::{
        DelegateCallEvidence, DelegateCallTarget, StorageEvidence, StorageLayouts,
        StoragePathSegment, contract_storage_with_hints_options_compose,
    },
};
use std::collections::{BTreeMap, BTreeSet};
use vsl::{
    SemanticCompatibility, compare_semantic_types, expected_field_start_at, expected_type_at,
    has_container_shape_contradiction, raw_expected_type_at, storage_trace_hints,
    virtual_struct_child,
};
use write_effect::ComposeWriteEffect;

#[cfg(feature = "rpc")]
pub use types::HttpRpcCodeSource;
pub use types::{
    DelegateCallValidationContext, DelegateCallWarning, RuntimeCodeSource, StorageCollision,
    StorageDiagnostic, StorageLocation, StorageValidationInput, StorageValidationReport,
    UncertainStorageScope, ValidatedVariable, VirtualStorageLayout, VirtualStorageLayoutRecord,
};

#[derive(Clone, Debug)]
struct VslVariableMatch {
    virtual_path: String,
    expected_type: Option<String>,
    expected_width: Option<u16>,
    expected_field_start: Option<u8>,
    is_dynamic_array_header: bool,
    mapping_layers: usize,
    dynamic_array_layers: usize,
    array_strides: Vec<(usize, usize)>,
    struct_projection: Option<StructProjection>,
}

#[derive(Clone, Debug)]
struct StructProjection {
    container_virtual_path: String,
    member_slot: usize,
    member_offset: u8,
}

#[derive(Clone, Copy, Debug, Default)]
struct ContainerMatch {
    mapping_layers: usize,
    dynamic_array_layers: usize,
    observed_array_stride: Option<usize>,
}

enum VslPathMatch {
    Matched(VslVariableMatch),
    Contradiction {
        virtual_path: String,
        expected_type: String,
        reason: String,
    },
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VslCursorState {
    Field,
    StructRoot,
}

impl ContainerMatch {
    /// Summary used by the flat matcher when a recursive VSL path is unavailable.
    fn from_path(path: &[StoragePathSegment]) -> Self {
        let dynamic_array = path.iter().rev().find_map(|segment| match segment {
            StoragePathSegment::DynamicArray { index, stride } if index.is_some() => Some(*stride),
            StoragePathSegment::Mapping { .. }
            | StoragePathSegment::Offset { .. }
            | StoragePathSegment::DynamicArray { .. } => None,
        });
        Self {
            mapping_layers: usize::from(
                path.iter()
                    .any(|segment| matches!(segment, StoragePathSegment::Mapping { .. })),
            ),
            dynamic_array_layers: usize::from(
                path.iter()
                    .any(|segment| matches!(segment, StoragePathSegment::DynamicArray { .. })),
            ),
            observed_array_stride: dynamic_array.flatten(),
        }
    }

    fn has_mapping(&self) -> bool {
        self.mapping_layers > 0
    }

    fn has_dynamic_array(&self) -> bool {
        self.dynamic_array_layers > 0
    }
}

type WriteEvidenceKey = (Option<Slot>, usize, u8, [u8; 4], Option<usize>, String);

/// Validates persistent `SSTORE` evidence against the supplied full-diamond VSL.
pub fn validate(input: &StorageValidationInput) -> StorageValidationReport {
    let trace = trace_layouts(input, None);
    validate_layouts(&trace, &input.virtual_storage_layout)
}

/// Validates direct writes and recursively follows constant delegatecall targets.
///
/// Every target is checked against the same full-diamond VSL because
/// `DELEGATECALL` preserves the caller's storage context.
pub fn validate_with_delegate_calls(
    input: &StorageValidationInput,
    source: &dyn RuntimeCodeSource,
    context: DelegateCallValidationContext,
) -> StorageValidationReport {
    let trace = trace_layouts(input, None);
    let mut report = validate_layouts(&trace, &input.virtual_storage_layout);
    let mut visited = BTreeSet::new();
    follow_delegate_calls(
        &trace.layouts.delegate_calls,
        &input.virtual_storage_layout,
        source,
        context,
        &mut visited,
        &mut report,
        0,
    );
    report
}

struct TraceLayouts {
    layouts: StorageLayouts,
    analyzed_selectors: BTreeSet<[u8; 4]>,
    write_effects: write_effect::ComposeWriteEffects,
}

fn trace_layouts(
    input: &StorageValidationInput,
    selected_selectors: Option<&BTreeSet<[u8; 4]>>,
) -> TraceLayouts {
    let trace_hints = storage_trace_hints(&input.virtual_storage_layout);
    let functions = function_selectors(&input.bytecode, 0, None)
        .0
        .into_iter()
        .filter(|(selector, _)| selected_selectors.is_none_or(|wanted| wanted.contains(selector)))
        .map(|(selector, (offset, _))| {
            let arguments = function_arguments(&input.bytecode, &selector, 0);
            (selector, offset, arguments)
        })
        .collect::<Vec<_>>();
    if std::env::var_os("COMPOSE_TRACE_STORAGE").is_some() {
        for (selector, _, arguments) in &functions {
            let arguments = arguments
                .iter()
                .map(|argument| argument.sol_type_name())
                .collect::<Vec<_>>();
            eprintln!(
                "[storage-validation:function] selector={} arguments={arguments:?}",
                hex(selector)
            );
        }
    }
    let analyzed_selectors = functions.iter().map(|(selector, _, _)| *selector).collect();
    let layouts = contract_storage_with_hints_options_compose(
        &input.bytecode,
        functions
            .iter()
            .map(|(selector, offset, arguments)| (*selector, *offset, arguments)),
        0,
        &trace_hints,
        selected_selectors.is_none() && functions.is_empty(),
    );
    let clear_candidate_selectors = layouts
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.domain == "persistent"
                && evidence.is_write
                && evidence.write_pc.is_some()
                && evidence.field_width.is_none()
        })
        .map(|evidence| evidence.selector)
        .collect();
    let write_effects =
        write_effect::trace(&input.bytecode, &functions, &clear_candidate_selectors);

    if std::env::var_os("COMPOSE_TRACE_STORAGE").is_some() {
        for evidence in &layouts.evidence {
            eprintln!(
                "[storage-validation:evidence] domain={} slot={:?} path={} storage_path={:?} slot_delta={} offset={} field_width={:?} type={} known={} score={} write={} pc={:?} selector={} fallback={} mask={:?}",
                evidence.domain,
                evidence.slot,
                evidence.symbolic_path,
                evidence.storage_path,
                evidence.slot_delta,
                evidence.offset,
                evidence.field_width,
                evidence.inferred_type,
                evidence.value_type_known,
                evidence.score,
                evidence.is_write,
                evidence.write_pc,
                hex(&evidence.selector),
                evidence.is_fallback_probe,
                evidence.mask,
            );
        }
    }

    TraceLayouts {
        layouts,
        analyzed_selectors,
        write_effects,
    }
}

fn validate_layouts(
    trace: &TraceLayouts,
    layout: &VirtualStorageLayout,
) -> StorageValidationReport {
    let layouts = &trace.layouts;
    let mut report = StorageValidationReport::default();
    collect_byte_string_access_uncertainties(layouts, layout, &mut report);
    let write_evidence = best_write_evidence(&layouts.evidence);
    let supported_projection_groups =
        structurally_supported_projection_groups(&write_evidence, layout, &trace.write_effects);
    for evidence in write_evidence
        .into_iter()
        .filter(|evidence| evidence.domain == "persistent")
    {
        validate_write(
            evidence,
            layout,
            &supported_projection_groups,
            &trace.write_effects,
            &mut report,
        );
    }
    report
}

fn structurally_supported_projection_groups(
    evidence: &[&StorageEvidence],
    layout: &VirtualStorageLayout,
    write_effects: &write_effect::ComposeWriteEffects,
) -> BTreeSet<String> {
    let mut positions = BTreeMap::<String, BTreeSet<(usize, u8)>>::new();
    for item in evidence.iter().filter(|item| {
        item.domain == "persistent"
            && item.value_type_known
            && matches!(
                write_effect::classify(item, write_effects),
                ComposeWriteEffect::Assignment
            )
    }) {
        let VslPathMatch::Matched(matched) = match_vsl_variable(item, layout) else {
            continue;
        };
        let Some(projection) = matched.struct_projection else {
            continue;
        };
        positions
            .entry(projection.container_virtual_path)
            .or_default()
            .insert((projection.member_slot, projection.member_offset));
    }
    positions
        .into_iter()
        .filter_map(|(path, members)| (members.len() >= 2).then_some(path))
        .collect()
}

fn collect_byte_string_access_uncertainties(
    layouts: &StorageLayouts,
    layout: &VirtualStorageLayout,
    report: &mut StorageValidationReport,
) {
    for evidence in layouts
        .evidence
        .iter()
        .filter(|item| item.domain == "persistent" && !item.is_fallback_probe)
    {
        let Some(slot) = evidence.slot else {
            continue;
        };
        let VslPathMatch::Matched(matched) = match_vsl_variable(evidence, layout) else {
            continue;
        };
        let Some(expected_type) = matched.expected_type else {
            continue;
        };
        if !matches!(expected_type.as_str(), "bytes" | "string") {
            continue;
        }
        push_byte_string_uncertainty(
            report,
            StorageLocation {
                slot: hex(&slot),
                offset: evidence.offset,
                selector: hex(&evidence.selector),
                pc: evidence.write_pc,
                symbolic_path: evidence.symbolic_path.clone(),
            },
            matched.virtual_path,
        );
    }
}

fn follow_delegate_calls(
    calls: &[DelegateCallEvidence],
    layout: &VirtualStorageLayout,
    source: &dyn RuntimeCodeSource,
    context: DelegateCallValidationContext,
    visited: &mut BTreeSet<([u8; 20], [u8; 4])>,
    report: &mut StorageValidationReport,
    depth: usize,
) {
    for call in calls {
        let caller_selector = hex(&call.caller_selector);
        let target_description = delegate_target_description(&call.target);
        let Some(selector) = call.selector else {
            report.delegatecall_warnings.push(DelegateCallWarning {
                caller_selector,
                pc: call.pc,
                target: target_description,
                selector: None,
                reason: "delegatecall calldata selector could not be recovered".to_owned(),
            });
            continue;
        };
        if depth >= context.max_depth {
            report.delegatecall_warnings.push(DelegateCallWarning {
                caller_selector,
                pc: call.pc,
                target: target_description,
                selector: Some(hex(&selector)),
                reason: format!(
                    "delegatecall recursion reached depth limit {}",
                    context.max_depth
                ),
            });
            continue;
        }
        let Some(address) = resolve_delegate_target(
            &call.target,
            source,
            context.storage_address,
            &caller_selector,
            call.pc,
            selector,
            report,
        ) else {
            continue;
        };
        if !visited.insert((address, selector)) {
            report.delegatecall_warnings.push(DelegateCallWarning {
                caller_selector,
                pc: call.pc,
                target: target_description,
                selector: Some(hex(&selector)),
                reason: "delegatecall target and selector were already traced".to_owned(),
            });
            continue;
        }
        let code = match source.code_at(address) {
            Ok(code) if !code.is_empty() => code,
            Ok(_) => {
                report.delegatecall_warnings.push(DelegateCallWarning {
                    caller_selector,
                    pc: call.pc,
                    target: target_description,
                    selector: Some(hex(&selector)),
                    reason: "delegatecall target has empty runtime code".to_owned(),
                });
                continue;
            }
            Err(error) => {
                report.delegatecall_warnings.push(DelegateCallWarning {
                    caller_selector,
                    pc: call.pc,
                    target: target_description,
                    selector: Some(hex(&selector)),
                    reason: format!("failed to fetch delegatecall target code: {error}"),
                });
                continue;
            }
        };

        let target_input = StorageValidationInput {
            bytecode: code,
            virtual_storage_layout: layout.clone(),
        };
        let selectors = BTreeSet::from([selector]);
        let target_trace = trace_layouts(&target_input, Some(&selectors));
        if !target_trace.analyzed_selectors.contains(&selector) {
            report.delegatecall_warnings.push(DelegateCallWarning {
                caller_selector,
                pc: call.pc,
                target: target_description,
                selector: Some(hex(&selector)),
                reason: "delegatecall target does not expose the recovered ABI selector".to_owned(),
            });
            continue;
        }
        let target_report = validate_layouts(&target_trace, layout);
        merge_report(report, target_report);
        follow_delegate_calls(
            &target_trace.layouts.delegate_calls,
            layout,
            source,
            context,
            visited,
            report,
            depth + 1,
        );
    }
}

fn resolve_delegate_target(
    target: &DelegateCallTarget,
    source: &dyn RuntimeCodeSource,
    storage_address: [u8; 20],
    caller_selector: &str,
    pc: usize,
    selector: [u8; 4],
    report: &mut StorageValidationReport,
) -> Option<[u8; 20]> {
    match target {
        DelegateCallTarget::Constant(address) => Some(*address),
        DelegateCallTarget::Storage {
            slot: Some(slot),
            byte_offset,
            symbolic_path,
        } => {
            if *byte_offset > 12 {
                report.delegatecall_warnings.push(DelegateCallWarning {
                    caller_selector: caller_selector.to_owned(),
                    pc,
                    target: format!("storage slot={} path={symbolic_path}", hex(slot)),
                    selector: Some(hex(&selector)),
                    reason: "delegatecall address crosses a storage-word boundary".to_owned(),
                });
                return None;
            }
            let word = match source.storage_at(storage_address, *slot) {
                Ok(word) => word,
                Err(error) => {
                    report.delegatecall_warnings.push(DelegateCallWarning {
                        caller_selector: caller_selector.to_owned(),
                        pc,
                        target: format!("storage slot={} path={symbolic_path}", hex(slot)),
                        selector: Some(hex(&selector)),
                        reason: format!("failed to fetch delegatecall target storage: {error}"),
                    });
                    return None;
                }
            };
            let end = 32 - usize::from(*byte_offset);
            let mut address = [0_u8; 20];
            address.copy_from_slice(&word[end - 20..end]);
            Some(address)
        }
        DelegateCallTarget::Storage {
            slot: None,
            symbolic_path,
            ..
        } => {
            report.delegatecall_warnings.push(DelegateCallWarning {
                caller_selector: caller_selector.to_owned(),
                pc,
                target: format!("storage slot=unresolved path={symbolic_path}"),
                selector: Some(hex(&selector)),
                reason: "delegatecall target storage slot could not be resolved".to_owned(),
            });
            None
        }
        DelegateCallTarget::TransientStorage { symbolic_path } => {
            report.delegatecall_warnings.push(DelegateCallWarning {
                caller_selector: caller_selector.to_owned(),
                pc,
                target: format!("transient storage path={symbolic_path}"),
                selector: Some(hex(&selector)),
                reason:
                    "delegatecall target comes from transient storage, which is not chain-readable"
                        .to_owned(),
            });
            None
        }
        DelegateCallTarget::Calldata | DelegateCallTarget::Unresolved => {
            report.delegatecall_warnings.push(DelegateCallWarning {
                caller_selector: caller_selector.to_owned(),
                pc,
                target: delegate_target_description(target),
                selector: Some(hex(&selector)),
                reason: delegate_target_reason(target).to_owned(),
            });
            None
        }
    }
}

fn merge_report(report: &mut StorageValidationReport, other: StorageValidationReport) {
    report.collisions.extend(other.collisions);
    report.validated_variables.extend(other.validated_variables);
    report.uncertain_scopes.extend(other.uncertain_scopes);
    report.diagnostics.extend(other.diagnostics);
    report
        .delegatecall_warnings
        .extend(other.delegatecall_warnings);
}

fn delegate_target_description(target: &DelegateCallTarget) -> String {
    match target {
        DelegateCallTarget::Constant(address) => hex(address),
        DelegateCallTarget::Storage {
            slot,
            byte_offset,
            symbolic_path,
        } => {
            format!(
                "storage slot={} offset={byte_offset} path={symbolic_path}",
                slot.map(|slot| hex(&slot))
                    .unwrap_or_else(|| "unresolved".to_owned())
            )
        }
        DelegateCallTarget::TransientStorage { symbolic_path } => {
            format!("transient storage path={symbolic_path}")
        }
        DelegateCallTarget::Calldata => "calldata".to_owned(),
        DelegateCallTarget::Unresolved => "unresolved".to_owned(),
    }
}

fn delegate_target_reason(target: &DelegateCallTarget) -> &'static str {
    match target {
        DelegateCallTarget::Storage { .. } => {
            "delegatecall target is loaded from storage and requires deployed storage context"
        }
        DelegateCallTarget::TransientStorage { .. } => {
            "delegatecall target is loaded from transient storage"
        }
        DelegateCallTarget::Calldata => "delegatecall target is supplied by calldata",
        DelegateCallTarget::Unresolved => "delegatecall target could not be recovered",
        DelegateCallTarget::Constant(_) => unreachable!("constant targets are traceable"),
    }
}

fn best_write_evidence(evidence: &[StorageEvidence]) -> Vec<&StorageEvidence> {
    let mut best: BTreeMap<WriteEvidenceKey, &StorageEvidence> = BTreeMap::new();
    for item in evidence
        .iter()
        .filter(|item| item.domain == "persistent" && item.is_write && !item.is_fallback_probe)
    {
        let key = (
            item.slot,
            item.slot_delta,
            item.offset,
            item.selector,
            item.write_pc,
            item.symbolic_path.clone(),
        );
        match best.get(&key) {
            Some(current) if current.score >= item.score => {}
            _ => {
                best.insert(key, item);
            }
        }
    }
    best.into_values().collect()
}

fn validate_write(
    evidence: &StorageEvidence,
    layout: &VirtualStorageLayout,
    supported_projection_groups: &BTreeSet<String>,
    write_effects: &write_effect::ComposeWriteEffects,
    report: &mut StorageValidationReport,
) {
    let effect = write_effect::classify(evidence, write_effects);
    let mut normalized_evidence;
    let evidence = match effect {
        ComposeWriteEffect::ClearRange { offset, .. } if offset != evidence.offset => {
            normalized_evidence = evidence.clone();
            normalized_evidence.offset = offset;
            &normalized_evidence
        }
        ComposeWriteEffect::Assignment | ComposeWriteEffect::ClearRange { .. } => evidence,
    };

    let Some(slot) = evidence.slot else {
        report.diagnostics.push(StorageDiagnostic {
            selector: hex(&evidence.selector),
            pc: evidence.write_pc,
            symbolic_path: evidence.symbolic_path.clone(),
            message: "persistent write has no resolved storage root".to_owned(),
        });
        return;
    };
    let location = StorageLocation {
        slot: hex(&slot),
        offset: evidence.offset,
        selector: hex(&evidence.selector),
        pc: evidence.write_pc,
        symbolic_path: evidence.symbolic_path.clone(),
    };
    let matched = match match_vsl_variable(evidence, layout) {
        VslPathMatch::Matched(matched) => matched,
        VslPathMatch::Contradiction {
            virtual_path,
            expected_type,
            reason,
        } => {
            report.collisions.push(StorageCollision {
                location,
                virtual_path,
                expected_type,
                observed_type: evidence.inferred_type.clone(),
                reason,
            });
            return;
        }
        VslPathMatch::NotFound => {
            report.uncertain_scopes.push(UncertainStorageScope {
                location,
                virtual_path: None,
                reason: "write root is not declared by the canonical VSL".to_owned(),
            });
            return;
        }
    };

    if let ComposeWriteEffect::ClearRange { offset, width } = effect {
        report.uncertain_scopes.push(UncertainStorageScope {
            location,
            virtual_path: Some(matched.virtual_path),
            reason: format!(
                "clear-only write covers byte range {offset}..{} but carries no value-type evidence",
                usize::from(offset) + usize::from(width / 8)
            ),
        });
        return;
    }

    let Some(expected_type) = matched.expected_type else {
        report.uncertain_scopes.push(UncertainStorageScope {
            location,
            virtual_path: Some(matched.virtual_path),
            reason: "VSL type is unsupported by the current comparator".to_owned(),
        });
        return;
    };
    let observed_type = unwrap_container_layers(
        &evidence.inferred_type,
        matched.mapping_layers,
        matched.dynamic_array_layers,
    )
    .unwrap_or_else(|| evidence.inferred_type.clone());

    if let Some((expected_stride, observed_stride)) = matched
        .array_strides
        .iter()
        .find(|(expected, observed)| expected != observed)
    {
        report.collisions.push(StorageCollision {
            location,
            virtual_path: matched.virtual_path,
            expected_type,
            observed_type,
            reason: format!(
                "dynamic-array element stride {observed_stride} slots contradicts expected {expected_stride} slots"
            ),
        });
        return;
    }

    if expected_type.contains("virtual-struct(") {
        report.uncertain_scopes.push(UncertainStorageScope {
            location,
            virtual_path: Some(matched.virtual_path),
            reason: "container child write is known, but its VSL member path is not reconstructed"
                .to_owned(),
        });
        return;
    }

    if matches!(expected_type.as_str(), "bytes" | "string") {
        push_byte_string_uncertainty(report, location, matched.virtual_path);
        return;
    }

    // A mask proves a concrete mapping-value field write. If that value is
    // not represented by a virtual child record, comparing it to the mapping
    // root would turn missing path reconstruction into a false collision.
    let containers = ContainerMatch::from_path(&evidence.storage_path);
    if containers.has_mapping() && matched.mapping_layers == 0 && evidence.field_width.is_some() {
        report.uncertain_scopes.push(UncertainStorageScope {
            location,
            virtual_path: Some(matched.virtual_path),
            reason: "mapping value write is known, but its VSL member path is not reconstructed"
                .to_owned(),
        });
        return;
    }

    if matched.is_dynamic_array_header || is_plain_dynamic_array_header(evidence, &expected_type) {
        report.validated_variables.push(ValidatedVariable {
            location,
            virtual_path: matched.virtual_path,
            expected_type,
            observed_type: "dynamic-array length".to_owned(),
        });
        return;
    }

    let Some(expected_width) = matched.expected_width else {
        if let (Some(observed_width), Some(expected_start)) =
            (evidence.field_width, matched.expected_field_start)
        {
            report.collisions.push(StorageCollision {
                location,
                virtual_path: matched.virtual_path,
                expected_type,
                observed_type: observed_type.clone(),
                reason: format!(
                    "packed write starts at byte {} with width {observed_width} bits, but the VSL field starts at byte {expected_start}",
                    evidence.offset
                ),
            });
            return;
        }
        report.uncertain_scopes.push(UncertainStorageScope {
            location,
            virtual_path: Some(matched.virtual_path),
            reason: "VSL has no field at the recovered byte offset".to_owned(),
        });
        return;
    };

    if let Some(observed_width) = evidence.field_width
        && observed_width != expected_width
    {
        report.collisions.push(StorageCollision {
            location,
            virtual_path: matched.virtual_path,
            expected_type,
            observed_type: observed_type.clone(),
            reason: format!(
                "packed write width {observed_width} bits contradicts expected {expected_width} bits"
            ),
        });
        return;
    }

    if !evidence.value_type_known {
        if has_container_shape_contradiction(&observed_type, &expected_type) {
            report.collisions.push(StorageCollision {
                location,
                virtual_path: matched.virtual_path,
                expected_type,
                observed_type: observed_type.clone(),
                reason: "recovered container shape contradicts the VSL type".to_owned(),
            });
        } else {
            report.uncertain_scopes.push(UncertainStorageScope {
                location,
                virtual_path: Some(matched.virtual_path),
                reason: "write position is known, but its value type was not recovered".to_owned(),
            });
        }
        return;
    }

    let Some(observed_width) = inferred_width(&observed_type) else {
        report.uncertain_scopes.push(UncertainStorageScope {
            location,
            virtual_path: Some(matched.virtual_path),
            reason: "bytecode write has no recoverable value width".to_owned(),
        });
        return;
    };

    if observed_width != expected_width {
        report.collisions.push(StorageCollision {
            location,
            virtual_path: matched.virtual_path,
            expected_type,
            observed_type: observed_type.clone(),
            reason: format!(
                "write width {observed_width} bits contradicts expected {expected_width} bits"
            ),
        });
        return;
    }

    match compare_semantic_types(&observed_type, &expected_type) {
        SemanticCompatibility::Compatible | SemanticCompatibility::KeyMismatch => {
            let projection_is_supported = matched.struct_projection.as_ref().is_none_or(|item| {
                supported_projection_groups.contains(&item.container_virtual_path)
            });
            if projection_is_supported {
                report.validated_variables.push(ValidatedVariable {
                    location,
                    virtual_path: matched.virtual_path,
                    expected_type,
                    observed_type,
                });
            } else {
                push_terminal_projection_uncertainty(report, location, matched.virtual_path);
            }
        }
        SemanticCompatibility::Contradiction => report.collisions.push(StorageCollision {
            location,
            virtual_path: matched.virtual_path,
            expected_type,
            observed_type,
            reason: "recovered bytecode variable contradicts the VSL type".to_owned(),
        }),
        SemanticCompatibility::Uncertain => report.uncertain_scopes.push(UncertainStorageScope {
            location,
            virtual_path: Some(matched.virtual_path),
            reason: "bytecode and VSL types cannot be compared conclusively".to_owned(),
        }),
    }
}

fn push_terminal_projection_uncertainty(
    report: &mut StorageValidationReport,
    location: StorageLocation,
    virtual_path: String,
) {
    const REASON: &str = "recovered write matches one VSL struct member, but bytecode does not prove the complete container element shape";
    if report.uncertain_scopes.iter().any(|scope| {
        scope.virtual_path.as_deref() == Some(virtual_path.as_str())
            && scope.location.selector == location.selector
            && scope.reason == REASON
    }) {
        return;
    }
    report.uncertain_scopes.push(UncertainStorageScope {
        location,
        virtual_path: Some(virtual_path),
        reason: REASON.to_owned(),
    });
}

fn push_byte_string_uncertainty(
    report: &mut StorageValidationReport,
    location: StorageLocation,
    virtual_path: String,
) {
    const REASON: &str =
        "bytes and string storage accesses cannot be compared conclusively from bytecode";
    if report.uncertain_scopes.iter().any(|scope| {
        scope.virtual_path.as_deref() == Some(virtual_path.as_str())
            && scope.location.selector == location.selector
            && scope.reason == REASON
    }) {
        return;
    }
    report.uncertain_scopes.push(UncertainStorageScope {
        location,
        virtual_path: Some(virtual_path),
        reason: REASON.to_owned(),
    });
}

fn is_plain_dynamic_array_header(evidence: &StorageEvidence, expected_type: &str) -> bool {
    evidence.storage_path.is_empty()
        && evidence.offset == 0
        && evidence.inferred_type == "uint256"
        && expected_type.trim().ends_with("[]")
}

fn match_vsl_variable(evidence: &StorageEvidence, layout: &VirtualStorageLayout) -> VslPathMatch {
    match match_recursive_vsl_variable(evidence, layout) {
        VslPathMatch::NotFound => match_flat_vsl_variable(evidence, layout)
            .map(VslPathMatch::Matched)
            .unwrap_or(VslPathMatch::NotFound),
        result => result,
    }
}

fn match_recursive_vsl_variable(
    evidence: &StorageEvidence,
    layout: &VirtualStorageLayout,
) -> VslPathMatch {
    // Plain slot writes need the flat matcher so its physical packing table can
    // select the field at the recovered byte offset.
    if evidence.storage_path.is_empty() {
        return VslPathMatch::NotFound;
    }

    let Some(slot) = evidence.slot.as_ref() else {
        return VslPathMatch::NotFound;
    };
    for root_record in layout
        .records
        .iter()
        .filter(|record| record.parent_virtual_path.is_none())
    {
        let Some(root) = decode_slot(&root_record.id) else {
            continue;
        };
        let Some(slot_index) = slot_delta(&root, slot, root_record.slots.len()) else {
            continue;
        };
        let result = match_recursive_vsl_root(evidence, layout, root_record, slot_index);
        if !matches!(result, VslPathMatch::NotFound) {
            return result;
        }
    }
    VslPathMatch::NotFound
}

fn match_recursive_vsl_root(
    evidence: &StorageEvidence,
    layout: &VirtualStorageLayout,
    root_record: &VirtualStorageLayoutRecord,
    initial_slot_index: usize,
) -> VslPathMatch {
    let mut record = root_record;
    let mut slot_index = initial_slot_index;
    let Some(mut current) = raw_expected_type_at(record, slot_index, 0) else {
        return VslPathMatch::NotFound;
    };
    let mut containers = ContainerMatch::default();
    let mut array_strides = Vec::new();
    let mut saw_container = false;
    let mut resolved_struct_child = false;
    let mut consumed_byte_string_payload = false;
    let mut cursor_state = VslCursorState::Field;

    // Transition table: container segments unwrap the current field schema;
    // offsets select either a root field or a field in the current child struct.
    for segment in &evidence.storage_path {
        match segment {
            StoragePathSegment::Offset { slots } => {
                if consumed_byte_string_payload || (saw_container && current.is_byte_string()) {
                    // An offset after a bytes/string container belongs to its
                    // element or long-data payload, not to the next VSL field.
                    continue;
                } else if matches!(cursor_state, VslCursorState::StructRoot) {
                    slot_index = *slots;
                    let Some(next) = raw_expected_type_at(record, slot_index, 0) else {
                        return VslPathMatch::Contradiction {
                            virtual_path: format!("{}.slot[{slot_index}]", record.virtual_path),
                            expected_type: format!("virtual-struct({})", record.virtual_path),
                            reason:
                                "bytecode storage path selects a slot beyond the VSL struct span"
                                    .to_owned(),
                        };
                    };
                    current = next;
                    cursor_state = VslCursorState::Field;
                } else if current.is_virtual_struct() {
                    let Some(child) = virtual_struct_child(record, &layout.records, slot_index)
                    else {
                        return VslPathMatch::NotFound;
                    };
                    record = child;
                    slot_index = *slots;
                    let Some(next) = raw_expected_type_at(record, slot_index, 0) else {
                        return VslPathMatch::NotFound;
                    };
                    current = next;
                    resolved_struct_child = true;
                    cursor_state = VslCursorState::Field;
                } else if !saw_container {
                    let Some(next_slot_index) = slot_index.checked_add(*slots) else {
                        return VslPathMatch::NotFound;
                    };
                    slot_index = next_slot_index;
                    let Some(next) = raw_expected_type_at(record, slot_index, 0) else {
                        return VslPathMatch::NotFound;
                    };
                    current = next;
                } else {
                    return VslPathMatch::NotFound;
                }
            }
            StoragePathSegment::Mapping { .. } => {
                if current.is_virtual_struct() {
                    if !resolve_virtual_cursor(
                        &mut record,
                        &mut slot_index,
                        &mut current,
                        &layout.records,
                    ) {
                        return VslPathMatch::NotFound;
                    }
                    resolved_struct_child = true;
                }
                let Some(value) = current.mapping_value() else {
                    return container_path_contradiction(
                        record,
                        slot_index,
                        &current.display(),
                        "mapping",
                    );
                };
                current = value.clone();
                containers.mapping_layers += 1;
                saw_container = true;
                cursor_state = VslCursorState::Field;
                if current.is_virtual_struct() {
                    if !resolve_virtual_cursor(
                        &mut record,
                        &mut slot_index,
                        &mut current,
                        &layout.records,
                    ) {
                        return VslPathMatch::NotFound;
                    }
                    resolved_struct_child = true;
                    cursor_state = VslCursorState::StructRoot;
                }
            }
            StoragePathSegment::DynamicArray { index, stride } => {
                if current.is_virtual_struct() {
                    if !resolve_virtual_cursor(
                        &mut record,
                        &mut slot_index,
                        &mut current,
                        &layout.records,
                    ) {
                        return VslPathMatch::NotFound;
                    }
                    resolved_struct_child = true;
                }
                if current.is_byte_string() && !consumed_byte_string_payload {
                    // Long bytes/string payloads live at keccak256(field slot).
                    // EVMole surfaces that physical path as another dynamic array.
                    consumed_byte_string_payload = true;
                    saw_container = true;
                    cursor_state = VslCursorState::Field;
                    continue;
                }
                let Some(element) = current.dynamic_array_element() else {
                    return container_path_contradiction(
                        record,
                        slot_index,
                        &current.display(),
                        "dynamic array",
                    );
                };
                current = element.clone();
                containers.dynamic_array_layers += 1;
                saw_container = true;
                cursor_state = VslCursorState::Field;
                if current.is_virtual_struct() {
                    let Some(child) = virtual_struct_child(record, &layout.records, slot_index)
                    else {
                        return VslPathMatch::NotFound;
                    };
                    if let Some(observed_stride) = stride.filter(|_| index.is_some()) {
                        array_strides.push((child.slots.len(), observed_stride));
                    }
                    record = child;
                    slot_index = 0;
                    let Some(next) = raw_expected_type_at(record, slot_index, 0) else {
                        return VslPathMatch::NotFound;
                    };
                    current = next;
                    resolved_struct_child = true;
                    cursor_state = VslCursorState::StructRoot;
                }
            }
        }
    }

    if current.is_virtual_struct()
        && !resolve_virtual_cursor(&mut record, &mut slot_index, &mut current, &layout.records)
    {
        return VslPathMatch::NotFound;
    }
    let mut matched = if resolved_struct_child {
        vsl_variable_match(
            record,
            layout,
            slot_index,
            evidence.offset,
            containers,
            array_strides,
        )
    } else {
        terminal_vsl_variable_match(
            record,
            slot_index,
            &current,
            evidence.offset,
            containers,
            array_strides,
        )
    };

    if resolved_struct_child
        && saw_container
        && let Some(matched) = matched.as_mut()
    {
        matched.struct_projection = Some(StructProjection {
            container_virtual_path: record.virtual_path.clone(),
            member_slot: slot_index,
            member_offset: evidence.offset,
        });
    }

    matched
        .map(VslPathMatch::Matched)
        .unwrap_or(VslPathMatch::NotFound)
}

fn resolve_virtual_cursor<'a>(
    record: &mut &'a VirtualStorageLayoutRecord,
    slot_index: &mut usize,
    current: &mut vsl::VslType,
    all_records: &'a [VirtualStorageLayoutRecord],
) -> bool {
    if !current.is_virtual_struct() {
        return true;
    }
    let Some(child) = virtual_struct_child(record, all_records, *slot_index) else {
        return false;
    };
    let Some(next) = raw_expected_type_at(child, 0, 0) else {
        return false;
    };
    *record = child;
    *slot_index = 0;
    *current = next;
    true
}

fn container_path_contradiction(
    record: &VirtualStorageLayoutRecord,
    slot_index: usize,
    expected_type: &str,
    observed_container: &str,
) -> VslPathMatch {
    VslPathMatch::Contradiction {
        virtual_path: format!("{}.slot[{slot_index}]", record.virtual_path),
        expected_type: expected_type.to_owned(),
        reason: format!("bytecode storage path uses {observed_container}, but the VSL does not"),
    }
}

fn match_flat_vsl_variable(
    evidence: &StorageEvidence,
    layout: &VirtualStorageLayout,
) -> Option<VslVariableMatch> {
    let slot = evidence.slot.as_ref()?;
    let containers = ContainerMatch::from_path(&evidence.storage_path);
    layout
        .records
        .iter()
        .filter(|record| record.parent_virtual_path.is_none())
        .find_map(|record| {
            let root = decode_slot(&record.id)?;
            let slot_index = slot_delta(&root, slot, record.slots.len())?;
            let container_type = expected_type_at(record, &layout.records, slot_index, 0);
            let child_path = container_type.as_deref().and_then(|container_type| {
                if containers.has_mapping() {
                    virtual_struct_path(container_type)
                } else if containers.has_dynamic_array()
                    && containers.observed_array_stride.is_some()
                {
                    dynamic_array_virtual_struct_path(container_type)
                } else {
                    None
                }
            });
            let child = child_path.and_then(|path| {
                layout.records.iter().find(|child| {
                    child.virtual_path == path
                        && child.parent_virtual_path.as_deref()
                            == Some(record.virtual_path.as_str())
                })
            });

            match child {
                Some(child) => vsl_variable_match(
                    child,
                    layout,
                    evidence.slot_delta,
                    evidence.offset,
                    containers,
                    containers
                        .observed_array_stride
                        .map(|observed| vec![(child.slots.len(), observed)])
                        .unwrap_or_default(),
                ),
                None => vsl_variable_match(
                    record,
                    layout,
                    slot_index,
                    evidence.offset,
                    ContainerMatch::default(),
                    Vec::new(),
                ),
            }
        })
}

fn vsl_variable_match(
    record: &VirtualStorageLayoutRecord,
    layout: &VirtualStorageLayout,
    slot_index: usize,
    offset: u8,
    container: ContainerMatch,
    array_strides: Vec<(usize, usize)>,
) -> Option<VslVariableMatch> {
    record.slots.get(slot_index)?;
    let expected_field_start = expected_field_start_at(record, slot_index, offset);
    Some(VslVariableMatch {
        virtual_path: format!("{}.slot[{slot_index}].byte[{offset}]", record.virtual_path),
        expected_type: expected_type_at(record, &layout.records, slot_index, offset).or_else(
            || {
                expected_field_start
                    .and_then(|start| expected_type_at(record, &layout.records, slot_index, start))
            },
        ),
        expected_width: expected_width_at(record, slot_index, offset),
        expected_field_start,
        is_dynamic_array_header: false,
        mapping_layers: container.mapping_layers,
        dynamic_array_layers: container.dynamic_array_layers,
        array_strides,
        struct_projection: None,
    })
}

/// Builds a match from the VSL cursor after a recursive path walk. Unlike the
/// flat matcher, `current` is already the schema selected by mapping/array
/// segments, so a mapping value scalar must not be compared with its mapping
/// declaration and a terminal dynamic array denotes its header slot.
fn terminal_vsl_variable_match(
    record: &VirtualStorageLayoutRecord,
    slot_index: usize,
    current: &vsl::VslType,
    offset: u8,
    container: ContainerMatch,
    array_strides: Vec<(usize, usize)>,
) -> Option<VslVariableMatch> {
    record.slots.get(slot_index)?;
    let expected_field_start = expected_field_start_at(record, slot_index, offset);
    Some(VslVariableMatch {
        virtual_path: format!("{}.slot[{slot_index}].byte[{offset}]", record.virtual_path),
        expected_type: Some(current.display()),
        expected_width: current.scalar_width(),
        expected_field_start,
        is_dynamic_array_header: matches!(current, vsl::VslType::DynamicArray(_)),
        mapping_layers: container.mapping_layers,
        dynamic_array_layers: container.dynamic_array_layers,
        array_strides,
        struct_projection: None,
    })
}

fn virtual_struct_path(expected_type: &str) -> Option<&str> {
    let prefix = "virtual-struct(";
    let start = expected_type.find(prefix)? + prefix.len();
    let end = expected_type[start..].find(')')? + start;
    Some(&expected_type[start..end])
}

fn dynamic_array_virtual_struct_path(expected_type: &str) -> Option<&str> {
    virtual_struct_path(expected_type.strip_suffix("[]")?)
}

fn unwrap_container_layers(
    value: &str,
    mapping_layers: usize,
    dynamic_array_layers: usize,
) -> Option<String> {
    let mut current = value.trim();
    for _ in 0..mapping_layers {
        let body = current.strip_prefix("mapping(")?.strip_suffix(')')?;
        let mut depth = 0_i32;
        let mut value_start = None;
        for (index, window) in body.as_bytes().windows(2).enumerate() {
            match window[0] {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                _ => {}
            }
            if depth == 0 && window == b"=>" {
                value_start = Some(index + 2);
                break;
            }
        }
        current = body.get(value_start?..)?.trim();
    }
    for _ in 0..dynamic_array_layers {
        current = current.strip_suffix("[]")?.trim();
    }
    Some(current.to_owned())
}

fn expected_width_at(
    record: &VirtualStorageLayoutRecord,
    slot_index: usize,
    offset: u8,
) -> Option<u16> {
    let group = record.slots.get(slot_index)?;
    let mut current_offset = 0_u16;
    for width in group {
        if current_offset / 8 == u16::from(offset) {
            return Some(*width);
        }
        current_offset = current_offset.saturating_add(*width);
    }
    None
}

fn inferred_width(inferred_type: &str) -> Option<u16> {
    if inferred_type.starts_with("mapping(")
        || inferred_type.ends_with(']')
        || matches!(inferred_type, "bytes" | "string" | "uint256")
    {
        return Some(256);
    }
    if inferred_type == "bool" {
        return Some(8);
    }
    if inferred_type == "address" {
        return Some(160);
    }
    if inferred_type.starts_with("function") {
        return Some(192);
    }
    numeric_suffix(inferred_type, "uint")
        .or_else(|| numeric_suffix(inferred_type, "int"))
        .or_else(|| numeric_suffix(inferred_type, "bytes").and_then(|bytes| bytes.checked_mul(8)))
}

fn numeric_suffix(value: &str, prefix: &str) -> Option<u16> {
    let suffix = value.strip_prefix(prefix)?;
    (!suffix.is_empty())
        .then(|| suffix.parse::<u16>().ok())
        .flatten()
}

fn decode_slot(value: &str) -> Option<Slot> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() || value.len() > 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let padded = format!("{value:0>64}");
    let mut slot = [0_u8; 32];
    for (index, byte) in slot.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&padded[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(slot)
}

fn slot_delta(root: &Slot, slot: &Slot, span: usize) -> Option<usize> {
    let mut current = *root;
    for delta in 0..span {
        if &current == slot {
            return Some(delta);
        }
        increment_slot(&mut current)?;
    }
    None
}

fn increment_slot(slot: &mut Slot) -> Option<()> {
    for byte in slot.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            return Some(());
        }
    }
    None
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(2 + bytes.len() * 2);
    output.push_str("0x");
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        follow_delegate_calls, inferred_width, resolve_delegate_target, slot_delta, validate_write,
    };
    use crate::{
        Selector, Slot,
        compose::{
            VirtualStorageLayoutKind, VirtualStorageLayoutRecord, VirtualStorageLayoutSource,
        },
        storage::{DelegateCallEvidence, DelegateCallTarget, StorageEvidence},
        storage_validation::{
            DelegateCallValidationContext, RuntimeCodeSource, StorageValidationReport,
            VirtualStorageLayout,
        },
    };
    use std::collections::BTreeSet;

    struct TestCodeSource {
        code: Result<Vec<u8>, String>,
        storage: Result<[u8; 32], String>,
    }

    impl RuntimeCodeSource for TestCodeSource {
        fn code_at(&self, _: [u8; 20]) -> Result<Vec<u8>, String> {
            self.code.clone()
        }

        fn storage_at(&self, _: [u8; 20], _: [u8; 32]) -> Result<[u8; 32], String> {
            self.storage.clone()
        }
    }

    #[test]
    fn resolves_a_packed_delegate_target_from_chain_storage() {
        let expected = [0xabu8; 20];
        let mut word = [0_u8; 32];
        // An address shifted by four bytes is packed into bytes 8..28.
        word[8..28].copy_from_slice(&expected);
        let source = TestCodeSource {
            code: Ok(Vec::new()),
            storage: Ok(word),
        };
        let target = DelegateCallTarget::Storage {
            slot: Some([0x11; 32]),
            byte_offset: 4,
            symbolic_path: "Plain(0x11)".to_owned(),
        };
        let mut report = StorageValidationReport::default();

        let resolved = resolve_delegate_target(
            &target,
            &source,
            [0x22; 20],
            "0x12345678",
            12,
            [0x12, 0x34, 0x56, 0x78],
            &mut report,
        );

        assert_eq!(resolved, Some(expected));
        assert!(report.delegatecall_warnings.is_empty());
    }

    #[test]
    fn scopes_delegate_target_storage_fetch_failures_as_warnings() {
        let source = TestCodeSource {
            code: Ok(Vec::new()),
            storage: Err("offline".to_owned()),
        };
        let target = DelegateCallTarget::Storage {
            slot: Some([0x11; 32]),
            byte_offset: 0,
            symbolic_path: "Plain(0x11)".to_owned(),
        };
        let mut report = StorageValidationReport::default();

        assert!(
            resolve_delegate_target(
                &target,
                &source,
                [0x22; 20],
                "0x12345678",
                12,
                [0x12, 0x34, 0x56, 0x78],
                &mut report,
            )
            .is_none()
        );

        assert_eq!(report.delegatecall_warnings.len(), 1);
        assert!(
            report.delegatecall_warnings[0]
                .reason
                .contains("failed to fetch delegatecall target storage")
        );
    }

    #[test]
    fn scopes_untraceable_delegate_targets_as_warnings() {
        let source = TestCodeSource {
            code: Ok(Vec::new()),
            storage: Ok([0; 32]),
        };
        let targets = [
            DelegateCallTarget::Calldata,
            DelegateCallTarget::Unresolved,
            DelegateCallTarget::TransientStorage {
                symbolic_path: "Plain(0x01)".to_owned(),
            },
            DelegateCallTarget::Storage {
                slot: None,
                byte_offset: 0,
                symbolic_path: "UnknownHash".to_owned(),
            },
        ];
        let mut report = StorageValidationReport::default();

        for target in &targets {
            assert!(
                resolve_delegate_target(
                    target,
                    &source,
                    [0x22; 20],
                    "0x12345678",
                    12,
                    [0x12, 0x34, 0x56, 0x78],
                    &mut report,
                )
                .is_none()
            );
        }

        assert_eq!(report.delegatecall_warnings.len(), targets.len());
    }

    #[test]
    fn reports_unavailable_delegate_target_code_as_a_scoped_warning() {
        let call = DelegateCallEvidence {
            target: DelegateCallTarget::Constant([0x44; 20]),
            selector: Some([0x12, 0x34, 0x56, 0x78]),
            pc: 7,
            caller_selector: [0xaa; 4],
        };
        let context = DelegateCallValidationContext::new([0x55; 20]);
        let mut report = StorageValidationReport::default();
        let mut visited = BTreeSet::new();
        let source = TestCodeSource {
            code: Err("offline".to_owned()),
            storage: Ok([0; 32]),
        };

        follow_delegate_calls(
            &[call],
            &VirtualStorageLayout::default(),
            &source,
            context,
            &mut visited,
            &mut report,
            0,
        );

        assert_eq!(report.delegatecall_warnings.len(), 1);
        assert!(
            report.delegatecall_warnings[0]
                .reason
                .contains("failed to fetch delegatecall target code")
        );
    }

    #[test]
    fn reports_empty_or_selectorless_delegate_target_code_as_warnings() {
        let call = DelegateCallEvidence {
            target: DelegateCallTarget::Constant([0x44; 20]),
            selector: Some([0x12, 0x34, 0x56, 0x78]),
            pc: 7,
            caller_selector: [0xaa; 4],
        };
        let context = DelegateCallValidationContext::new([0x55; 20]);

        let mut empty_report = StorageValidationReport::default();
        follow_delegate_calls(
            &[call.clone()],
            &VirtualStorageLayout::default(),
            &TestCodeSource {
                code: Ok(Vec::new()),
                storage: Ok([0; 32]),
            },
            context,
            &mut BTreeSet::new(),
            &mut empty_report,
            0,
        );
        assert!(
            empty_report.delegatecall_warnings[0]
                .reason
                .contains("empty runtime code")
        );

        let mut selector_report = StorageValidationReport::default();
        follow_delegate_calls(
            &[call],
            &VirtualStorageLayout::default(),
            &TestCodeSource {
                code: Ok(vec![0x00]),
                storage: Ok([0; 32]),
            },
            context,
            &mut BTreeSet::new(),
            &mut selector_report,
            0,
        );
        assert!(
            selector_report.delegatecall_warnings[0]
                .reason
                .contains("does not expose the recovered ABI selector")
        );
    }

    #[test]
    fn reports_delegatecall_depth_and_cycles_as_warnings() {
        let target = [0x44; 20];
        let selector = [0x12, 0x34, 0x56, 0x78];
        let call = DelegateCallEvidence {
            target: DelegateCallTarget::Constant(target),
            selector: Some(selector),
            pc: 7,
            caller_selector: [0xaa; 4],
        };
        let source = TestCodeSource {
            code: Ok(Vec::new()),
            storage: Ok([0; 32]),
        };

        let mut depth_report = StorageValidationReport::default();
        follow_delegate_calls(
            &[call.clone()],
            &VirtualStorageLayout::default(),
            &source,
            DelegateCallValidationContext {
                storage_address: [0x55; 20],
                max_depth: 0,
            },
            &mut BTreeSet::new(),
            &mut depth_report,
            0,
        );
        assert!(
            depth_report.delegatecall_warnings[0]
                .reason
                .contains("depth limit")
        );

        let mut cycle_report = StorageValidationReport::default();
        let mut visited = BTreeSet::from([(target, selector)]);
        follow_delegate_calls(
            &[call],
            &VirtualStorageLayout::default(),
            &source,
            DelegateCallValidationContext::new([0x55; 20]),
            &mut visited,
            &mut cycle_report,
            0,
        );
        assert!(
            cycle_report.delegatecall_warnings[0]
                .reason
                .contains("already traced")
        );
    }

    #[test]
    fn keeps_mapping_and_arrays_as_word_variables() {
        assert_eq!(inferred_width("mapping(address => uint256)"), Some(256));
        assert_eq!(inferred_width("uint8[]"), Some(256));
    }

    #[test]
    fn resolves_static_vsl_slot_ranges() {
        let root = [0_u8; 32];
        let mut slot: Slot = root;
        slot[31] = 2;
        assert_eq!(slot_delta(&root, &slot, 3), Some(2));
    }

    #[test]
    fn reports_a_proven_width_collision_at_a_known_slot() {
        let layout = VirtualStorageLayout {
            records: vec![VirtualStorageLayoutRecord {
                id: "0x01".to_owned(),
                virtual_path: "fixture.root".to_owned(),
                parent_virtual_path: None,
                kind: VirtualStorageLayoutKind::Normal,
                code_width: 1,
                layout: vec!["0x01".to_owned()],
                serialized_layout: vec!["0x01".to_owned(), "0x01".to_owned()],
                slots: vec![vec![8]],
                source: VirtualStorageLayoutSource::SlotAssignment,
                source_name: "Fixture.sol".to_owned(),
                contract_name: "Fixture".to_owned(),
                struct_name: Some("Storage".to_owned()),
                diamond_name: None,
            }],
        };
        let evidence = StorageEvidence {
            domain: "persistent",
            slot: Some({
                let mut slot = [0_u8; 32];
                slot[31] = 1;
                slot
            }),
            symbolic_path: "Plain(0x01)".to_owned(),
            storage_path: Vec::new(),
            slot_delta: 0,
            offset: 0,
            field_width: None,
            inferred_type: "uint256".to_owned(),
            score: 1,
            is_write: true,
            value_type_known: true,
            write_pc: Some(42),
            selector: Selector::default(),
            is_fallback_probe: false,
            mask: None,
        };
        let mut report = StorageValidationReport::default();

        validate_write(
            &evidence,
            &layout,
            &BTreeSet::new(),
            &Default::default(),
            &mut report,
        );

        assert_eq!(report.collisions.len(), 1);
        assert!(report.uncertain_scopes.is_empty());
    }

    #[test]
    fn scopes_an_unmapped_write_to_its_concrete_slot() {
        let layout = VirtualStorageLayout::default();
        let evidence = StorageEvidence {
            domain: "persistent",
            slot: Some({
                let mut slot = [0_u8; 32];
                slot[31] = 9;
                slot
            }),
            symbolic_path: "Plain(0x09)".to_owned(),
            storage_path: Vec::new(),
            slot_delta: 0,
            offset: 0,
            field_width: None,
            inferred_type: "uint256".to_owned(),
            score: 1,
            is_write: true,
            value_type_known: true,
            write_pc: Some(9),
            selector: Selector::default(),
            is_fallback_probe: false,
            mask: None,
        };
        let mut report = StorageValidationReport::default();

        validate_write(
            &evidence,
            &layout,
            &BTreeSet::new(),
            &Default::default(),
            &mut report,
        );

        assert!(report.collisions.is_empty());
        assert_eq!(report.uncertain_scopes.len(), 1);
        assert_eq!(
            report.uncertain_scopes[0].location.slot,
            format!("0x{:064x}", 9)
        );
    }
}
