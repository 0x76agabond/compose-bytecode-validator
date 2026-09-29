//! Compose-owned bytecode validation host.
//!
//! The host compares two experimental paths over the same EVMole storage
//! observations: one keeps bytecode inference independent from VSL, while the
//! other allows explicitly reported VSL assumptions to resolve ambiguity.

use std::collections::BTreeMap;

pub(crate) mod calldata;
#[allow(clippy::module_inception)] // Keeps the experiment's public name `compose`.
pub mod compose;
pub mod compose_vsl_bias;
mod matcher;
pub(crate) mod storage;
mod types;
mod vsl_semantics;

use crate::{arguments::function_arguments, selectors::function_selectors};

use self::storage::contract_storage;

use types::RawStorageObservation;
pub use types::{
    ComposeEngine, ComposeEngineReport, ComposeValidationInput, ComposeValidationReport,
    ComposeValidationStatus, InferenceSource, ObservationVerdict, StorageObservation,
    VirtualStorageLayout, VirtualStorageLayoutKind, VirtualStorageLayoutRecord,
    VirtualStorageLayoutSource, VslBiasAssumption, VslSlotMatch,
};

/// Runs both inference paths over one bytecode analysis for direct comparison.
pub fn validate(input: &ComposeValidationInput) -> ComposeValidationReport {
    let observations = analyze_storage(&input.bytecode);
    ComposeValidationReport {
        compose: compose::validate_observations(input, &observations),
        compose_vsl_bias: compose_vsl_bias::validate_observations(input, &observations),
    }
}

/// Runs both paths and prints their observations and VSL assumptions.
pub fn validate_and_print(input: &ComposeValidationInput) -> ComposeValidationReport {
    let report = validate(input);
    println!(
        "[compose] stage=input bytecode_bytes={} vsl_records={}",
        input.bytecode.len(),
        input.virtual_storage_layout.records.len()
    );
    for (index, record) in input.virtual_storage_layout.records.iter().enumerate() {
        println!(
            "[compose] stage=vsl-record index={} id={} virtual_path={} kind={} slots={}",
            index,
            record.id,
            record.virtual_path,
            record.kind,
            record.slots.len()
        );
    }
    println!("{report}");
    report
}

pub(crate) fn analyze_storage(bytecode: &[u8]) -> Vec<RawStorageObservation> {
    let functions = function_selectors(bytecode, 0, None)
        .0
        .into_iter()
        .map(|(selector, (offset, _))| {
            let arguments = function_arguments(bytecode, &selector, 0);
            (selector, offset, arguments)
        })
        .collect::<Vec<_>>();
    let layouts = contract_storage(
        bytecode,
        functions
            .iter()
            .map(|(selector, offset, arguments)| (*selector, *offset, arguments)),
        0,
    );

    let observations = layouts
        .evidence
        .into_iter()
        .filter(|evidence| evidence.domain == "persistent")
        .map(|evidence| RawStorageObservation {
            slot: evidence.slot,
            symbolic_path: evidence.symbolic_path,
            offset: evidence.offset,
            inferred_type: evidence.inferred_type,
            candidate_types: Vec::new(),
            score: evidence.score,
            reads: (!evidence.is_write)
                .then_some(vec![evidence.selector])
                .unwrap_or_default(),
            writes: evidence
                .is_write
                .then_some(vec![evidence.selector])
                .unwrap_or_default(),
            is_write: evidence.is_write,
            mask: evidence.mask,
        })
        .collect::<Vec<_>>();
    collapse_candidates(observations)
}

fn collapse_candidates(observations: Vec<RawStorageObservation>) -> Vec<RawStorageObservation> {
    let mut groups = BTreeMap::<(Option<[u8; 32]>, u8, String), Vec<_>>::new();
    for observation in observations {
        let unresolved_path = if observation.slot.is_none() {
            observation.symbolic_path.clone()
        } else {
            String::new()
        };
        groups
            .entry((observation.slot, observation.offset, unresolved_path))
            .or_default()
            .push(observation);
    }

    groups
        .into_values()
        .map(|group| {
            let mut selected = group
                .iter()
                .max_by_key(|observation| observation.score)
                .cloned()
                .expect("candidate group is non-empty");
            selected.candidate_types = group
                .iter()
                .map(|observation| observation.inferred_type.clone())
                .collect();
            selected.candidate_types.sort();
            selected.candidate_types.dedup();
            selected.reads = group
                .iter()
                .flat_map(|observation| observation.reads.iter().copied())
                .collect();
            selected.reads.sort();
            selected.reads.dedup();
            selected.writes = group
                .iter()
                .flat_map(|observation| observation.writes.iter().copied())
                .collect();
            selected.writes.sort();
            selected.writes.dedup();
            selected.is_write = !selected.writes.is_empty();
            selected
        })
        .collect()
}
