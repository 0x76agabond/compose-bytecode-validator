//! Compose-owned storage tracing extensions.
//!
//! The upstream EVMole tracer remains in `crate::storage`. This module keeps
//! Compose-only evidence, VSL hints, write paths, and delegatecall tracing out
//! of the generic decompiler API.
use crate::{
    DynSolType, Selector, Slot,
    collections::HashMap,
    compose::calldata::ComposeCallData,
    evm::{
        U256, VAL_1, VAL_1_B, VAL_32_B,
        calldata::{CallDataLabel, CallDataLabelType},
        element::Element,
        op,
        vm::{StepResult, Vm},
    },
    utils::{and_mask_to_type, elabel, execute_until_function_start, match_first_two},
};
use alloy_primitives::keccak256;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

/// Represents an inferred persistent or transient storage record.
///
/// The containing [`crate::Contract`] field identifies the storage domain.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct StorageRecord {
    /// Storage slot location for the variable
    #[cfg_attr(feature = "serde", serde(serialize_with = "crate::serialize::slot"))]
    pub slot: Slot,

    /// Byte offset within the storage slot (0-31)
    pub offset: u8,

    /// Variable type
    pub r#type: String,

    /// Function selectors that read from this storage location
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "crate::serialize::vec_selector")
    )]
    pub reads: Vec<Selector>,

    /// Function selectors that write to this storage location
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "crate::serialize::vec_selector")
    )]
    pub writes: Vec<Selector>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Label {
    Constant,

    Typed(DynSolType, Option<AffineExpr>),
    /// A typed value masked to a packed storage field before it is shifted
    /// into a read-modify-write `SSTORE` value.
    Packed(DynSolType),
    Loaded(Rc<RefCell<StorageElement>>),
    IsZero(Rc<RefCell<StorageElement>>),
    Keccak(u32, SlotExpr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AffineExpr {
    calldata_terms: BTreeMap<usize, U256>,
    constant: U256,
}

impl AffineExpr {
    fn calldata(offset: usize) -> Self {
        Self {
            calldata_terms: BTreeMap::from([(offset, U256::from(1))]),
            constant: U256::ZERO,
        }
    }

    fn add(&self, other: &Self) -> Option<Self> {
        let mut result = self.clone();
        result.constant = result.constant.checked_add(other.constant)?;
        for (source, coefficient) in &other.calldata_terms {
            let current = result
                .calldata_terms
                .get(source)
                .copied()
                .unwrap_or_default();
            result
                .calldata_terms
                .insert(*source, current.checked_add(*coefficient)?);
        }
        Some(result)
    }

    fn add_constant(&self, value: U256) -> Option<Self> {
        let mut result = self.clone();
        result.constant = result.constant.checked_add(value)?;
        Some(result)
    }

    fn multiply(&self, value: U256) -> Option<Self> {
        let mut result = self.clone();
        result.constant = result.constant.checked_mul(value)?;
        for coefficient in result.calldata_terms.values_mut() {
            *coefficient = coefficient.checked_mul(value)?;
        }
        Some(result)
    }

    fn scale_from(&self, scaled: &Self) -> Option<usize> {
        let (base, candidate) = self
            .calldata_terms
            .iter()
            .find(|(_, coefficient)| !coefficient.is_zero())
            .and_then(|(source, coefficient)| {
                scaled
                    .calldata_terms
                    .get(source)
                    .map(|scaled| (*coefficient, *scaled))
            })?;
        let factor = candidate.checked_div(base)?;
        if base.checked_mul(factor)? != candidate
            || self.multiply(factor).as_ref() != Some(scaled)
            || factor.is_zero()
            || factor > U256::from(usize::MAX)
        {
            return None;
        }
        Some(factor.to())
    }
}

/// Optional type anchors supplied by a host that already knows source storage.
///
/// The Compose tracer remains usable without these hints. They anchor scalar
/// values loaded as mapping keys and mapping key chains, but do not decide
/// whether a write is compatible with a layout.
#[derive(Clone, Debug, Default)]
pub(crate) struct StorageTraceHints {
    persistent_scalar_types: BTreeMap<Slot, DynSolType>,
    persistent_mapping_key_types: BTreeMap<Slot, Vec<DynSolType>>,
}

impl StorageTraceHints {
    pub(crate) fn insert_persistent_scalar_type(&mut self, slot: Slot, ty: DynSolType) {
        self.persistent_scalar_types.insert(slot, ty);
    }

    pub(crate) fn insert_persistent_mapping_key_types(
        &mut self,
        slot: Slot,
        key_types: Vec<DynSolType>,
    ) {
        self.persistent_mapping_key_types.insert(slot, key_types);
    }

    fn scalar_type(&self, domain: StorageDomain, slot: Option<Slot>) -> Option<DynSolType> {
        match domain {
            StorageDomain::Persistent => {
                slot.and_then(|slot| self.persistent_scalar_types.get(&slot).cloned())
            }
            StorageDomain::Transient => None,
        }
    }

    fn mapping_key_type(&self, base: &SlotExpr) -> Option<DynSolType> {
        let root = base.canonical_slot()?;
        let depth = mapping_depth(base);
        self.persistent_mapping_key_types
            .get(&root)
            .and_then(|types| types.get(depth).cloned())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SlotExpr {
    Plain(Slot),
    Mapping {
        key_type: DynSolType,
        base: Box<SlotExpr>,
    },
    /// A compile-time slot displacement from a mapping or array value root.
    ///
    /// The generic layout output intentionally groups these under the same
    /// container. Compose validation needs the displacement to match the VSL
    /// child schema, so it is preserved symbolically here.
    Offset {
        base: Box<SlotExpr>,
        slots: usize,
    },
    DynamicArray {
        base: Box<SlotExpr>,
    },
    DynamicArrayElement {
        base: Box<SlotExpr>,
        index: AffineExpr,
        stride: usize,
    },
    HashedConst {
        hash: Slot,
        preimage: Vec<u8>,
    },
    UnknownHash {
        size: u32,
        preimage: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum StorageDomain {
    Persistent,
    Transient,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum SlotKey {
    Known(Slot),
    UnknownHash { size: u32, preimage: Vec<u8> },
}

fn should_surface_hashed_slot(preimage: &[u8]) -> bool {
    if matches!(preimage.len(), 32 | 64) {
        return false;
    }

    if preimage.len() > 32 {
        let tail = &preimage[preimage.len() - 32..];
        if tail[..31].iter().all(|b| *b == 0) {
            return false;
        }
    }

    true
}

impl SlotExpr {
    fn canonical_slot(&self) -> Option<Slot> {
        match self {
            SlotExpr::Plain(slot) => Some(*slot),
            SlotExpr::HashedConst {
                hash: slot,
                preimage,
            } => should_surface_hashed_slot(preimage).then_some(*slot),
            SlotExpr::Mapping { base, .. }
            | SlotExpr::Offset { base, .. }
            | SlotExpr::DynamicArray { base }
            | SlotExpr::DynamicArrayElement { base, .. } => base.canonical_slot(),
            SlotExpr::UnknownHash { .. } => None,
        }
    }

    fn slot_key(&self) -> SlotKey {
        match self {
            SlotExpr::Plain(slot) | SlotExpr::HashedConst { hash: slot, .. } => {
                SlotKey::Known(*slot)
            }
            SlotExpr::Mapping { base, .. }
            | SlotExpr::Offset { base, .. }
            | SlotExpr::DynamicArray { base }
            | SlotExpr::DynamicArrayElement { base, .. } => base.slot_key(),
            SlotExpr::UnknownHash { size, preimage } => SlotKey::UnknownHash {
                size: *size,
                preimage: preimage.clone(),
            },
        }
    }
}

/// Ordered storage containers between a declared root and an observed write.
///
/// This preserves the symbolic route so later validation can recurse through
/// the same route instead of rebuilding container facts from flat metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StoragePathSegment {
    Mapping {
        key_type: String,
    },
    DynamicArray {
        index: Option<String>,
        stride: Option<usize>,
    },
    Offset {
        slots: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DelegateCallTarget {
    Constant([u8; 20]),
    Storage {
        slot: Option<Slot>,
        byte_offset: u8,
        symbolic_path: String,
    },
    TransientStorage {
        symbolic_path: String,
    },
    Calldata,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DelegateCallEvidence {
    pub target: DelegateCallTarget,
    pub selector: Option<Selector>,
    pub pc: usize,
    pub caller_selector: Selector,
}

fn storage_path(expr: &SlotExpr, path: &mut Vec<StoragePathSegment>) {
    match expr {
        SlotExpr::Mapping { key_type, base } => {
            storage_path(base, path);
            path.push(StoragePathSegment::Mapping {
                key_type: format!("{key_type:?}"),
            });
        }
        SlotExpr::Offset { base, slots } => {
            storage_path(base, path);
            path.push(StoragePathSegment::Offset { slots: *slots });
        }
        SlotExpr::DynamicArray { base } => {
            storage_path(base, path);
            path.push(StoragePathSegment::DynamicArray {
                index: None,
                stride: None,
            });
        }
        SlotExpr::DynamicArrayElement {
            base,
            index,
            stride,
        } => {
            let array_base = match base.as_ref() {
                SlotExpr::DynamicArray { base } => base.as_ref(),
                base => base,
            };
            storage_path(array_base, path);
            path.push(StoragePathSegment::DynamicArray {
                index: Some(format!("{index:?}")),
                stride: Some(*stride),
            });
        }
        SlotExpr::Plain(_) | SlotExpr::HashedConst { .. } | SlotExpr::UnknownHash { .. } => {}
    }
}

fn mapping_depth(expr: &SlotExpr) -> usize {
    match expr {
        SlotExpr::Mapping { base, .. } => 1 + mapping_depth(base),
        SlotExpr::Offset { base, .. }
        | SlotExpr::DynamicArray { base }
        | SlotExpr::DynamicArrayElement { base, .. } => mapping_depth(base),
        SlotExpr::Plain(_) | SlotExpr::HashedConst { .. } | SlotExpr::UnknownHash { .. } => 0,
    }
}

impl CallDataLabel for Label {
    fn label(offset: usize, tp: &DynSolType, label_type: CallDataLabelType) -> Option<Label> {
        if matches!(label_type, CallDataLabelType::RealValue) {
            let affine = matches!(tp, DynSolType::Uint(_)).then(|| AffineExpr::calldata(offset));
            Some(Label::Typed(tp.clone(), affine))
        } else {
            None
        }
    }
}

fn get_base_internal_type(val: &DynSolType) -> DynSolType {
    if let DynSolType::Array(t) = val {
        get_base_internal_type(t)
    } else {
        val.clone()
    }
}

fn get_base_score(t: &DynSolType) -> usize {
    match t {
        DynSolType::Uint(256) => 1,
        DynSolType::Uint(8) => 3,
        DynSolType::Bool => 4,
        DynSolType::FixedBytes(32) => 6,
        DynSolType::FixedBytes(_) => 2,
        DynSolType::String | DynSolType::Bytes => 500,
        DynSolType::Array(v) => 5 * get_base_score(v),
        _ => 5,
    }
}

#[derive(Clone, PartialEq, Eq)]
enum StorageType {
    Base(DynSolType),
    Map(DynSolType, Box<StorageType>),
}

impl StorageType {
    fn set_type(&mut self, tp: DynSolType) {
        if let StorageType::Base(DynSolType::String) = self {
            return;
        }
        match self {
            StorageType::Base(DynSolType::Array(v)) => {
                let mut current = v.as_mut();
                while let DynSolType::Array(inner) = current {
                    current = inner;
                    if let DynSolType::Uint(256) = &current {}
                }
                *current = tp;
            }
            StorageType::Base(v) => *v = tp,
            StorageType::Map(_, v) => v.set_type(tp),
        }
    }

    fn get_internal_type(&self) -> DynSolType {
        match self {
            StorageType::Base(t) => get_base_internal_type(t),
            StorageType::Map(_, v) => v.get_internal_type(),
        }
    }

    fn get_score(&self) -> usize {
        match self {
            StorageType::Base(t) => get_base_score(t),
            StorageType::Map(k, v) => 1000 * get_base_score(k) + v.get_score(),
        }
    }

    fn has_known_internal_type(&self) -> bool {
        !matches!(self.get_internal_type(), DynSolType::Uint(256))
    }

    fn is_string_like(&self) -> bool {
        matches!(
            self,
            StorageType::Base(DynSolType::String | DynSolType::Bytes)
        )
    }

    fn requires_zero_offset(&self) -> bool {
        match self {
            StorageType::Map(_, _) => true,
            StorageType::Base(t) => matches!(
                t,
                DynSolType::Array(_)
                    | DynSolType::FixedArray(_, _)
                    | DynSolType::String
                    | DynSolType::Bytes
                    | DynSolType::Uint(256)
                    | DynSolType::Int(256)
                    | DynSolType::FixedBytes(32)
            ),
        }
    }
}

impl std::fmt::Debug for StorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageType::Base(v) => write!(f, "{}", v.sol_type_name()),
            StorageType::Map(k, v) => write!(f, "mapping({} => {:?})", k.sol_type_name(), v),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct StorageElement {
    domain: StorageDomain,
    slot_key: SlotKey,
    slot: Option<Slot>,
    slot_expr: SlotExpr,
    stype: StorageType,
    slot_delta: usize,
    rshift: u8, // in bytes
    field_width: Option<u16>,
    is_write: bool,
    write_pc: Option<usize>,
    write_value_known: bool,
    last_and: Option<U256>,
    last_or2: Option<Element<Label>>,
}

struct WriteMetadata {
    rshift: u8,
    write_pc: usize,
    value_known: bool,
    field_width: Option<u16>,
}

impl std::fmt::Debug for StorageElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let slot_repr = self
            .slot
            .map(alloy_primitives::hex::encode)
            .unwrap_or_else(|| format!("{:?}", self.slot_expr));
        write!(
            f,
            "{}:{:?}:{}:{:?}",
            slot_repr, self.stype, self.rshift, self.last_and
        )
    }
}

type SlotHashMap = HashMap<(StorageDomain, SlotKey), Vec<Rc<RefCell<StorageElement>>>>;

fn known_constant_hash(
    data: &[u8],
    chunks: &[crate::evm::memory::MemoryChunk<Label>],
) -> Option<Slot> {
    let covered: usize = chunks
        .iter()
        .map(|chunk| chunk.dst_range.end - chunk.dst_range.start)
        .sum();
    if covered == data.len()
        && chunks
            .iter()
            .all(|chunk| matches!(chunk.src_label, Label::Constant))
    {
        Some(keccak256(data).0)
    } else {
        None
    }
}

fn full_word_label(
    chunks: &[crate::evm::memory::MemoryChunk<Label>],
    size: usize,
) -> Option<&Label> {
    match chunks {
        [chunk] if chunk.dst_range.start == 0 && chunk.dst_range.end == size => {
            Some(&chunk.src_label)
        }
        _ => None,
    }
}

fn word_slot_expr(
    data: Slot,
    chunks: &[crate::evm::memory::MemoryChunk<Label>],
) -> (SlotExpr, u32) {
    match full_word_label(chunks, 32) {
        Some(Label::Keccak(depth, expr)) => (expr.clone(), depth + 1),
        _ => (SlotExpr::Plain(data), 0),
    }
}

fn typed_dynamic_key_type(
    chunks: &[crate::evm::memory::MemoryChunk<Label>],
    key_size: usize,
) -> Option<DynSolType> {
    let mut saw_bytes = false;

    for chunk in chunks {
        if chunk.dst_range.start >= key_size {
            continue;
        }

        match &chunk.src_label {
            Label::Typed(DynSolType::String, _) => return Some(DynSolType::String),
            Label::Typed(DynSolType::Bytes, _) => saw_bytes = true,
            _ => {}
        }
    }

    if saw_bytes {
        Some(DynSolType::Bytes)
    } else {
        None
    }
}

fn mapping_key_type(
    label: Option<&Label>,
    base: &SlotExpr,
    hints: &StorageTraceHints,
) -> DynSolType {
    if let Some(hinted) = hints.mapping_key_type(base) {
        return hinted;
    }

    match label {
        Some(Label::Typed(tp, _)) => tp.clone(),
        Some(Label::Loaded(storage)) => {
            let storage = storage.borrow();
            hints
                .scalar_type(storage.domain, storage.slot)
                .or_else(|| {
                    storage
                        .stype
                        .has_known_internal_type()
                        .then(|| storage.stype.get_internal_type())
                })
                .unwrap_or(DynSolType::Uint(256))
        }
        _ => DynSolType::Uint(256),
    }
}

fn normalize_slot_expr(slot_expr: &SlotExpr) -> (SlotKey, Option<Slot>, StorageType, usize) {
    let mut current = slot_expr;
    let mut stype = StorageType::Base(DynSolType::Uint(256));
    let mut slot_delta = 0_usize;

    loop {
        match current {
            SlotExpr::Mapping { key_type, base } => {
                stype = StorageType::Map(key_type.clone(), Box::new(stype));
                current = base;
            }
            SlotExpr::DynamicArray { base } => {
                stype = match stype {
                    StorageType::Base(inner) => {
                        StorageType::Base(DynSolType::Array(Box::new(inner)))
                    }
                    StorageType::Map(_, _) => {
                        StorageType::Base(DynSolType::Array(Box::new(DynSolType::Uint(256))))
                    }
                };
                current = base;
            }
            SlotExpr::DynamicArrayElement { base, .. } => current = base,
            SlotExpr::Offset { base, slots } => {
                slot_delta = slot_delta.saturating_add(*slots);
                current = base;
            }
            _ => {
                return (
                    current.slot_key(),
                    current.canonical_slot(),
                    stype,
                    slot_delta,
                );
            }
        }
    }
}

fn constant_slot_delta(value: &Element<Label>) -> Option<usize> {
    let value: U256 = value.into();
    (value <= U256::from(usize::MAX)).then(|| value.to())
}

fn with_slot_delta(expr: SlotExpr, slots: usize) -> SlotExpr {
    if slots == 0 {
        return expr;
    }
    match expr {
        SlotExpr::Offset {
            base,
            slots: current,
        } => SlotExpr::Offset {
            base,
            slots: current.saturating_add(slots),
        },
        base => SlotExpr::Offset {
            base: Box::new(base),
            slots,
        },
    }
}

fn packed_field(mask: U256) -> Option<(u8, u16)> {
    let cleared = !mask;
    if cleared.is_zero() {
        return None;
    }
    let bit_offset = cleared.trailing_zeros();
    let width = (cleared >> bit_offset).trailing_ones();
    if bit_offset >= 256
        || width == 0
        || !bit_offset.is_multiple_of(8)
        || !width.is_multiple_of(8)
        || (cleared >> bit_offset >> width) != U256::ZERO
    {
        return None;
    }
    Some(((bit_offset / 8) as u8, width as u16))
}

fn packed_constant_is_bool(value: &Element<Label>, offset: u8) -> bool {
    let value: U256 = value.into();
    (value >> (usize::from(offset) * 8)) <= VAL_1
}

fn storage_slot_element(storage: &StorageElement) -> Element<Label> {
    Element {
        data: storage.slot.unwrap_or_default(),
        label: match &storage.slot_expr {
            SlotExpr::Plain(_) => None,
            expr => Some(Label::Keccak(0, expr.clone())),
        },
    }
}

fn is_scalar_storage_type(stype: &StorageType) -> bool {
    matches!(
        stype,
        StorageType::Base(
            DynSolType::Bool
                | DynSolType::Address
                | DynSolType::String
                | DynSolType::Bytes
                | DynSolType::Uint(_)
                | DynSolType::Int(_)
                | DynSolType::FixedBytes(_)
        )
    )
}

fn is_suspicious_opaque_root(stype: &StorageType) -> bool {
    matches!(
        stype,
        StorageType::Base(DynSolType::String | DynSolType::Bytes)
    ) || matches!(
        stype,
        StorageType::Base(DynSolType::Uint(bits) | DynSolType::Int(bits)) if *bits >= 128
    ) || matches!(stype, StorageType::Base(DynSolType::FixedBytes(size)) if *size >= 16)
}

fn is_legitimate_packed_root(stype: &StorageType) -> bool {
    matches!(stype, StorageType::Base(DynSolType::Address))
}

fn looks_like_opaque_bitfield_slot(entries: &[(Selector, StorageElement)]) -> bool {
    let mut nonzero_offsets: BTreeSet<u8> = BTreeSet::new();
    let mut min_nonzero_offset: Option<u8> = None;
    let mut has_suspicious_root = false;
    let mut has_legitimate_root = false;

    for (_, entry) in entries {
        if !is_scalar_storage_type(&entry.stype) {
            return false;
        }

        if entry.rshift == 0 {
            has_suspicious_root |= is_suspicious_opaque_root(&entry.stype);
            has_legitimate_root |= is_legitimate_packed_root(&entry.stype);
        } else {
            nonzero_offsets.insert(entry.rshift);
            min_nonzero_offset =
                Some(min_nonzero_offset.map_or(entry.rshift, |current| current.min(entry.rshift)));
        }
    }

    if nonzero_offsets.len() < 4 || min_nonzero_offset.unwrap_or_default() < 16 {
        return false;
    }

    has_suspicious_root && !has_legitimate_root
}

#[derive(Clone, Debug)]
struct CheckedArrayIndex {
    root: SlotKey,
    index: AffineExpr,
}

#[derive(Default)]
struct Storage {
    loaded: SlotHashMap,
    checked_array_indexes: Vec<CheckedArrayIndex>,
    delegate_calls: Vec<DelegateCallEvidence>,
}
impl Storage {
    fn record_delegate_call(
        &mut self,
        target: &Element<Label>,
        calldata_offset: &Element<Label>,
        calldata_size: &Element<Label>,
        vm: &Vm<Label, ComposeCallData<Label>>,
        pc: usize,
        caller_selector: Selector,
    ) {
        let target = match target.label.as_ref() {
            Some(Label::Constant) => {
                let mut address = [0_u8; 20];
                address.copy_from_slice(&target.data[12..]);
                DelegateCallTarget::Constant(address)
            }
            Some(Label::Loaded(storage)) => {
                let storage = storage.borrow();
                if storage.domain == StorageDomain::Persistent {
                    DelegateCallTarget::Storage {
                        slot: storage.slot,
                        byte_offset: storage.rshift,
                        symbolic_path: format!("{:?}", storage.slot_expr),
                    }
                } else {
                    DelegateCallTarget::TransientStorage {
                        symbolic_path: format!("{:?}", storage.slot_expr),
                    }
                }
            }
            Some(Label::Typed(_, Some(affine))) if !affine.calldata_terms.is_empty() => {
                DelegateCallTarget::Calldata
            }
            _ => DelegateCallTarget::Unresolved,
        };

        let offset = u32::try_from(calldata_offset).ok();
        let size = u32::try_from(calldata_size).ok();
        let selector = match (offset, size) {
            (Some(offset), Some(size)) if size >= 4 => {
                let (data, _) = vm.memory.load(offset, 4);
                Some([data[0], data[1], data[2], data[3]])
            }
            _ => None,
        };

        self.delegate_calls.push(DelegateCallEvidence {
            target,
            selector,
            pc,
            caller_selector,
        });
        if cfg!(feature = "trace_storage") || std::env::var_os("COMPOSE_TRACE_STORAGE").is_some() {
            let evidence = self.delegate_calls.last().expect("just inserted evidence");
            eprintln!(
                "[storage-validation:delegatecall] caller_selector={} pc={} target={:?} selector={:?}",
                alloy_primitives::hex::encode(evidence.caller_selector),
                evidence.pc,
                evidence.target,
                evidence.selector.map(alloy_primitives::hex::encode),
            );
        }
    }

    fn record_array_index(&mut self, storage: &Rc<RefCell<StorageElement>>, index: AffineExpr) {
        let storage = storage.borrow();
        let checked = CheckedArrayIndex {
            root: storage.slot_expr.slot_key(),
            index,
        };
        if !self
            .checked_array_indexes
            .iter()
            .any(|item| item.root == checked.root && item.index == checked.index)
        {
            self.checked_array_indexes.push(checked);
        }
    }

    fn array_element(
        &self,
        dynamic_array: &SlotExpr,
        scaled_index: &AffineExpr,
    ) -> Option<(AffineExpr, usize)> {
        let SlotExpr::DynamicArray { base } = dynamic_array else {
            return None;
        };
        let root = base.slot_key();
        self.checked_array_indexes
            .iter()
            .rev()
            .filter(|checked| checked.root == root)
            .find_map(|checked| {
                checked
                    .index
                    .scale_from(scaled_index)
                    .map(|stride| (checked.index.clone(), stride))
            })
    }

    fn remove(&mut self, val: &Rc<RefCell<StorageElement>>) {
        let key = {
            let val = val.borrow();
            (val.domain, val.slot_key.clone())
        };
        self.loaded.get_mut(&key).unwrap().retain(|x| x != val);
    }

    fn store(
        &mut self,
        domain: StorageDomain,
        slot: Element<Label>,
        vtype: DynSolType,
        metadata: WriteMetadata,
    ) {
        let x = self.get(domain, slot, true, Some(metadata.write_pc));
        x.borrow_mut().stype.set_type(vtype);
        x.borrow_mut().rshift = metadata.rshift;
        x.borrow_mut().write_value_known = metadata.value_known;
        x.borrow_mut().field_width = metadata.field_width;
    }

    fn load(&mut self, domain: StorageDomain, slot: Element<Label>) -> Rc<RefCell<StorageElement>> {
        self.get(domain, slot, false, None)
    }

    fn get(
        &mut self,
        domain: StorageDomain,
        slot: Element<Label>,
        is_write: bool,
        write_pc: Option<usize>,
    ) -> Rc<RefCell<StorageElement>> {
        let slot_expr = match slot.label {
            Some(Label::Keccak(_, expr)) => expr,
            _ => SlotExpr::Plain(slot.data),
        };
        let (slot_key, canonical_slot, stype, slot_delta) = normalize_slot_expr(&slot_expr);

        let v = Rc::new(RefCell::new(StorageElement {
            domain,
            slot_key: slot_key.clone(),
            slot: canonical_slot,
            slot_expr,
            stype,
            slot_delta,
            rshift: 0,
            field_width: None,
            is_write,
            write_pc,
            write_value_known: false,
            last_and: None,
            last_or2: None,
        }));
        self.loaded
            .entry((domain, slot_key))
            .or_default()
            .push(v.clone());
        v
    }
}

fn analyze(
    vm: &mut Vm<Label, ComposeCallData<Label>>,
    st: &mut Storage,
    hints: &StorageTraceHints,
    ret: StepResult<Label>,
    pc: usize,
    caller_selector: Selector,
) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    match ret {
        StepResult {
            op: op::PUSH0..=op::PUSH32,
            ..
        } => {
            vm.stack.peek_mut()?.label = Some(Label::Constant);
        }

        StepResult {
            op: op::DELEGATECALL,
            args: [target, ..],
            exargs,
            ..
        } if exargs.len() >= 3 => {
            st.record_delegate_call(&target, &exargs[1], &exargs[2], vm, pc, caller_selector);
        }

        StepResult {
            op: op::CODECOPY,
            args: [mem_off, ..],
            ..
        } => {
            let off: u32 = mem_off.try_into()?;
            if let Some(entry) = vm.memory.get_mut(off) {
                entry.label = Some(Label::Constant);
            }
        }

        StepResult {
            op:
                op::ADD
                | op::MUL
                | op::SUB
                | op::DIV
                | op::SDIV
                | op::MOD
                | op::SMOD
                | op::EXP
                | op::SIGNEXTEND
                | op::LT
                | op::GT
                | op::SLT
                | op::SGT
                | op::EQ
                | op::AND
                | op::OR
                | op::XOR
                | op::BYTE
                | op::SHL
                | op::SHR
                | op::SAR,
            args: [elabel!(Label::Constant), elabel!(Label::Constant), ..],
            ..
        } => {
            vm.stack.peek_mut()?.label = Some(Label::Constant);
        }

        StepResult {
            op: op::MUL,
            args:
                match_first_two!(
                    elabel!(Label::Typed(tp, Some(affine))),
                    value @ Element {
                        label: Some(Label::Constant),
                        ..
                    }
                ),
            ..
        } => {
            let factor: U256 = (&value).into();
            vm.stack.peek_mut()?.label = Some(Label::Typed(tp, affine.multiply(factor)));
        }

        StepResult {
            op: op::SHL,
            args:
                [
                    shift @ Element {
                        label: Some(Label::Constant),
                        ..
                    },
                    elabel!(Label::Typed(tp, Some(affine))),
                    ..,
                ],
            ..
        } => {
            let shift: U256 = (&shift).into();
            let affine = (shift < U256::from(256))
                .then(|| U256::from(1) << shift.to::<usize>())
                .and_then(|factor| affine.multiply(factor));
            vm.stack.peek_mut()?.label = Some(Label::Typed(tp, affine));
        }

        StepResult {
            op: op::ADD,
            args:
                match_first_two!(
                    elabel!(Label::Typed(tp, Some(affine))),
                    value @ Element {
                        label: Some(Label::Constant),
                        ..
                    }
                ),
            ..
        } => {
            let value: U256 = (&value).into();
            vm.stack.peek_mut()?.label = Some(Label::Typed(tp, affine.add_constant(value)));
        }

        StepResult {
            op: op::ADD,
            args:
                [
                    elabel!(Label::Typed(tp, Some(left))),
                    elabel!(Label::Typed(_, Some(right))),
                    ..,
                ],
            ..
        } => {
            vm.stack.peek_mut()?.label = Some(Label::Typed(tp, left.add(&right)));
        }

        StepResult {
            op: op::ADD | op::MUL | op::SUB | op::XOR | op::SHL | op::SHR,
            args:
                match_first_two!(
                    elabel!(lb @ (Label::Loaded(_) | Label::Typed(_, _))),
                    elabel!(Label::Constant)
                ),
            ..
        } => {
            vm.stack.peek_mut()?.label = Some(match lb {
                Label::Typed(tp, _) => Label::Typed(tp, None),
                other => other,
            });
        }

        StepResult {
            op: op::MUL | op::SHL,
            args: match_first_two!(elabel!(label @ Label::Packed(_)), _),
            ..
        } => {
            vm.stack.peek_mut()?.label = Some(label);
        }

        StepResult {
            op: op::NOT | op::ISZERO,
            args: [elabel!(Label::Constant), ..],
            ..
        } => {
            vm.stack.peek_mut()?.label = Some(Label::Constant);
        }

        StepResult {
            op: op::CALLVALUE, ..
        } => {
            vm.stack.peek_mut()?.label = Some(Label::Typed(DynSolType::Uint(256), None));
        }

        StepResult {
            op: op::TIMESTAMP, ..
        } => {
            vm.stack.peek_mut()?.label = Some(Label::Typed(DynSolType::Uint(256), None));
        }

        //TODO signextend & byte
        StepResult {
            op: op::ISZERO,
            args: [elabel!(label @ Label::Typed(DynSolType::Bool, _)), ..],
            ..
        } => {
            let Label::Typed(tp, _) = label else {
                unreachable!("pattern only matches typed boolean labels");
            };
            vm.stack.peek_mut()?.label = Some(Label::Packed(tp));
        }

        StepResult {
            op: op::ISZERO,
            args: [elabel!(label @ Label::Packed(DynSolType::Bool)), ..],
            ..
        } => {
            vm.stack.peek_mut()?.label = Some(label);
        }

        StepResult {
            op: op::SIGNEXTEND,
            args: [_, elabel!(label @ Label::Typed(_, _)), ..],
            ..
        } => {
            vm.stack.peek_mut()?.label = Some(label);
        }

        StepResult {
            op: op::LT | op::GT,
            args:
                match_first_two!(
                    elabel!(Label::Typed(_, Some(index))),
                    elabel!(Label::Loaded(storage))
                ),
            ..
        } => {
            st.record_array_index(&storage, index);
        }

        StepResult {
            op: op::ADD,
            args:
                match_first_two!(
                    elabel!(Label::Keccak(depth, expr)),
                    elabel!(Label::Typed(_, Some(scaled_index)))
                ),
            ..
        } => {
            let expr = match st.array_element(&expr, &scaled_index) {
                Some((index, stride)) => SlotExpr::DynamicArrayElement {
                    base: Box::new(expr),
                    index,
                    stride,
                },
                None => expr,
            };
            vm.stack.peek_mut()?.label = Some(Label::Keccak(depth, expr));
        }

        StepResult {
            op: op::ADD,
            args:
                match_first_two!(
                    elabel!(Label::Keccak(depth, expr)),
                    value @ Element {
                        label: Some(Label::Constant),
                        ..
                    }
                ),
            ..
        } => {
            let label = match constant_slot_delta(&value) {
                Some(slots) => Label::Keccak(depth, with_slot_delta(expr, slots)),
                None => Label::Keccak(depth, expr),
            };
            vm.stack.peek_mut()?.label = Some(label);
        }

        StepResult {
            op: op::ADD | op::SUB,
            args: match_first_two!(elabel!(label @ Label::Keccak(_, _)), _),
            ..
        } => {
            vm.stack.peek_mut()?.label = Some(label);
        }

        StepResult {
            op: opcode @ (op::SLOAD | op::TLOAD),
            args: [slot, ..],
            ..
        } => {
            let domain = if opcode == op::SLOAD {
                StorageDomain::Persistent
            } else {
                StorageDomain::Transient
            };
            *vm.stack.peek_mut()? = Element {
                label: Some(Label::Loaded(st.load(domain, slot))),
                data: VAL_1_B,
            };
        }

        StepResult {
            op: op::JUMPI,
            args: [fa, ..],
            ..
        } => {
            let other_pc = usize::try_from(fa).expect("set to usize in vm.rs");
            return Ok(Some(other_pc));
        }

        StepResult {
            op: op::CALLER | op::ORIGIN | op::ADDRESS,
            ..
        } => {
            *vm.stack.peek_mut()? = Element {
                label: Some(Label::Typed(DynSolType::Address, None)),
                data: VAL_1_B,
            };
        }

        StepResult {
            op: op::ISZERO,
            args: [elabel!(Label::Loaded(sl)), ..],
            ..
        } => {
            vm.stack.peek_mut()?.label = Some(Label::IsZero(sl));
        }

        StepResult {
            op: op::ISZERO,
            args: [elabel!(Label::IsZero(sl)), ..],
            ..
        } => {
            sl.borrow_mut().stype.set_type(DynSolType::Bool);
        }

        StepResult {
            op: op::SIGNEXTEND,
            args: [s0, elabel!(Label::Loaded(sl)), ..],
            ..
        } => {
            if s0.data < VAL_32_B {
                let s0: u8 = s0.data[31];
                sl.borrow_mut()
                    .stype
                    .set_type(DynSolType::Int((s0 as usize + 1) * 8));
            }
        }

        StepResult {
            op: op::BYTE,
            args: [_, elabel!(Label::Loaded(sl)), ..],
            ..
        } => sl.borrow_mut().stype.set_type(DynSolType::FixedBytes(32)),

        StepResult {
            op: op::EQ,
            args: match_first_two!(elabel!(Label::Typed(tp, _)), elabel!(Label::Loaded(sl))),
            ..
        } => {
            sl.borrow_mut().stype.set_type(tp);
        }

        StepResult {
            op: op::OR,
            args:
                match_first_two!(elabel!(Label::Loaded(sl)), tt @ Element{label: Some(Label::Typed(_, _) | Label::Packed(_) | Label::Constant), ..} ),
            ..
        } => {
            sl.borrow_mut().last_or2 = Some(tt);
            vm.stack.peek_mut()?.label = Some(Label::Loaded(sl));
        }

        StepResult {
            op: op::AND,
            args:
                match_first_two!(
                    elabel!(Label::Typed(tp, _)),
                    Element {
                        label: Some(Label::Constant),
                        ..
                    }
                ),
            ..
        } => {
            vm.stack.peek_mut()?.label = Some(Label::Packed(tp));
        }

        StepResult {
            op: op::AND,
            args: match_first_two!(elabel!(label @ Label::Typed(_, _)), _),
            ..
        } => {
            vm.stack.peek_mut()?.label = Some(label);
        }

        StepResult {
            op: op::AND,
            args:
                match_first_two!(elabel!(Label::Loaded(sl)), ot @ Element{label: Some(Label::Constant), ..} ),
            ..
        } => {
            let mask: U256 = ot.into();
            sl.borrow_mut().last_and = Some(mask);

            if let Some(t) = and_mask_to_type(mask) {
                sl.borrow_mut().stype.set_type(t);
            } else if mask == VAL_1 && sl.borrow().rshift == 0 {
                // string, check for SSO (only at rshift 0, not within packed fields)
                sl.borrow_mut().stype.set_type(DynSolType::String);
            }
            vm.stack.peek_mut()?.label = Some(Label::Loaded(sl));
        }

        StepResult {
            op: op::AND,
            args: match_first_two!(elabel!(Label::Loaded(sl)), _),
            ..
        } => {
            // A packed array index makes the clearing mask depend on runtime
            // index arithmetic. Keep the read-modify-write link even though
            // that mask cannot be interpreted as a constant field mask.
            vm.stack.peek_mut()?.label = Some(Label::Loaded(sl));
        }

        StepResult {
            op: opcode @ (op::SSTORE | op::TSTORE),
            args: [slot, value, ..],
            ..
        } => {
            let domain = if opcode == op::SSTORE {
                StorageDomain::Persistent
            } else {
                StorageDomain::Transient
            };

            if let Some(Label::Loaded(ref sl)) = value.label
                && sl.borrow().domain == domain
            {
                st.remove(sl);
            }

            match value.label {
                Some(Label::Typed(t, _)) => st.store(
                    domain,
                    slot,
                    t,
                    WriteMetadata {
                        rshift: 0,
                        write_pc: pc,
                        value_known: true,
                        field_width: Some(256),
                    },
                ),
                Some(Label::Constant) => st.store(
                    domain,
                    slot,
                    DynSolType::Uint(256),
                    WriteMetadata {
                        rshift: 0,
                        write_pc: pc,
                        value_known: true,
                        field_width: Some(256),
                    },
                ),
                Some(Label::Loaded(sl)) => {
                    let sbr = sl.borrow();
                    if let Some(lor) = &sbr.last_or2 {
                        if let Some(land) = sbr.last_and {
                            let field = packed_field(land);
                            let (offset, width) = field.unwrap_or((0, 256));

                            let (dt, known) = match &lor.label {
                                Some(Label::Typed(tp, _)) => (tp.clone(), true),
                                Some(Label::Packed(tp)) => (tp.clone(), true),
                                Some(Label::Constant)
                                    if width == 8 && packed_constant_is_bool(lor, offset) =>
                                {
                                    (DynSolType::Bool, true)
                                }
                                Some(Label::Loaded(sl2)) => {
                                    let sl2 = sl2.borrow();
                                    (
                                        sl2.stype.get_internal_type(),
                                        sl2.stype.has_known_internal_type(),
                                    )
                                }
                                _ => {
                                    let inferred = if width == 160 {
                                        DynSolType::Address
                                    } else {
                                        DynSolType::Uint(width as usize)
                                    };
                                    (inferred, false)
                                }
                            };
                            st.store(
                                domain,
                                slot,
                                dt,
                                WriteMetadata {
                                    rshift: offset,
                                    write_pc: pc,
                                    value_known: known,
                                    field_width: field.map(|(_, width)| width),
                                },
                            );
                        } else {
                            let (dt, known) = match &lor.label {
                                Some(Label::Typed(tp, _) | Label::Packed(tp)) => (tp.clone(), true),
                                Some(Label::Loaded(sl2)) => {
                                    let sl2 = sl2.borrow();
                                    (
                                        sl2.stype.get_internal_type(),
                                        sl2.stype.has_known_internal_type(),
                                    )
                                }
                                _ => (
                                    sbr.stype.get_internal_type(),
                                    sbr.stype.has_known_internal_type(),
                                ),
                            };
                            st.store(
                                domain,
                                slot,
                                dt,
                                WriteMetadata {
                                    rshift: 0,
                                    write_pc: pc,
                                    value_known: known,
                                    field_width: None,
                                },
                            );
                        }
                    } else {
                        let known = sbr.stype.has_known_internal_type();
                        st.store(
                            domain,
                            slot,
                            sbr.stype.get_internal_type(),
                            WriteMetadata {
                                rshift: 0,
                                write_pc: pc,
                                value_known: known,
                                field_width: None,
                            },
                        );
                    }
                }
                _ => st.store(
                    domain,
                    slot,
                    DynSolType::Uint(256),
                    WriteMetadata {
                        rshift: 0,
                        write_pc: pc,
                        value_known: false,
                        field_width: None,
                    },
                ),
            }
        }

        StepResult {
            op: op::DIV,
            args: [elabel!(Label::Loaded(sl)), ot, ..],
            ..
        } => {
            let mask: U256 = ot.into();

            if mask > VAL_1
                && (mask & (mask - VAL_1)).is_zero()
                && (mask.bit_len() - 1).is_multiple_of(8)
            {
                let slot = {
                    let storage = sl.borrow();
                    storage_slot_element(&storage)
                };
                let domain = sl.borrow().domain;
                let nl = st.load(domain, slot);
                let bl = mask.bit_len() - 1;
                nl.borrow_mut().rshift = (bl / 8) as u8;
                vm.stack.peek_mut()?.label = Some(Label::Loaded(nl));

                // TODO: postprocess this
                // sl.borrow_mut().stype.set_type(if bl == 160 { DynSolType::Address } else { DynSolType::Uint(bl) });
            } else {
                vm.stack.peek_mut()?.label = Some(Label::Loaded(sl));
            }
        }

        StepResult {
            op: op::SHR,
            args: [shift_amount, elabel!(Label::Loaded(sl)), ..],
            ..
        } => {
            let shift: U256 = (&shift_amount).into();
            if !shift.is_zero() && shift.bit_len() <= 9 {
                let bits: usize = shift.to();
                if bits.is_multiple_of(8) {
                    let slot = {
                        let storage = sl.borrow();
                        storage_slot_element(&storage)
                    };
                    let domain = sl.borrow().domain;
                    let nl = st.load(domain, slot);
                    nl.borrow_mut().rshift = (bits / 8) as u8;
                    vm.stack.peek_mut()?.label = Some(Label::Loaded(nl));
                } else {
                    vm.stack.peek_mut()?.label = Some(Label::Loaded(sl));
                }
            } else {
                vm.stack.peek_mut()?.label = Some(Label::Loaded(sl));
            }
        }

        StepResult {
            op: op::KECCAK256,
            args: [fa, sa, ..],
            ..
        } => {
            let off = u32::try_from(fa)?;
            let sz = u32::try_from(sa)?;
            let (data, used) = vm.memory.load(off, sz);
            let constant_hash = known_constant_hash(&data, &used.chunks);

            if let Some(hash) = constant_hash {
                vm.stack.peek_mut()?.data = hash;
            }

            let mut depth = 0;
            let mut slot_expr = constant_hash.map_or_else(
                || SlotExpr::UnknownHash {
                    size: sz,
                    preimage: data.clone(),
                },
                |hash| SlotExpr::HashedConst {
                    hash,
                    preimage: data.clone(),
                },
            );

            if sz == 64 {
                let (_val, used) = vm.memory.load_element(off); // value
                let (sval, sused) = vm.memory.load_element(off + 32); // slot
                let key_depth = match full_word_label(&used.chunks, 32) {
                    Some(Label::Keccak(d, _)) => d + 1,
                    _ => 0,
                };
                let (base_expr, base_depth) = word_slot_expr(sval.data, &sused.chunks);
                let key_type =
                    mapping_key_type(full_word_label(&used.chunks, 32), &base_expr, hints);
                depth = key_depth.max(base_depth);
                if depth < 6 {
                    slot_expr = SlotExpr::Mapping {
                        key_type,
                        base: Box::new(base_expr),
                    };
                }
            } else if sz > 32 {
                let key_size = sz - 32;
                let (sval, sused) = vm.memory.load_element(off + key_size);
                let (base_expr, base_depth) = word_slot_expr(sval.data, &sused.chunks);
                let key_depth = used
                    .chunks
                    .iter()
                    .filter(|chunk| chunk.dst_range.start < key_size as usize)
                    .filter_map(|chunk| match chunk.src_label {
                        Label::Keccak(d, _) => Some(d + 1),
                        _ => None,
                    })
                    .max()
                    .unwrap_or(0);
                let key_type = hints
                    .mapping_key_type(&base_expr)
                    .or_else(|| typed_dynamic_key_type(&used.chunks, key_size as usize))
                    .unwrap_or(DynSolType::String);
                let tail_looks_like_slot = full_word_label(&sused.chunks, 32).is_some()
                    || sval.data[..31].iter().all(|b| *b == 0);
                depth = key_depth.max(base_depth);
                if tail_looks_like_slot && depth < 6 {
                    slot_expr = SlotExpr::Mapping {
                        key_type,
                        base: Box::new(base_expr),
                    };
                }
            } else if sz == 32 {
                let (val, used) = vm.memory.load_element(off); // value
                let (base_expr, base_depth) = word_slot_expr(val.data, &used.chunks);
                depth = base_depth;
                if depth < 6 {
                    slot_expr = SlotExpr::DynamicArray {
                        base: Box::new(base_expr),
                    };
                }
            }
            vm.stack.peek_mut()?.label = Some(Label::Keccak(depth, slot_expr));
        }
        _ => (),
    };
    Ok(None)
}

fn analyze_rec(
    mut vm: Vm<Label, ComposeCallData<Label>>,
    st: &mut Storage,
    hints: &StorageTraceHints,
    gas_limit: u32,
    depth: u32,
    caller_selector: Selector,
) -> u32 {
    let mut gas_used = 0;

    while !vm.stopped {
        if cfg!(feature = "trace_storage") {
            println!("{vm:?}\n");
            println!("storage: {:?}\n", st.loaded);
        }
        let pc = vm.pc;
        let ret = match vm.step() {
            Ok(v) => v,
            Err(error) => {
                if std::env::var_os("COMPOSE_TRACE_STORAGE_OPS").is_some() {
                    eprintln!(
                        "[storage-validation:trace-error] selector={} pc={} error={error}",
                        alloy_primitives::hex::encode(caller_selector),
                        pc,
                    );
                }
                break;
            }
        };
        if std::env::var_os("COMPOSE_TRACE_STORAGE_OPS").is_some() {
            eprintln!(
                "[storage-validation:op] selector={} pc={} op={}",
                alloy_primitives::hex::encode(caller_selector),
                pc,
                ret.op,
            );
        }
        gas_used += ret.gas_used;
        if gas_used > gas_limit {
            break;
        }

        match analyze(&mut vm, st, hints, ret, pc, caller_selector) {
            Err(error) => {
                if std::env::var_os("COMPOSE_TRACE_STORAGE_OPS").is_some() {
                    eprintln!(
                        "[storage-validation:analysis-error] selector={} pc={} error={error}",
                        alloy_primitives::hex::encode(caller_selector),
                        pc,
                    );
                }
                break;
            }
            Ok(Some(other_pc)) => {
                if depth < 8 && other_pc < vm.code.len() {
                    let mut cloned = vm.fork();
                    cloned.pc = other_pc;
                    gas_used += analyze_rec(
                        cloned,
                        st,
                        hints,
                        (gas_limit - gas_used) / 2,
                        depth + 1,
                        caller_selector,
                    );
                }
            }
            Ok(None) => {}
        }
    }

    gas_used
}

struct FunctionStorageLayouts {
    loaded: SlotHashMap,
    delegate_calls: Vec<DelegateCallEvidence>,
}

fn analyze_one_function(
    code: &[u8],
    selector: Selector,
    arguments: &[DynSolType],
    is_fallback: bool,
    hints: &StorageTraceHints,
    gas_limit: u32,
    use_compose_calldata: bool,
) -> FunctionStorageLayouts {
    if cfg!(feature = "trace_storage") {
        println!(
            "analyze selector {}\n",
            alloy_primitives::hex::encode(selector)
        );
    }

    let calldata = if use_compose_calldata {
        ComposeCallData::<Label>::bounded_copy(selector, arguments)
    } else {
        ComposeCallData::<Label>::passthrough(selector, arguments)
    };
    let mut vm = Vm::new(code, &calldata);

    let mut st = Storage::default();
    let mut gas_used = 0;

    if !is_fallback {
        if let Some(g) = execute_until_function_start(&mut vm, gas_limit) {
            gas_used += g;
        } else {
            return FunctionStorageLayouts {
                loaded: st.loaded,
                delegate_calls: st.delegate_calls,
            };
        }
    }

    #[allow(unused_assignments)]
    if gas_used < gas_limit {
        gas_used += analyze_rec(vm, &mut st, hints, gas_limit - gas_used, 0, selector);
    }

    let loaded = st
        .loaded
        .into_iter()
        .map(|(k, v)| {
            // Filter out impossible packed entries: full-slot/container types cannot start mid-slot.
            let v: Vec<_> = v
                .into_iter()
                .filter(|e| {
                    let br = e.borrow();
                    !(br.rshift > 0 && br.stype.requires_zero_offset() && !br.is_write)
                })
                .collect();
            let string_like_elements: Vec<_> = v
                .iter()
                .filter(|e| e.borrow().stype.is_string_like())
                .cloned()
                .collect();
            let map_elements: Vec<_> = v
                .clone()
                .into_iter()
                .filter(|e| {
                    let br = e.borrow();
                    if let StorageType::Map(_, _) = br.stype {
                        br.rshift == 0 || br.is_write
                    } else {
                        false
                    }
                })
                .collect();
            (
                k,
                if !string_like_elements.is_empty() {
                    string_like_elements
                } else if !map_elements.is_empty() {
                    map_elements
                } else {
                    v
                },
            )
        })
        .collect();
    FunctionStorageLayouts {
        loaded,
        delegate_calls: st.delegate_calls,
    }
}

type SlotRecords = BTreeMap<(Slot, u8), Vec<(Selector, StorageElement)>>;

#[derive(Default)]
struct DomainSlotRecords {
    persistent: SlotRecords,
    transient: SlotRecords,
}

pub(crate) struct StorageLayouts {
    // Retained for Compose tracing/debug output even though direct validation
    // currently consumes only evidence and delegate calls.
    #[allow(dead_code)]
    pub storage: Vec<StorageRecord>,
    #[allow(dead_code)]
    pub transient_storage: Vec<StorageRecord>,
    pub evidence: Vec<StorageEvidence>,
    pub delegate_calls: Vec<DelegateCallEvidence>,
}

#[derive(Clone, Debug)]
pub(crate) struct StorageEvidence {
    pub domain: &'static str,
    pub slot: Option<Slot>,
    pub symbolic_path: String,
    pub storage_path: Vec<StoragePathSegment>,
    pub slot_delta: usize,
    pub offset: u8,
    pub field_width: Option<u16>,
    pub inferred_type: String,
    pub score: usize,
    pub is_write: bool,
    pub value_type_known: bool,
    pub write_pc: Option<usize>,
    pub selector: Selector,
    pub is_fallback_probe: bool,
    pub mask: Option<String>,
}

fn collect_storage_evidence(
    evidence: &mut Vec<StorageEvidence>,
    selector: Selector,
    is_fallback_probe: bool,
    loaded: &SlotHashMap,
) {
    for elements in loaded.values() {
        for element in elements {
            let element = element.borrow();
            let mut storage_path_segments = Vec::new();
            storage_path(&element.slot_expr, &mut storage_path_segments);
            evidence.push(StorageEvidence {
                domain: match element.domain {
                    StorageDomain::Persistent => "persistent",
                    StorageDomain::Transient => "transient",
                },
                slot: element.slot,
                symbolic_path: format!("{:?}", element.slot_expr),
                storage_path: storage_path_segments,
                slot_delta: element.slot_delta,
                offset: element.rshift,
                field_width: element.field_width,
                inferred_type: format!("{:?}", element.stype),
                score: element.stype.get_score(),
                is_write: element.is_write,
                value_type_known: element.write_value_known,
                write_pc: element.write_pc,
                selector,
                is_fallback_probe,
                mask: element.last_and.map(|mask| format!("{mask:?}")),
            });
        }
    }
}

fn collect_slot_records(records: &mut DomainSlotRecords, selector: Selector, loaded: SlotHashMap) {
    for elements in loaded.into_values() {
        for element in elements {
            let value = element.borrow();
            let Some(slot) = value.slot else {
                continue;
            };
            let domain_records = match value.domain {
                StorageDomain::Persistent => &mut records.persistent,
                StorageDomain::Transient => &mut records.transient,
            };
            domain_records
                .entry((slot, value.rshift))
                .or_default()
                .push((selector, value.clone()));
        }
    }
}

fn finalize_slot_records(
    slot_records: SlotRecords,
    fallback_selector: Selector,
    domain_name: &str,
) -> Vec<StorageRecord> {
    let mut normalized_slot_records = BTreeMap::new();
    let mut grouped_by_slot: BTreeMap<Slot, Vec<_>> = BTreeMap::new();

    for ((slot, offset), entries) in slot_records {
        grouped_by_slot
            .entry(slot)
            .or_default()
            .push((offset, entries));
    }

    for (slot, groups) in grouped_by_slot {
        let flattened: Vec<_> = groups
            .iter()
            .flat_map(|(_, entries)| entries.iter().cloned())
            .collect();

        if looks_like_opaque_bitfield_slot(&flattened) {
            let collapsed_entries = flattened
                .into_iter()
                .map(|(selector, mut entry)| {
                    entry.rshift = 0;
                    entry.stype = StorageType::Base(DynSolType::FixedBytes(32));
                    (selector, entry)
                })
                .collect();
            normalized_slot_records.insert((slot, 0), collapsed_entries);
        } else {
            for (offset, entries) in groups {
                normalized_slot_records.insert((slot, offset), entries);
            }
        }
    }

    let mut records = Vec::with_capacity(normalized_slot_records.len());
    for ((slot, offset), entries) in normalized_slot_records {
        let mut reads = BTreeSet::new();
        let mut writes = BTreeSet::new();
        let mut best_type = StorageType::Base(DynSolType::Uint(256));
        let mut best_score = best_type.get_score();

        for (selector, element) in entries {
            if selector != fallback_selector {
                if element.is_write {
                    writes.insert(selector);
                } else {
                    reads.insert(selector);
                }
            }

            let score = element.stype.get_score();
            if score > best_score {
                best_type = element.stype;
                best_score = score;
            }
        }

        records.push(StorageRecord {
            slot,
            offset,
            r#type: format!("{best_type:?}"),
            reads: reads.into_iter().collect(),
            writes: writes.into_iter().collect(),
        });
    }

    if cfg!(feature = "trace_storage") {
        println!("{domain_name} storage:");
        for record in &records {
            println!(
                "slot {} off {}",
                alloy_primitives::hex::encode(record.slot),
                record.offset
            );
            println!(" type: {}", record.r#type);
            println!(
                " reads: {:?}",
                record
                    .reads
                    .iter()
                    .map(alloy_primitives::hex::encode)
                    .collect::<Vec<_>>()
            );
            println!(
                " writes: {:?}",
                record
                    .writes
                    .iter()
                    .map(alloy_primitives::hex::encode)
                    .collect::<Vec<_>>()
            );
        }
    }

    records
}

pub(crate) fn contract_storage<I, D>(code: &[u8], functions: I, gas_limit: u32) -> StorageLayouts
where
    I: IntoIterator<Item = (Selector, usize, D)>,
    D: AsRef<[DynSolType]>,
{
    let hints = StorageTraceHints::default();
    contract_storage_with_hints(code, functions, gas_limit, &hints)
}

pub(crate) fn contract_storage_with_hints<I, D>(
    code: &[u8],
    functions: I,
    gas_limit: u32,
    hints: &StorageTraceHints,
) -> StorageLayouts
where
    I: IntoIterator<Item = (Selector, usize, D)>,
    D: AsRef<[DynSolType]>,
{
    contract_storage_with_hints_options(code, functions, gas_limit, hints, true)
}

pub(crate) fn contract_storage_with_hints_options<I, D>(
    code: &[u8],
    functions: I,
    gas_limit: u32,
    hints: &StorageTraceHints,
    include_fallback: bool,
) -> StorageLayouts
where
    I: IntoIterator<Item = (Selector, usize, D)>,
    D: AsRef<[DynSolType]>,
{
    contract_storage_with_hints_options_mode(
        code,
        functions,
        gas_limit,
        hints,
        include_fallback,
        false,
    )
}

pub(crate) fn contract_storage_with_hints_options_compose<I, D>(
    code: &[u8],
    functions: I,
    gas_limit: u32,
    hints: &StorageTraceHints,
    include_fallback: bool,
) -> StorageLayouts
where
    I: IntoIterator<Item = (Selector, usize, D)>,
    D: AsRef<[DynSolType]>,
{
    contract_storage_with_hints_options_mode(
        code,
        functions,
        gas_limit,
        hints,
        include_fallback,
        true,
    )
}

fn contract_storage_with_hints_options_mode<I, D>(
    code: &[u8],
    functions: I,
    gas_limit: u32,
    hints: &StorageTraceHints,
    include_fallback: bool,
    use_compose_calldata: bool,
) -> StorageLayouts
where
    I: IntoIterator<Item = (Selector, usize, D)>,
    D: AsRef<[DynSolType]>,
{
    let real_gas_limit = if gas_limit == 0 {
        1e6 as u32
    } else {
        gas_limit
    };

    let mut slot_records = DomainSlotRecords::default();
    let mut evidence = Vec::new();
    let mut delegate_calls = Vec::new();

    let functions: Vec<_> = functions.into_iter().collect();
    let selectors: BTreeSet<Selector> = functions.iter().map(|(sel, _, _)| *sel).collect();
    let mut fallback_selector: Selector = [0xff, 0xff, 0xff, 0xff];
    while selectors.contains(&fallback_selector) {
        let val = u32::from_be_bytes(fallback_selector) - 1;
        fallback_selector = val.to_be_bytes();
    }

    for &(selector, _, ref arguments) in &functions {
        let layouts = analyze_one_function(
            code,
            selector,
            arguments.as_ref(),
            false,
            hints,
            real_gas_limit,
            use_compose_calldata,
        );
        collect_storage_evidence(&mut evidence, selector, false, &layouts.loaded);
        collect_slot_records(&mut slot_records, selector, layouts.loaded);
        delegate_calls.extend(layouts.delegate_calls);
    }

    if include_fallback {
        let fallback = analyze_one_function(
            code,
            fallback_selector,
            &[],
            true,
            hints,
            real_gas_limit,
            use_compose_calldata,
        );
        collect_storage_evidence(&mut evidence, fallback_selector, true, &fallback.loaded);
        collect_slot_records(&mut slot_records, fallback_selector, fallback.loaded);
        delegate_calls.extend(fallback.delegate_calls);
    }

    StorageLayouts {
        storage: finalize_slot_records(slot_records.persistent, fallback_selector, "persistent"),
        transient_storage: finalize_slot_records(
            slot_records.transient,
            fallback_selector,
            "transient",
        ),
        evidence,
        delegate_calls,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_array_stride_after_user_index_arithmetic() {
        let checked_index = AffineExpr::calldata(0)
            .multiply(U256::from(2))
            .and_then(|index| index.add_constant(U256::from(1)))
            .expect("small affine expression");
        let storage_offset = checked_index
            .multiply(U256::from(3))
            .expect("small affine expression");

        assert_eq!(checked_index.scale_from(&storage_offset), Some(3));
    }

    #[test]
    fn does_not_treat_unrelated_index_terms_as_an_array_stride() {
        let checked_index = AffineExpr::calldata(0);
        let unrelated = AffineExpr::calldata(32);

        assert_eq!(checked_index.scale_from(&unrelated), None);
    }

    #[test]
    fn preserves_ordered_nested_storage_path() {
        let expression = SlotExpr::Offset {
            slots: 2,
            base: Box::new(SlotExpr::DynamicArrayElement {
                base: Box::new(SlotExpr::DynamicArray {
                    base: Box::new(SlotExpr::Mapping {
                        key_type: DynSolType::FixedBytes(4),
                        base: Box::new(SlotExpr::Plain([0_u8; 32])),
                    }),
                }),
                index: AffineExpr::calldata(0),
                stride: 3,
            }),
        };

        let mut path = Vec::new();
        storage_path(&expression, &mut path);

        assert!(matches!(
            path.as_slice(),
            [
                StoragePathSegment::Mapping { .. },
                StoragePathSegment::DynamicArray {
                    index: Some(_),
                    stride: Some(3),
                },
                StoragePathSegment::Offset { slots: 2 },
            ]
        ));
    }

    #[test]
    fn prefers_vsl_mapping_key_types_for_known_roots() {
        let root = [0_u8; 32];
        let mut hints = StorageTraceHints::default();
        hints.insert_persistent_mapping_key_types(
            root,
            vec![DynSolType::Address, DynSolType::FixedBytes(32)],
        );

        let outer = SlotExpr::Plain(root);
        assert_eq!(
            mapping_key_type(
                Some(&Label::Typed(DynSolType::Uint(256), None)),
                &outer,
                &hints,
            ),
            DynSolType::Address
        );

        let inner = SlotExpr::Mapping {
            key_type: DynSolType::Address,
            base: Box::new(outer),
        };
        assert_eq!(
            mapping_key_type(
                Some(&Label::Typed(DynSolType::Uint(256), None)),
                &inner,
                &hints,
            ),
            DynSolType::FixedBytes(32)
        );
    }

    #[test]
    fn recognizes_packed_boolean_constants() {
        let false_value = Element {
            data: [0_u8; 32],
            label: Some(Label::Constant),
        };
        let mut true_data = [0_u8; 32];
        true_data[30] = 1;
        let shifted_true = Element {
            data: true_data,
            label: Some(Label::Constant),
        };
        let mut non_boolean_data = [0_u8; 32];
        non_boolean_data[31] = 2;
        let non_boolean = Element {
            data: non_boolean_data,
            label: Some(Label::Constant),
        };

        assert!(packed_constant_is_bool(&false_value, 0));
        assert!(packed_constant_is_bool(&shifted_true, 1));
        assert!(!packed_constant_is_bool(&non_boolean, 0));
    }
}
