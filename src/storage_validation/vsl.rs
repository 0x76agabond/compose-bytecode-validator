use crate::{
    DynSolType, Slot,
    compose::{VirtualStorageLayout, VirtualStorageLayoutRecord, storage::StorageTraceHints},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SemanticCompatibility {
    Compatible,
    KeyMismatch,
    Contradiction,
    Uncertain,
}

pub(crate) fn compare_semantic_types(inferred: &str, expected: &str) -> SemanticCompatibility {
    let inferred = normalize(inferred);
    let expected = normalize(expected);
    if inferred == expected {
        return SemanticCompatibility::Compatible;
    }
    if matches!(
        (inferred.as_str(), expected.as_str()),
        ("uint256", "bytes32") | ("bytes32", "uint256")
    ) {
        // A full ABI/storage word carries no opcode-level distinction between
        // these types. Treat the recovered uint256 default as representation
        // evidence, while the VSL remains the semantic type anchor.
        return SemanticCompatibility::Compatible;
    }
    if inferred == "unknown" || expected == "unknown" || expected == "function-internal" {
        return SemanticCompatibility::Uncertain;
    }
    if let (Some((inferred_key, inferred_value)), Some((expected_key, expected_value))) =
        (mapping_parts(&inferred), mapping_parts(&expected))
    {
        return match compare_semantic_types(&inferred_value, &expected_value) {
            SemanticCompatibility::Contradiction => SemanticCompatibility::Contradiction,
            SemanticCompatibility::Uncertain => SemanticCompatibility::Uncertain,
            SemanticCompatibility::Compatible | SemanticCompatibility::KeyMismatch => {
                if inferred_key == expected_key {
                    SemanticCompatibility::Compatible
                } else {
                    SemanticCompatibility::KeyMismatch
                }
            }
        };
    }
    if let (Some(inferred_element), Some(expected_element)) =
        (array_element(&inferred), array_element(&expected))
    {
        return compare_semantic_types(&inferred_element, &expected_element);
    }
    if expected.starts_with("virtual-struct(") {
        return SemanticCompatibility::Contradiction;
    }
    SemanticCompatibility::Contradiction
}

pub(crate) fn has_container_shape_contradiction(inferred: &str, expected: &str) -> bool {
    fn compare(inferred: &str, expected: &str) -> bool {
        if expected.starts_with("virtual-struct(") {
            return false;
        }
        match (mapping_parts(inferred), mapping_parts(expected)) {
            (Some((_, inferred_value)), Some((_, expected_value))) => {
                return compare(&inferred_value, &expected_value);
            }
            (Some(_), None) | (None, Some(_)) => return true,
            (None, None) => {}
        }
        match (array_element(inferred), array_element(expected)) {
            (Some(inferred_element), Some(expected_element)) => {
                compare(&inferred_element, &expected_element)
            }
            (Some(_), None) | (None, Some(_)) => true,
            (None, None) => false,
        }
    }

    compare(&normalize(inferred), &normalize(expected))
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn mapping_parts(value: &str) -> Option<(String, String)> {
    let body = value.strip_prefix("mapping(")?.strip_suffix(')')?;
    let mut depth = 0_i32;
    for (index, window) in body.as_bytes().windows(2).enumerate() {
        match window[0] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            _ => {}
        }
        if depth == 0 && window == b"=>" {
            return Some((body[..index].to_owned(), body[index + 2..].to_owned()));
        }
    }
    None
}

fn array_element(value: &str) -> Option<String> {
    if let Some(element) = value.strip_suffix("[]") {
        return Some(element.to_owned());
    }
    let end = value.strip_suffix(']')?;
    let bracket = end.rfind('[')?;
    end[bracket + 1..]
        .chars()
        .all(|character| character.is_ascii_digit())
        .then(|| end[..bracket].to_owned())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VslType {
    Scalar {
        name: String,
        width: Option<u16>,
    },
    Mapping(Box<VslType>, Box<VslType>),
    DynamicArray(Box<VslType>),
    FixedArray {
        length: usize,
        element: Box<VslType>,
    },
    Struct(Vec<VslType>),
    VirtualStruct,
    Unknown,
}

impl VslType {
    pub(crate) fn display(&self) -> String {
        match self {
            Self::Scalar { name, .. } => name.clone(),
            Self::Mapping(key, value) => {
                format!("mapping({} => {})", key.display(), value.display())
            }
            Self::DynamicArray(element) => format!("{}[]", element.display()),
            Self::FixedArray { length, element } => format!("{}[{length}]", element.display()),
            Self::Struct(_) => "struct".to_owned(),
            Self::VirtualStruct => "virtual-struct".to_owned(),
            Self::Unknown => "unknown".to_owned(),
        }
    }

    pub(crate) fn mapping_value(&self) -> Option<&Self> {
        let Self::Mapping(_, value) = self else {
            return None;
        };
        Some(value)
    }

    pub(crate) fn dynamic_array_element(&self) -> Option<&Self> {
        let Self::DynamicArray(element) = self else {
            return None;
        };
        Some(element)
    }

    pub(crate) fn is_virtual_struct(&self) -> bool {
        matches!(self, Self::VirtualStruct)
    }

    pub(crate) fn is_byte_string(&self) -> bool {
        matches!(
            self,
            Self::Scalar { name, .. } if matches!(name.as_str(), "bytes" | "string")
        )
    }

    pub(crate) fn scalar_width(&self) -> Option<u16> {
        let Self::Scalar { width, .. } = self else {
            return None;
        };
        *width
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SemanticField {
    pub slot_index: usize,
    pub offset: u8,
    pub ty: VslType,
}

pub(crate) fn expected_type_at(
    record: &VirtualStorageLayoutRecord,
    all_records: &[VirtualStorageLayoutRecord],
    slot_index: usize,
    offset: u8,
) -> Option<String> {
    semantic_fields(record, all_records)
        .into_iter()
        .find(|field| field.slot_index == slot_index && field.offset == offset)
        .map(|field| field.ty.display())
}

/// Returns the field schema without replacing a virtual struct with its
/// display-only marker. Recursive storage validation uses this to follow the
/// child record declared at the current parent slot.
pub(crate) fn raw_expected_type_at(
    record: &VirtualStorageLayoutRecord,
    slot_index: usize,
    offset: u8,
) -> Option<VslType> {
    semantic_fields(record, &[])
        .into_iter()
        .find(|field| field.slot_index == slot_index && field.offset == offset)
        .map(|field| field.ty)
}

pub(crate) fn virtual_struct_child<'a>(
    record: &'a VirtualStorageLayoutRecord,
    all_records: &'a [VirtualStorageLayoutRecord],
    slot_index: usize,
) -> Option<&'a VirtualStorageLayoutRecord> {
    let expected_path = format!("{}.{}", record.virtual_path, slot_index);
    all_records.iter().find(|child| {
        child.virtual_path == expected_path
            && child.parent_virtual_path.as_deref() == Some(record.virtual_path.as_str())
    })
}

pub(crate) fn expected_field_start_at(
    record: &VirtualStorageLayoutRecord,
    slot_index: usize,
    offset: u8,
) -> Option<u8> {
    let group = record.slots.get(slot_index)?;
    let mut start = 0_u16;
    for width in group {
        let end = start.saturating_add(*width);
        let bit_offset = u16::from(offset).saturating_mul(8);
        if bit_offset >= start && bit_offset < end {
            return Some((start / 8) as u8);
        }
        start = end;
    }
    None
}

/// Compiles the parts of VSL that can anchor a bytecode storage trace without
/// deciding its compatibility. At present this is deliberately limited to
/// scalar storage keys and mapping key chains.
pub(crate) fn storage_trace_hints(layout: &VirtualStorageLayout) -> StorageTraceHints {
    let mut hints = StorageTraceHints::default();

    for record in layout
        .records
        .iter()
        .filter(|record| record.parent_virtual_path.is_none())
    {
        let Some(root) = decode_slot(&record.id) else {
            continue;
        };
        for field in semantic_fields(record, &layout.records) {
            let Some(slot) = slot_at(root, field.slot_index) else {
                continue;
            };
            if let Some(ty) = dyn_sol_type(&field.ty) {
                hints.insert_persistent_scalar_type(slot, ty);
            }
            if let Some(key_types) = mapping_key_types(&field.ty) {
                hints.insert_persistent_mapping_key_types(slot, key_types);
            }
        }
    }

    hints
}

fn semantic_fields(
    record: &VirtualStorageLayoutRecord,
    all_records: &[VirtualStorageLayoutRecord],
) -> Vec<SemanticField> {
    let tokens = record
        .layout
        .iter()
        .filter_map(|token| parse_token(token))
        .collect::<Vec<_>>();
    let mut index = 0;
    let mut types = Vec::new();
    while index < tokens.len() {
        let Some((ty, next, _)) = parse_type(&tokens, index) else {
            break;
        };
        types.push(ty);
        index = next;
    }

    let mut cursor = LayoutCursor::default();
    let mut fields = Vec::new();
    for ty in &types {
        place_type(ty, &mut cursor, &mut fields, record, all_records);
    }
    fields
}

fn dyn_sol_type(ty: &VslType) -> Option<DynSolType> {
    match ty {
        VslType::Scalar { name, width } if name == "bool" => Some(DynSolType::Bool),
        VslType::Scalar { name, .. } if name == "address" => Some(DynSolType::Address),
        VslType::Scalar { name, width } if name.starts_with("uint") => {
            Some(DynSolType::Uint((*width)? as usize))
        }
        VslType::Scalar { name, width } if name.starts_with("int") => {
            Some(DynSolType::Int((*width)? as usize))
        }
        VslType::Scalar { name, width } if name.starts_with("bytes") => {
            Some(DynSolType::FixedBytes(((*width)? / 8) as usize))
        }
        _ => None,
    }
}

fn mapping_key_types(ty: &VslType) -> Option<Vec<DynSolType>> {
    let VslType::Mapping(key, value) = ty else {
        return None;
    };
    let mut key_types = vec![dyn_sol_type(key)?];
    if let Some(mut nested) = mapping_key_types(value) {
        key_types.append(&mut nested);
    }
    Some(key_types)
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

fn slot_at(mut slot: Slot, index: usize) -> Option<Slot> {
    for _ in 0..index {
        for byte in slot.iter_mut().rev() {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
        if slot.iter().all(|byte| *byte == 0) {
            return None;
        }
    }
    Some(slot)
}

#[derive(Default)]
struct LayoutCursor {
    slot_index: usize,
    bit_offset: u16,
}

fn place_type(
    ty: &VslType,
    cursor: &mut LayoutCursor,
    fields: &mut Vec<SemanticField>,
    record: &VirtualStorageLayoutRecord,
    all_records: &[VirtualStorageLayoutRecord],
) {
    match ty {
        VslType::Scalar {
            width: Some(width), ..
        } if *width < 256 => {
            if cursor.bit_offset.saturating_add(*width) > 256 {
                cursor.slot_index += 1;
                cursor.bit_offset = 0;
            }
            fields.push(SemanticField {
                slot_index: cursor.slot_index,
                offset: (cursor.bit_offset / 8) as u8,
                ty: ty.clone(),
            });
            cursor.bit_offset += *width;
            if cursor.bit_offset == 256 {
                cursor.slot_index += 1;
                cursor.bit_offset = 0;
            }
        }
        VslType::Struct(members) => {
            align(cursor);
            for member in members {
                place_type(member, cursor, fields, record, all_records);
            }
            align(cursor);
        }
        VslType::FixedArray { length, element } => {
            align(cursor);
            for _ in 0..*length {
                place_type(element, cursor, fields, record, all_records);
            }
            align(cursor);
        }
        _ => {
            align(cursor);
            let slot_index = cursor.slot_index;
            let mut resolved = ty.clone();
            resolve_virtual_struct(&mut resolved, record, all_records, slot_index);
            fields.push(SemanticField {
                slot_index,
                offset: 0,
                ty: resolved,
            });
            cursor.slot_index += 1;
        }
    }
}

fn align(cursor: &mut LayoutCursor) {
    if cursor.bit_offset != 0 {
        cursor.slot_index += 1;
        cursor.bit_offset = 0;
    }
}

fn resolve_virtual_struct(
    ty: &mut VslType,
    record: &VirtualStorageLayoutRecord,
    all_records: &[VirtualStorageLayoutRecord],
    slot_index: usize,
) {
    match ty {
        VslType::Mapping(_, value) | VslType::DynamicArray(value) => {
            resolve_virtual_struct(value, record, all_records, slot_index);
        }
        VslType::FixedArray { element, .. } => {
            resolve_virtual_struct(element, record, all_records, slot_index);
        }
        VslType::VirtualStruct => {
            let expected_path = format!("{}.{}", record.virtual_path, slot_index);
            if all_records.iter().any(|child| {
                child.virtual_path == expected_path
                    && child.parent_virtual_path.as_deref() == Some(record.virtual_path.as_str())
            }) {
                *ty = VslType::Scalar {
                    name: format!("virtual-struct({expected_path})"),
                    width: None,
                };
            }
        }
        _ => {}
    }
}

fn parse_type(tokens: &[u8], index: usize) -> Option<(VslType, usize, bool)> {
    let token = *tokens.get(index)?;
    let scalar = scalar(token);
    if scalar != VslType::Unknown {
        return Some((scalar, index + 1, false));
    }

    match token {
        0xf4 => parse_struct(tokens, index + 1),
        0xf1 => parse_mapping(tokens, index + 1),
        0xf2 => parse_dynamic_array(tokens, index + 1),
        0xf3 => parse_fixed_array(tokens, index + 1),
        _ => Some((VslType::Unknown, index + 1, false)),
    }
}

fn parse_struct(tokens: &[u8], mut index: usize) -> Option<(VslType, usize, bool)> {
    let mut members = Vec::new();
    while *tokens.get(index)? != 0xff {
        let (member, next, _) = parse_type(tokens, index)?;
        members.push(member);
        index = next;
    }
    Some((VslType::Struct(members), index + 1, true))
}

fn parse_mapping(tokens: &[u8], index: usize) -> Option<(VslType, usize, bool)> {
    let (key, mut next, _) = parse_type(tokens, index)?;
    if *tokens.get(next)? == 0xff {
        return Some((
            VslType::Mapping(Box::new(key), Box::new(VslType::VirtualStruct)),
            next + 1,
            true,
        ));
    }
    let (value, value_next, value_closed) = parse_type(tokens, next)?;
    next = value_next;
    if !value_closed {
        expect_end(tokens, &mut next)?;
    }
    Some((VslType::Mapping(Box::new(key), Box::new(value)), next, true))
}

fn parse_dynamic_array(tokens: &[u8], index: usize) -> Option<(VslType, usize, bool)> {
    if *tokens.get(index)? == 0xff {
        return Some((
            VslType::DynamicArray(Box::new(VslType::VirtualStruct)),
            index + 1,
            true,
        ));
    }
    let (element, mut next, element_closed) = parse_type(tokens, index)?;
    if !element_closed {
        expect_end(tokens, &mut next)?;
    }
    Some((VslType::DynamicArray(Box::new(element)), next, true))
}

fn parse_fixed_array(tokens: &[u8], index: usize) -> Option<(VslType, usize, bool)> {
    let byte_count = usize::from(*tokens.get(index)?);
    let length_end = index.checked_add(1 + byte_count)?;
    let length = tokens
        .get(index + 1..length_end)?
        .iter()
        .fold(0_usize, |value, byte| (value << 8) | usize::from(*byte));
    if *tokens.get(length_end)? == 0xff {
        return Some((
            VslType::FixedArray {
                length,
                element: Box::new(VslType::VirtualStruct),
            },
            length_end + 1,
            true,
        ));
    }
    let (element, mut next, element_closed) = parse_type(tokens, length_end)?;
    if !element_closed {
        expect_end(tokens, &mut next)?;
    }
    Some((
        VslType::FixedArray {
            length,
            element: Box::new(element),
        },
        next,
        true,
    ))
}

fn expect_end(tokens: &[u8], index: &mut usize) -> Option<()> {
    (*tokens.get(*index)? == 0xff).then_some(())?;
    *index += 1;
    Some(())
}

fn scalar(token: u8) -> VslType {
    let scalar = |name: &str, width: u16| VslType::Scalar {
        name: name.to_owned(),
        width: Some(width),
    };
    match token {
        0x01 => scalar("bool", 8),
        0x02 => scalar("enum", 8),
        0x03 => scalar("address", 160),
        0x10..=0x2f => scalar(
            &format!("uint{}", (u16::from(token) - 0x10 + 1) * 8),
            (u16::from(token) - 0x10 + 1) * 8,
        ),
        0x30..=0x4f => scalar(
            &format!("int{}", (u16::from(token) - 0x30 + 1) * 8),
            (u16::from(token) - 0x30 + 1) * 8,
        ),
        0x50..=0x6f => scalar(
            &format!("bytes{}", u16::from(token) - 0x50 + 1),
            (u16::from(token) - 0x50 + 1) * 8,
        ),
        0x70 => scalar("function-external", 192),
        0x71 => VslType::Scalar {
            name: "function-internal".to_owned(),
            width: None,
        },
        0x72 => VslType::Scalar {
            name: "bytes".to_owned(),
            width: Some(256),
        },
        0x73 => VslType::Scalar {
            name: "string".to_owned(),
            width: Some(256),
        },
        0xfe => VslType::Unknown,
        _ => VslType::Unknown,
    }
}

fn parse_token(token: &str) -> Option<u8> {
    u8::from_str_radix(token.trim_start_matches("0x"), 16).ok()
}

#[cfg(test)]
mod tests {
    use super::{SemanticCompatibility, VslType, compare_semantic_types, expected_type_at};
    use crate::compose::{
        VirtualStorageLayoutKind, VirtualStorageLayoutRecord, VirtualStorageLayoutSource,
    };

    fn record(layout: &[&str]) -> VirtualStorageLayoutRecord {
        VirtualStorageLayoutRecord {
            id: "0x01".to_owned(),
            virtual_path: "fixture".to_owned(),
            parent_virtual_path: None,
            kind: VirtualStorageLayoutKind::Normal,
            code_width: 1,
            layout: layout.iter().map(|item| (*item).to_owned()).collect(),
            serialized_layout: Vec::new(),
            slots: vec![vec![8, 160], vec![256]],
            source: VirtualStorageLayoutSource::Erc8042,
            source_name: "Fixture.sol".to_owned(),
            contract_name: "Fixture".to_owned(),
            struct_name: None,
            diamond_name: None,
        }
    }

    #[test]
    fn maps_packed_scalars_to_semantic_types() {
        let record = record(&["0x01", "0x03", "0xf1", "0x03", "0x2f", "0xff"]);
        assert_eq!(
            expected_type_at(&record, &[], 0, 0),
            Some("bool".to_owned())
        );
        assert_eq!(
            expected_type_at(&record, &[], 0, 1),
            Some("address".to_owned())
        );
        assert_eq!(
            expected_type_at(&record, &[], 1, 0),
            Some("mapping(address => uint256)".to_owned())
        );
    }

    #[test]
    fn keeps_virtual_struct_as_semantic_marker() {
        assert_eq!(VslType::VirtualStruct.display(), "virtual-struct");
    }

    #[test]
    fn links_container_children_to_their_virtual_path() {
        let root = record(&["0xf1", "0x53", "0xff"]);
        let mut child = record(&["0x2f", "0x01", "0x03"]);
        child.id = "0x02".to_owned();
        child.virtual_path = "fixture.0".to_owned();
        child.parent_virtual_path = Some("fixture".to_owned());
        assert_eq!(
            expected_type_at(&root, &[root.clone(), child], 0, 0),
            Some("mapping(bytes4 => virtual-struct(fixture.0))".to_owned())
        );
    }

    #[test]
    fn accepts_mapping_key_noise_but_not_value_shape_changes() {
        assert_eq!(
            compare_semantic_types("mapping(uint256 => uint256)", "mapping(address => uint256)"),
            SemanticCompatibility::KeyMismatch
        );
        assert_eq!(
            compare_semantic_types(
                "mapping(bytes4 => address)",
                "mapping(bytes4 => virtual-struct(fixture.0))"
            ),
            SemanticCompatibility::Contradiction
        );
    }

    #[test]
    fn accepts_full_word_uint_and_bytes32_representations() {
        assert_eq!(
            compare_semantic_types("uint256", "bytes32"),
            SemanticCompatibility::Compatible
        );
        assert_eq!(
            compare_semantic_types("bytes32", "uint256"),
            SemanticCompatibility::Compatible
        );
        assert_eq!(
            compare_semantic_types("uint8", "bool"),
            SemanticCompatibility::Contradiction
        );
    }
}
