use evmole::{
    compose::{VirtualStorageLayoutKind, VirtualStorageLayoutRecord, VirtualStorageLayoutSource},
    storage_validation::{StorageValidationInput, VirtualStorageLayout, validate},
};

fn decode_hex(value: &str) -> Vec<u8> {
    let value = value.trim().trim_start_matches("0x");
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn normal_layout() -> VirtualStorageLayoutRecord {
    let layout = [
        "0x2f", "0x53", "0xf4", "0x53", "0xf4", "0x53", "0x17", "0x10", "0xff", "0x13", "0xff",
        "0xf1", "0x03", "0x2f", "0xff", "0xf1", "0x03", "0xf1", "0x03", "0x2f", "0xff", "0xf2",
        "0x10", "0xff",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let mut serialized_layout = vec!["0x01".to_owned()];
    serialized_layout.extend(layout.iter().cloned());

    VirtualStorageLayoutRecord {
        id: "0xb4df32537f6767405c9db7d67260e5375218aecdea91f4240ad14000623cbdff".to_owned(),
        virtual_path: "evmole.normal".to_owned(),
        parent_virtual_path: None,
        kind: VirtualStorageLayoutKind::Normal,
        code_width: 1,
        layout,
        serialized_layout,
        slots: vec![
            vec![256],
            vec![32],
            vec![32],
            vec![32, 64, 8],
            vec![32],
            vec![256],
            vec![256],
            vec![256],
        ],
        source: VirtualStorageLayoutSource::SlotAssignment,
        source_name: "tests/fixtures/legacy/normal-bytecode.txt".to_owned(),
        contract_name: "Normal".to_owned(),
        struct_name: Some("NormalStorage".to_owned()),
        diamond_name: None,
    }
}

fn packed_struct_clear_layout() -> VirtualStorageLayout {
    let root_path = "compose.fixture.packed-struct-clear";
    VirtualStorageLayout {
        records: vec![
            VirtualStorageLayoutRecord {
                id: "0x16a861a6371ce33e2053e823c07ec26da3569fe1bdc9d1885d0995727db10890".to_owned(),
                virtual_path: root_path.to_owned(),
                parent_virtual_path: None,
                kind: VirtualStorageLayoutKind::Normal,
                code_width: 1,
                layout: ["0xf1", "0x53", "0xff"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                serialized_layout: ["0x01", "0xf1", "0x53", "0xff"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                slots: vec![vec![256]],
                source: VirtualStorageLayoutSource::Erc8042,
                source_name: "PackedStructClear.sol".to_owned(),
                contract_name: "PackedStructClear".to_owned(),
                struct_name: Some("Storage".to_owned()),
                diamond_name: None,
            },
            VirtualStorageLayoutRecord {
                id: "0xfd9e0ce174a083b23f7c56dd6c49e71f06e6bb4e359f3e153b6c87effc9c3f9d".to_owned(),
                virtual_path: format!("{root_path}.0"),
                parent_virtual_path: Some(root_path.to_owned()),
                kind: VirtualStorageLayoutKind::Normal,
                code_width: 1,
                layout: ["0x03", "0x53", "0x53"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                serialized_layout: ["0x01", "0x03", "0x53", "0x53"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                slots: vec![vec![160, 32, 32]],
                source: VirtualStorageLayoutSource::Erc8042,
                source_name: "PackedStructClear.sol".to_owned(),
                contract_name: "PackedStructClear".to_owned(),
                struct_name: Some("FacetNode".to_owned()),
                diamond_name: None,
            },
        ],
    }
}

#[test]
fn validates_recovered_write_against_the_vsl() {
    let report = validate(&StorageValidationInput {
        bytecode: decode_hex(include_str!("fixtures/legacy/normal-bytecode.txt")),
        virtual_storage_layout: VirtualStorageLayout {
            records: vec![normal_layout()],
        },
    });

    assert!(report.collisions.is_empty());
    assert!(report.uncertain_scopes.is_empty());
    assert_eq!(report.validated_variables.len(), 1, "{report:#?}");
    assert_eq!(report.validated_variables[0].expected_type, "uint8");
    assert_eq!(report.validated_variables[0].observed_type, "uint8");
    assert!(report.validated_variables[0].location.pc.is_some());
}

#[test]
fn reports_actual_bytecode_that_overwrites_a_packed_vsl_slot() {
    let report = validate(&StorageValidationInput {
        bytecode: decode_hex(include_str!(
            "fixtures/storage-validation/wrong-packed-write-bytecode.txt"
        )),
        virtual_storage_layout: VirtualStorageLayout {
            records: vec![normal_layout()],
        },
    });

    assert_eq!(report.collisions.len(), 1, "{report:#?}");
    assert_eq!(
        report.collisions[0].virtual_path,
        "evmole.normal.slot[3].byte[0]"
    );
    assert_eq!(report.collisions[0].expected_type, "bytes4");
    assert_eq!(report.collisions[0].observed_type, "uint256");
    assert!(report.collisions[0].location.pc.is_some());
}

#[test]
fn treats_a_packed_struct_delete_as_clear_only_evidence() {
    let report = validate(&StorageValidationInput {
        bytecode: decode_hex(include_str!(
            "fixtures/storage-validation/packed-struct-clear-bytecode.txt"
        )),
        virtual_storage_layout: packed_struct_clear_layout(),
    });

    assert!(report.collisions.is_empty(), "{report:#?}");
    assert!(
        report.uncertain_scopes.iter().any(|scope| {
            scope.virtual_path.as_deref()
                == Some("compose.fixture.packed-struct-clear.0.slot[0].byte[0]")
                && scope
                    .reason
                    .contains("clear-only write covers byte range 0..28")
        }),
        "{report:#?}"
    );
    assert!(
        report.uncertain_scopes.iter().any(|scope| {
            scope.virtual_path.as_deref()
                == Some("compose.fixture.packed-struct-clear.0.slot[0].byte[20]")
                && scope
                    .reason
                    .contains("clear-only write covers byte range 20..24")
        }),
        "{report:#?}"
    );
}
