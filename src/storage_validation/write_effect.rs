use crate::{
    DynSolType, Selector,
    compose::{calldata::ComposeCallData, storage::StorageEvidence},
    evm::{
        U256,
        calldata::{CallDataLabel, CallDataLabelType},
        op,
        vm::{StepResult, Vm},
    },
    utils::execute_until_function_start,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
};

const GAS_LIMIT: u32 = 1_000_000;
const MAX_BRANCH_DEPTH: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ComposeWriteEffect {
    Assignment,
    ClearRange { offset: u8, width: u16 },
}

pub(super) type ComposeWriteEffects = BTreeMap<(Selector, usize), ComposeWriteEffect>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Label {
    Constant,
    Loaded([u8; 32]),
    ClearRange {
        source_slot: [u8; 32],
        offset: u8,
        width: u16,
    },
}

impl CallDataLabel for Label {
    fn label(_: usize, _: &DynSolType, _: CallDataLabelType) -> Option<Self> {
        None
    }
}

pub(super) fn trace(
    code: &[u8],
    functions: &[(Selector, usize, Vec<DynSolType>)],
    selected_selectors: &BTreeSet<Selector>,
) -> ComposeWriteEffects {
    let mut effects = BTreeMap::new();
    for (selector, _, arguments) in functions
        .iter()
        .filter(|(selector, _, _)| selected_selectors.contains(selector))
    {
        let calldata = ComposeCallData::<Label>::bounded_copy(*selector, arguments);
        let mut vm = Vm::new(code, &calldata);
        let Some(gas_used) = execute_until_function_start(&mut vm, GAS_LIMIT) else {
            continue;
        };
        trace_rec(
            vm,
            GAS_LIMIT.saturating_sub(gas_used),
            0,
            *selector,
            &mut effects,
        );
    }
    effects
}

pub(super) fn classify(
    evidence: &StorageEvidence,
    effects: &ComposeWriteEffects,
) -> ComposeWriteEffect {
    evidence
        .write_pc
        .and_then(|pc| effects.get(&(evidence.selector, pc)).copied())
        .unwrap_or(ComposeWriteEffect::Assignment)
}

fn trace_rec(
    mut vm: Vm<'_, Label, ComposeCallData<Label>>,
    gas_limit: u32,
    depth: u32,
    selector: Selector,
    effects: &mut ComposeWriteEffects,
) {
    let mut gas_used = 0;
    while !vm.stopped && gas_used <= gas_limit {
        let pc = vm.pc;
        let Ok(step) = vm.step() else {
            break;
        };
        gas_used = gas_used.saturating_add(step.gas_used);
        if gas_used > gas_limit {
            break;
        }

        let branch = usize::try_from(&step.args[0]).ok();
        if apply_step(&mut vm, &step, pc, selector, effects).is_err() {
            break;
        }
        if step.op == op::JUMPI
            && depth < MAX_BRANCH_DEPTH
            && let Some(branch) = branch.filter(|branch| *branch < vm.code.len())
        {
            let mut fork = vm.fork();
            fork.pc = branch;
            trace_rec(
                fork,
                gas_limit.saturating_sub(gas_used) / 2,
                depth + 1,
                selector,
                effects,
            );
        }
    }
}

fn apply_step(
    vm: &mut Vm<'_, Label, ComposeCallData<Label>>,
    step: &StepResult<Label>,
    pc: usize,
    selector: Selector,
    effects: &mut ComposeWriteEffects,
) -> Result<(), Box<dyn Error>> {
    match step.op {
        op::PUSH0..=op::PUSH32 => vm.stack.peek_mut()?.label = Some(Label::Constant),
        op::NOT if is_constant(&step.args[0]) => {
            vm.stack.peek_mut()?.label = Some(Label::Constant);
        }
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
        | op::XOR
        | op::BYTE
        | op::SHL
        | op::SHR
        | op::SAR
            if is_constant(&step.args[0]) && is_constant(&step.args[1]) =>
        {
            vm.stack.peek_mut()?.label = Some(Label::Constant);
        }
        op::SLOAD => vm.stack.peek_mut()?.label = Some(Label::Loaded(step.args[0].data)),
        op::AND => {
            let clear = loaded_and_constant(step).and_then(|(source_slot, mask)| {
                clear_range(mask).map(|(offset, width)| Label::ClearRange {
                    source_slot,
                    offset,
                    width,
                })
            });
            vm.stack.peek_mut()?.label = clear.or_else(|| {
                (is_constant(&step.args[0]) && is_constant(&step.args[1]))
                    .then_some(Label::Constant)
            });
        }
        op::SSTORE => {
            let effect =
                clear_write_effect(step.args[1].label, step.args[0].data, step.args[1].data);
            if let Some(effect) = effect {
                effects.insert((selector, pc), effect);
            }
        }
        _ => {}
    }
    Ok(())
}

fn clear_write_effect(
    value_label: Option<Label>,
    destination_slot: [u8; 32],
    value: [u8; 32],
) -> Option<ComposeWriteEffect> {
    match value_label {
        Some(Label::ClearRange {
            source_slot,
            offset,
            width,
        }) if source_slot == destination_slot => {
            Some(ComposeWriteEffect::ClearRange { offset, width })
        }
        Some(Label::Constant) if U256::from_be_bytes(value).is_zero() => {
            Some(ComposeWriteEffect::ClearRange {
                offset: 0,
                width: 256,
            })
        }
        _ => None,
    }
}

fn is_constant(value: &crate::evm::element::Element<Label>) -> bool {
    value.label == Some(Label::Constant)
}

fn loaded_and_constant(step: &StepResult<Label>) -> Option<([u8; 32], U256)> {
    match (&step.args[0].label, &step.args[1].label) {
        (Some(Label::Loaded(slot)), Some(Label::Constant)) => {
            Some((*slot, U256::from_be_bytes(step.args[1].data)))
        }
        (Some(Label::Constant), Some(Label::Loaded(slot))) => {
            Some((*slot, U256::from_be_bytes(step.args[0].data)))
        }
        _ => None,
    }
}

fn clear_range(mask: U256) -> Option<(u8, u16)> {
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

#[cfg(test)]
mod tests {
    use super::{ComposeWriteEffect, Label, clear_range, clear_write_effect};
    use crate::evm::U256;

    #[test]
    fn recovers_the_range_cleared_by_a_retained_padding_mask() {
        let mask = U256::from(0xffff_ffff_u32) << 224;
        assert_eq!(clear_range(mask), Some((0, 224)));
    }

    #[test]
    fn recovers_a_nonzero_packed_clear_offset() {
        let field: U256 = ((U256::from(1) << 32_usize) - U256::from(1)) << 160_usize;
        assert_eq!(clear_range(!field), Some((20, 32)));
    }

    #[test]
    fn does_not_treat_a_masked_copy_between_slots_as_a_clear() {
        let source_slot = [0x11; 32];
        let destination_slot = [0x22; 32];
        let label = Label::ClearRange {
            source_slot,
            offset: 0,
            width: 224,
        };

        assert_eq!(
            clear_write_effect(Some(label), destination_slot, [0; 32]),
            None
        );
        assert_eq!(
            clear_write_effect(Some(label), source_slot, [0; 32]),
            Some(ComposeWriteEffect::ClearRange {
                offset: 0,
                width: 224,
            })
        );
    }
}
