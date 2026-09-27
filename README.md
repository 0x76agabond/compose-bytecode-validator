# Compose Bytecode Validator

Compose's Rust bytecode storage validator. It validates a facet's deployed
runtime bytecode against its Solidity-derived Virtual Storage Layout (VSL).

This is not a general-purpose Solidity decompiler and it does not attempt to
reconstruct a complete contract layout from bytecode. Compose already has a
stronger source-side model: the VSL knows declared types, packing, container
boundaries, and named storage roots. This project asks a narrower question:

> Does this facet's bytecode storage evidence clearly contradict the full diamond VSL?

## Virtual Storage Layout

The VSL is the canonical source-side model of the full diamond's declared
storage. It is generated from Solidity's compact AST before this validator sees
any bytecode. A record has a namespace-derived root identity and a compact
layout encoding, while its readable virtual path describes the variable or
virtual struct child that occupies each position.

The layout is a small recursive token stream:

- `0x01..0x73`: one byte per scalar type, for example `0x01` is `bool` and
  `0x03` is `address`,
- `0xf1`: mapping,
- `0xf2`: dynamic array,
- `0xf3`: fixed array,
- `0xf4`: struct,
- `0xff`: end of the current container.

For example, this Solidity shape:

```solidity
struct Node {
    address target;
    bytes4 previousId;
    bytes8 nextId;
}

struct Storage {
    mapping(bytes4 => Node[]) nodes;
}
```

uses two records. The root record is:

```text
0xf1 0x53 0xf2 0xff
mapping bytes4 dynamic-array virtual-child
```

The child record at `nodes.0` holds the `Node` schema:

```text
0x03 0x53 0x57
address bytes4 bytes8
```

Here `0xf2 0xff` means the dynamic-array element is a virtual child rather
than an inline type. `0xf2` is already the mapping value, so that one `0xff`
finishes the array branch and the mapping is complete too, it does not close an
unrelated outer struct. The separate child record preserves the struct schema
and physical span.

It preserves the Solidity rules that matter for bytecode validation:

- declaration order, slot boundaries, byte packing, and fixed-array physical
  span,
- semantic boundaries for structs, mappings, and dynamic arrays, including
  virtual child records for structs inside containers, and
- declared scalar type and width at every comparable slot and byte offset.

That gives the validator a complete expected storage map for the diamond rather
than asking a decompiler to rediscover one from every facet in isolation. VSL
does not prove that bytecode reaches every path or interpret arbitrary assembly,
it supplies the expected coordinate system and the type/packing constraints
against which recovered persistent writes are challenged.

## Inputs and Verdicts

Each validation run consumes:

- a facet's runtime bytecode,
- VSL records generated from the Solidity compact AST, and
- concrete root slots derived from the VSL namespaces.

The validator traces persistent `SSTORE` operations and compares concrete
storage evidence with the canonical full-diamond VSL. It reports four evidence
collections:

| Evidence | Meaning |
| --- | --- |
| `collisions` | A persistent write contradicts a VSL slot, offset, width, or value/container shape. |
| `validatedVariables` | A recovered persistent write matches one VSL variable. |
| `uncertainScopes` | A write has a concrete storage scope but cannot be compared conclusively. |
| `diagnostics` | The engine cannot recover even a concrete persistent storage root. |
| `delegatecallWarnings` | A delegatecall target or selector cannot be traced with the supplied chain context. This is non-blocking and separate from storage uncertainty. |

## What Differs From Original EVMole

Original EVMole is a general bytecode-to-Solidity recovery tool. Its storage
output is designed to summarize inferred contract state, so it may intentionally
collapse `KECCAK256 + constant` accesses back to a mapping or array root.

This fork keeps EVMole's interpreter, CFG, ABI argument recovery, and symbolic
storage tracer as the analysis substrate, then adds a Compose-specific layer:

- it accepts the canonical full-diamond VSL as an external input rather than
  inferring the entire source layout from bytecode,
- it retains `SSTORE` evidence needed for contradiction checks, including
  persistent root slot, constant mapping-value slot delta, packed byte offset,
  field width, selector, and program counter,
- it compares only concrete writes against declared VSL variables and returns
  a proven collision, validation, scoped uncertainty, or unresolved-root
  diagnostic, and
- it preserves generic-decompiler uncertainty instead of letting VSL turn an
  ambiguous bytecode trace into a safe verdict.

The scope is deliberately narrower than a complete decompiler: the validator
tries to prove a bytecode/VSL contradiction, not reconstruct every storage
variable that a facet could access. Mapping key-type differences are diagnostic
only, value shape, container shape, byte width, packing offset, and root slot
identity are storage compatibility evidence.

## Fixture Coverage

The fixture families in `tests/fixtures/evmole/` are write-based challenge suites.
Each directory contains a canonical Solidity contract, its checked-in canonical
VSL, and one or more incompatible contracts that use the same storage root.
Foundry builds every runtime bytecode before the runner compares each variant
against the canonical VSL.

| Fixture | Challenge | Current evidence |
| --- | --- | --- |
| `1-normal` | Packed nested-struct width shifts | Canonical writes validate, incompatible slot shifts produce collisions. |
| `2-constant-key` | Constant mapping keys and packed dynamic-array width | VSL anchors constant keys, canonical array writes validate and width mismatch collides. |
| `3-storage-key` | Storage-derived mapping keys and dynamic/fixed indexes | VSL anchors the loaded `uint64` key, dynamic and fixed packed element mismatches collide. |
| `4-mapping-struct` | Reordered packed members inside a mapping value | Mapping-value child slots and packed fields validate, reordered members collide. |
| `5-array-struct` | Packed and multi-slot array structs, reordered members, scalar projections, and adjacent arrays | Canonical child paths validate, reordered fields and an incompatible element stride collide, a lone matching member is scoped as uncertain. |
| `5.1-mapping-struct` | Two-member mapping structs, a scalar terminal projection, and reordered members | Two distinct child positions validate or collide, a lone matching member is scoped as uncertain. |
| `6-array-mapping-struct` | Indexed mapping to an array of packed structs | Canonical indexed writes validate, reordered members collide without uncertainty. |
| `7-array-mapping-struct-push` | Mapping to an array of packed structs created with `push()`, including a nested dynamic array variant | Recursive paths validate, incompatible nested containers and extra fields collide, with scoped uncertainty where `push()` loses a child boundary. |
| `final-full-storage` | Full representative VSL: packed primitives, inline structs, mappings, arrays, fixed arrays, struct containers, and independent ERC-8110-style domains | Canonical writes validate across 29 recovered variables, incompatible terminal, nested, and dynamic-key writes collide. |
| `8-bytes-string` | `bytes`, `string`, `bytes[]`, and `string[]` assignment and append flows | Type swaps produce scoped uncertainty rather than false collisions, a proven incompatible container shape still collides. |
| `8.1-string-array-struct-bytes` | `string[]` versus an array of structs with a `bytes data` field, with payload writes and empty `push()` | Both layouts have the same observed physical shape, payload and empty variants remain scoped uncertainty rather than false validation or collision. |
| `9-delegatecall` | Immutable, persistent-storage, calldata, transient, symbolic, empty-code, missing-selector, and nested delegatecall targets | Proven targets recurse against the same VSL, untraceable targets return non-blocking delegatecall warnings. |
| `10-total-assembly` | Inline-assembly writes to direct slots, packed fields, a mapping, a dynamic array, and a caller-provided raw slot | Known roots and manual `KECCAK256` paths validate, type-width mismatches collide, raw or composite writes stay scoped uncertainty. |
| `11-solady-erc721` | Solady-style ownership, balance/aux, and operator-approval coordinates across three ERC-8110 domains | Four custom writes remain unresolved evidence rather than false validation or collision. |

An inferred fallback `uint256` cannot prove a collision. The raw tracer marks
whether the write value type was actually recovered, fallback values are
reported only as scoped uncertainty. Dynamic-array length writes are compared
as container metadata rather than as element writes.

### Current Result Snapshot

#### Fixture 1: Normal

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Canonical | 0 | 11 | 0 |
| Packed-width mismatch | 2 | 3 | 0 |

**Characteristics:** Direct roots, packed fields, fixed slots, and packed dynamic arrays.

**Conclusion:** High confidence for direct Solidity slots and packing, no conclusion beyond recovered writes.

#### Fixture 2: Constant Key

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Canonical | 0 | 4 | 0 |
| Widened dynamic element | 1 | 3 | 0 |

**Characteristics:** Constant mapping keys and packed dynamic-array elements.

**Conclusion:** High confidence for value shape with a constant key anchor, no conclusion about unrecovered key semantics.

#### Fixture 3: Storage Key

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Canonical | 0 | 8 | 0 |
| Dynamic-width mismatch | 2 | 0 | 0 |
| Fixed-width mismatch | 2 | 0 | 0 |

**Characteristics:** Mapping keys loaded from storage and dynamic or fixed indexes.

**Conclusion:** High confidence when VSL supplies the storage-key type, no conclusion for an unanchored key path.

#### Fixture 4: Mapping Struct

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Canonical | 0 | 5 | 0 |
| Reordered packed members | 2 | 3 | 0 |

**Characteristics:** Mapping child deltas from `KECCAK256 + constant` and packed struct members.

**Conclusion:** High confidence when child deltas and packed offsets recover, no conclusion when either is lost.

#### Fixture 5: Array Struct

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Canonical | 0 | 9 | 0 |
| Reordered members | 2 | 1 | 0 |
| Wide reordered members | 2 | 1 | 0 |
| Address-only projection | 0 | 0 | 1 |
| Adjacent arrays | 1 | 0 | 1 |

**Characteristics:** Packed and multi-slot array structs, scalar projections, and stride recovery.

**Conclusion:** High confidence for complete element and stride evidence, no conclusion from a lone member projection.

#### Fixture 5.1: Mapping Struct Projection

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Canonical two members | 0 | 2 | 0 |
| Single terminal projection | 0 | 0 | 1 |
| Reordered two members | 2 | 0 | 0 |

**Characteristics:** Mapping values whose terminal scalar can resemble a complete value.

**Conclusion:** Useful for rejecting reordered mappings with multiple members, no conclusion from one terminal member.

#### Fixture 6: Array Mapping Struct

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Canonical | 0 | 3 | 0 |
| Reordered members | 3 | 0 | 0 |

**Characteristics:** Indexed array, mapping, and struct paths resolved recursively.

**Conclusion:** High confidence for fully recovered recursive paths, no conclusion when a path segment is missing.

#### Fixture 7: Array Mapping Struct Push

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Canonical | 0 | 4 | 0 |
| Incompatible struct | 1 | 1 | 1 |
| Incompatible container and fields | 3 | 1 | 1 |

**Characteristics:** Mapping to packed struct arrays created with `push()`, including nested arrays.

**Conclusion:** Useful after child writes recover, no conclusion for the `push()` boundary itself.

#### Final Full Storage

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Canonical | 0 | 29 | 3 |
| Compatible prefix | 0 | 1 | 0 |
| Incompatible layout | 12 | 4 | 3 |

**Characteristics:** Combined primitive, struct, mapping, array, fixed-array, and independent ERC-8110-style domains.

**Conclusion:** High confidence across recovered layouts, no conclusion for terminal projections, bytes/string, or missing child paths.

#### Fixture 8: Bytes and String

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Canonical | 0 | 2 | 4 |
| Swapped `bytes` and `string` | 0 | 2 | 4 |
| Incompatible container | 2 | 0 | 0 |

**Characteristics:** Dynamic `bytes`, `string`, `bytes[]`, and `string[]` payload flows.

**Conclusion:** Useful for container-shape contradictions, no conclusion about bytes versus string payload semantics.

#### Fixture 8.1: String Array Struct Bytes

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Struct array with payload | 0 | 0 | 2 |
| Struct array empty `push()` | 0 | 0 | 1 |
| String array with payload | 0 | 0 | 2 |
| String array empty `push()` | 0 | 0 | 1 |

**Characteristics:** `string[]` compared with an array of structs holding `bytes data`.

**Conclusion:** No confidence for this physical ambiguity, so it deliberately reaches no compatibility conclusion.

#### Fixture 9: Delegatecall

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Deployed target graph | 1 | 0 | 4 |

**Characteristics:** Anvil-backed target resolution through immutable, storage, calldata, transient, symbolic, empty-code, missing-selector, and nested calls.

**Conclusion:** High confidence for recovered target code and selectors, single-member struct projections and untraceable targets remain non-conclusive.

#### Fixture 10: Assembly Evidence

| Variant | Collisions | Validated | Uncertain |
| --- | ---: | ---: | ---: |
| Canonical assembly | 0 | 4 | 2 |
| Incompatible assembly | 2 | 2 | 2 |

**Characteristics:** Direct slots, packed composite writes, manual mapping and array paths, and caller-provided raw slots.

**Conclusion:** Useful for concrete assembly paths, no conclusion for raw slots or opaque packed composites.

#### Fixture 11: Solady Custom Coordinates

| Variant | Collisions | Validated | Uncertain | Diagnostics |
| --- | ---: | ---: | ---: | ---: |
| Canonical custom coordinate | 0 | 0 | 2 | 2 |
| Incompatible packed order | 0 | 0 | 2 | 2 |

**Characteristics:** Solady-style ownership, balance/aux, and operator-approval coordinates across independent ERC-8110 domains.

**Conclusion:** No compatibility confidence for custom coordinates, so they remain unresolved evidence only.

## Delegatecall Handling

`validate_with_delegate_calls` is an optional extension of the direct-write
validator. It receives a chain code source and the original diamond/proxy
storage address. A recovered target is traced recursively against the same
full-diamond VSL because `DELEGATECALL` changes code context but retains storage
context.

The validator follows a deliberately narrow target allowlist:

- bytecode constants and immutable runtime values,
- persistent `SLOAD` values when their concrete slot can be read through
  `eth_getStorageAt`, and
- nested targets reached from those traces, bounded by a configurable depth
  limit and `(target, selector)` visited set.

Persistent `SSTORE` is the only storage write domain compared with VSL,
transient storage is not layout state. Targets outside the supported recovery
set are reported as non-blocking `delegatecallWarnings`.

The generic EVMole VM remains unchanged. Compose uses
`src/compose/calldata.rs` only for this path: it bounds materialized
`CALLDATACOPY` bytes while preserving EVMole's symbolic `CALLDATASIZE` on the
stack, which is enough to recover forwarded selectors.

## Known Limitations

### Evidence Coverage

The validator proves recovered contradictions, an empty collision list is not a
complete safety proof. Unreached paths and unsupported bytecode patterns,
including assembly-origin code that the symbolic tracer cannot recover, remain
outside the evidence set.

### Dynamic `bytes` and `string`

`bytes` and `string` share Solidity's physical storage encoding, so exchanging
them is not a physical collision. Accesses to these fields are reported as
scoped uncertainty because bytecode cannot distinguish the source-level type.
For `bytes[]` and `string[]`, the outer array header can still validate while
each element and its payload remain uncertain. A proven incompatible outer
container or root shape is still reported as a collision.

The same ambiguity extends to `string[]` and a one-member array of structs with
a `bytes data` field, both use a one-slot array element whose payload has the
same bytes/string encoding. Payload writes and empty `push()` operations
therefore remain scoped uncertainty unless another recovered member proves a
different struct shape.

### `push()` Child Boundaries

For some nested dynamic-array `push()` paths, the tracer loses an element child
boundary. It reports a scoped uncertainty for the affected array-length write,
independently recovered member writes still validate or collide normally.

### Clear-only Writes

Solidity can delete a packed struct with `SLOAD -> AND(mask) -> SSTORE` and no
replacement value. A Compose-owned write-effect pass recovers the same-slot
clear range without changing EVMole's storage tracer. Its root, container path,
and starting packed field are matched against VSL, but a zeroing operation
carries no value-type evidence, so it is reported as scoped uncertainty rather
than validation or collision.

### Inline Assembly

Assembly follows the same validation path as compiler-generated bytecode. If
its `SSTORE` pattern is recoverable by EVMole, it validates or collides against
the VSL normally. If the root, path, or packed member cannot be recovered, the
bytecode cannot be matched to the VSL, so it returns scoped uncertainty and
makes no safe conclusion.

### Delegatecall Target Sources

Only constant/immutable targets and concrete persistent `SLOAD` targets are
followed. Calldata, `TLOAD`, hash/arithmetic expressions, unresolved storage
slots, empty code, RPC failures, and missing selectors produce a non-blocking
`delegatecallWarning`. `CALLCODE` is intentionally not modeled.

### In-Transaction Upgrades

Persistent target recovery reads a pinned chain snapshot. It does not yet model
an in-transaction storage overlay. A pattern such as `upgradeAndCall` can
`SSTORE` a new implementation address and then `SLOAD` that same slot before
the transaction finishes. `eth_getStorageAt` still returns the pre-transaction
implementation, so this validator cannot prove the actual delegatecall target
for that path. Treat upgrade-and-call flows as unsupported until the tracer
tracks preceding storage writes into delegatecall target resolution.

## Run the Validator

Build all write fixtures with Foundry and run the assertion-backed comparison:

```sh
./run-storage-validation.sh
```

Set `COMPOSE_FIXTURE_CASE=4-mapping-struct` to run one case. Set
`COMPOSE_TRACE_STORAGE=1` to print raw storage evidence before comparison.

Run the test suite:

```sh
cargo test --features fixture
```

Run the delegatecall fixture, which starts an Anvil node, deploys the diamond,
pins the resulting block, and validates the deployed target graph:

```sh
./run-delegatecall-fixture.sh
```

## Generate VSL Inputs

`tools/generate-vsl.mts` compiles one Solidity source with Foundry's `--ast`
output and writes canonical VSL JSON. The tool-local VSL builder is
copied from Compose CLI and preserves a readable `virtualPath`, its `id` is
canonicalized with `cast keccak` so it can match physical EVM storage roots.

It requires Foundry (`forge`, `cast`) and `tsx` from a Compose CLI checkout.
From this repository, with a Compose CLI checkout available at the sibling
path used below:

```sh
node ../../../Compose/cli/node_modules/tsx/dist/cli.mjs tools/generate-vsl.mts \
  tests/fixtures/evmole/1-normal/Canonical.sol Case1Canonical \
  --out tests/fixtures/evmole/1-normal/canonical-vsl.json
```

Set `FOUNDRY_FORGE` or `FOUNDRY_CAST` when the executables are not on `PATH`.

## Architecture

[Architecture.md](./Architecture.md) documents the inherited symbolic-execution
engine and the Compose validator boundary. The main extension points are:

- `src/storage/mod.rs`: raw storage evidence before EVMole collapses records,
- `src/storage_validation/`: active VSL-driven persistent-write validator,
- `src/compose/`: historical unbiased and VSL-bias comparison experiments,
- `tools/`: VSL generation from Solidity AST,
- `tests/fixtures/evmole/`: canonical VSL and incompatible bytecode challenge
  sources for each fixture case.

## Provenance

This repository began as a fork of
[EVMole](https://github.com/cdump/evmole) v0.9.3. The EVM interpreter,
selector/argument recovery, and storage tracer remain the analysis substrate,
Compose-specific validator logic is added as a separate host layer. The original
MIT license is retained in [LICENSE](./LICENSE).
