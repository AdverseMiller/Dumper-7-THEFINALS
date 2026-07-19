# Discovery automation

The Discovery fork bootstraps from live structure and instruction semantics. It does not resolve or decrypt the protected `GObjects` global, use a fixed `FName::AppendString` or ProcessEvent RVA, or suspend game threads.

## Automated recovery chain

The current chain is:

1. Find a likely first `FUObjectItem` allocation in committed readable memory.
2. Recover the item stride and `UObject::InternalIndex` offset from many consecutive live objects.
3. Search committed writable memory for an aligned pointer equal to the first chunk. Treat each occurrence as a possible chunk table.
4. Infer elements per chunk from `InternalIndex - slot` votes in the second chunk, with standard Unreal values retained only as fallback candidates. A candidate table is accepted only when its first entry is the independently found chunk and every consecutive chunk contains objects whose `InternalIndex` agrees with `(chunk index * elements per chunk) + slot`.
5. Scan the final validated chunk backward and derive the enumeration limit from the highest live object whose stored `InternalIndex` matches its structural position.
6. Recover the protected UObject address hash and slot decoder from code, then classify the Class, Outer, and Name selectors independently for all four base-slot values over thousands of objects.
7. Locate `FName::AppendString` by executable instruction shape and require one usable implementation.
8. Walk a live UObject vtable, resolve wrapper call targets, and accept ProcessEvent only when the dispatcher has the expected repeated function-flag accesses and native/script branch semantics.
9. Recover and cross-object validate `UFunction::FunctionFlags`, including its XOR key, plus `UFunction::ExecFunction`.
10. Recover the FField name transform and FField/FFieldClass layout by checking known fields with distinct names, cast flags, IDs, and superclass relationships.
11. Recover `FProperty::PropertyFlags` and `Offset_Internal` keys and the ArrayDim, ElementSize, property base, and derived-property member offsets from multiple known properties.
12. Validate the complete FProperty layout before generation. Missing, overlapping, unaligned, or implausibly distant members stop the dump.
13. Recover `FText` size from the reflected return property of `Conv_StringToText` without calling the function.

All critical Discovery paths fail closed. A table, geometry, object, or index relationship that cannot satisfy its independent structural checks is rejected. There is no protected-global RVA, cipher template, disassembler, or fallback decoder in the object-array bootstrap.

## Generated artifacts

Each run writes `discovery-report.json` beside the SDK. It records the structural object-array strategy, runtime table address, chunk geometry, recovered RVAs for the remaining systems, transforms, selector tables, layout offsets, XOR keys, object count, and validation policy.

The generated C++ SDK is protector-aware where it needs to access UObject identity:

- `UObject::GetClass()`, `GetOuter()`, and `GetFName()` contain the recovered decoder constants from that run.
- generated UFunction wrappers use `GetClass()` rather than a nonexistent raw `Class` member;
- protected UObject Class, Outer, and Name storage is padding, not falsely emitted as ordinary fields;
- protected FField names are emitted as `ProtectedName[0x10]`;
- protected FProperty values are named `EncodedPropertyFlags` and `EncodedOffset`;
- the unvalidated protected `FFieldClass::ClassFlags` member is omitted;
- zero-sized native structs with valid reflected members use their reflected member end as a conservative size fallback;
- FText is emitted as opaque storage of the reflected size because its internal data-pointer layout is intentionally not actively probed.

There is deliberately no generated stable `GObjects` RVA. `Offsets::GObjects` is zero and IDA mappings omit the symbol because the reconstructed chunk table is a session-specific heap allocation. Consumers that need runtime object enumeration must provide their own structural resolver or initialize the generated wrapper manually with a compatible object-array representation.

The report is the authoritative record for protected reflection storage. A consumer that needs to inspect FField names or encoded FProperty members at runtime must implement the recorded decoder rather than treating those bytes as ordinary fields.

## Validation, July 18-19 2026

The current `fb7af7f2` build completed a clean live dump in about 13.8 seconds. The game process remained running throughout and after generation.

Values from that run, included only as historical validation evidence and not as inputs, were:

- protected object global RVA `0x0D888A30`;
- `FUObjectItem` stride `0x14`, index at `+0x0C`, and `0x10000` elements per chunk;
- `FName::AppendString` RVA `0x00249EC0`;
- ProcessEvent vtable index `0x4D`, wrapper RVA `0x004AAFC0`, dispatcher RVA `0x004A2EF0`;
- `UFunction::FunctionFlags` at `+0x120`, XOR `0x2`;
- FField Name/Next/Class/Owner at `+0x30/+0x48/+0x50/+0x58`;
- FProperty flags/ArrayDim/ElementSize/value-offset at `+0x70/+0x78/+0x7C/+0x8C`;
- FProperty size `0xD0` and FText size `0x18`.

On July 19, an independent read-only `/proc/<pid>/mem` validation exercised the replacement chain without loading a DLL:

- structural discovery found first chunk `0x7E8D0008`, item stride `0x14`, and index `+0x0C`;
- an aligned reverse-pointer scan found exactly one reference, at runtime table `0x4AE8C340`;
- all nine consecutive chunks validated against their expected internal-index ranges;
- the highest valid live index was `0x825F4`, producing enumeration limit `0x825F5`;
- the table and limit exactly matched an independent decode of the protected global.

The cipher-free C++ implementation subsequently completed a live dump in 37.6 seconds. It scanned 1175.5 MiB before finding the structurally valid table, recovered the same table, geometry, and count listed above, generated all SDK artifacts, and left the game process running. The generated report recorded `global_cipher_used: false`, no stable global RVA, nine chunks, and object count `0x825F5`.

The generated CoreUObject function unit passes a MinGW C++23 syntax check with its layout assertions enabled. Compiling `Basic.cpp` together with every transitively included package still exposes unrelated stock Dumper-7 generator issues in other engine types, including missing `<cmath>` declarations, invalid reflected enum widths, and several pre-existing tail-padding assertions. Those are broader SDK-generator correctness issues, not failures in the Discovery bootstrap or protected CoreUObject decoder.

## What can still break after a rebuild

This is automated, not claimed to be universally update-proof. It should be unaffected by changes to the protected-global RVA, cipher constants, cipher operations, compiler register allocation, or accessor implementation because none of those are read. It will intentionally stop if a rebuild changes a structural invariant beyond the bounded models currently understood, including:

- a nonstandard `FUObjectItem` organization outside the candidate stride/index ranges;
- an unusual elements-per-chunk organization that cannot be inferred from the second chunk and is outside the fallback set;
- a chunk table that is not present in committed writable memory or does not directly contain chunk pointers;
- fewer than two populated chunks, which does not provide enough information to disambiguate geometry;
- a UObject representation whose vtable no longer points into the main module;
- a different UObject hash/slot transform family;
- a different FField name transform family;
- an inlined or ABI-changed `FName::AppendString`;
- a ProcessEvent dispatcher that no longer exposes the current flag-read/native-branch semantics;
- reflection metadata that no longer provides enough independent known objects to disambiguate a layout.

`FFieldClass::ClassFlags` remains separately protected and unused by Dumper-7, so it is deliberately omitted rather than guessed. FText internals also remain opaque in the generated SDK to preserve the no-game-call validation policy.

## Test policy

Building the DLL does not load it. A live test is a separate explicit action. Runtime discovery uses readable-memory queries and guarded reads; it does not attach a debugger, suspend threads, set breakpoints, or patch the process.

For a test, preserve the previous log, inject once, and wait for either `Generating SDK took` or `Dumper-7 aborted safely`. Then verify that the process is still alive, parse `discovery-report.json`, search generated output for impossible negative sizes, and inspect the protector-aware UObject helpers.
