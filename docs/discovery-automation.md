# Discovery automation

The Discovery fork bootstraps from live structure and instruction semantics. It does not use a fixed `GObjects`, `FName::AppendString`, or ProcessEvent RVA, and it does not suspend game threads.

## Automated recovery chain

The current chain is:

1. Find a likely first `FUObjectItem` allocation in committed readable memory.
2. Recover the item stride, `UObject::InternalIndex` offset, and elements-per-chunk geometry from many consecutive live objects.
3. Scan committed, readable executable regions for possible protected-global accessors and disassemble them with the X86-only Capstone engine embedded in the DLL.
4. Concretely evaluate the accessor's data flow instead of requiring one byte template. The evaluator follows GPR and XMM values through memory loads, moves, XOR/OR, `pshufb`, per-lane shifts, scalar shifts/rotates, arithmetic, and byte swaps. Legacy SSE and VEX/AVX forms are supported.
5. Observe candidate count and chunk-table results, then accept a global only when its decoded first chunk agrees with the independently discovered allocation, exactly one chunk geometry matches, and every active chunk validates structurally.
6. Recover the protected UObject address hash and slot decoder from code, then classify the Class, Outer, and Name selectors independently for all four base-slot values over thousands of objects.
7. Locate `FName::AppendString` by executable instruction shape and require one usable implementation.
8. Walk a live UObject vtable, resolve wrapper call targets, and accept ProcessEvent only when the dispatcher has the expected repeated function-flag accesses and native/script branch semantics.
9. Recover and cross-object validate `UFunction::FunctionFlags`, including its XOR key, plus `UFunction::ExecFunction`.
10. Recover the FField name transform and FField/FFieldClass layout by checking known fields with distinct names, cast flags, IDs, and superclass relationships.
11. Recover `FProperty::PropertyFlags` and `Offset_Internal` keys and the ArrayDim, ElementSize, property base, and derived-property member offsets from multiple known properties.
12. Validate the complete FProperty layout before generation. Missing, overlapping, unaligned, or implausibly distant members stop the dump.
13. Recover `FText` size from the reflected return property of `Conv_StringToText` without calling the function.

All critical Discovery paths fail closed. Unsupported instructions invalidate any registers they write, and a scan that is ambiguous or cannot satisfy its independent structural checks raises an error before an old address, guessed key, or invalid layout is used. The former current-build byte-template extractor remains as a compatibility fallback; `discovery-report.json` records whether `semantic-x86-concrete-dataflow` or `current-template-fallback` was used.

This semantic path covers both protected-global families observed so far:

- the current 64-bit-lane XOR/rotate/shuffle accessor;
- the documented older `pshufb -> xor -> xor -> rotl32` accessor.

It does not need to recover a named Python formula before decoding. It executes the accessor's supported instruction semantics over the live encrypted bytes and constants, then validates the concrete results independently.

## Generated artifacts

Each run writes `discovery-report.json` beside the SDK. It records the recovered RVAs, transforms, selector tables, layout offsets, XOR keys, object count, and validation policy.

The generated C++ SDK is protector-aware where it needs to access UObject identity:

- `UObject::GetClass()`, `GetOuter()`, and `GetFName()` contain the recovered decoder constants from that run.
- generated UFunction wrappers use `GetClass()` rather than a nonexistent raw `Class` member;
- protected UObject Class, Outer, and Name storage is padding, not falsely emitted as ordinary fields;
- protected FField names are emitted as `ProtectedName[0x10]`;
- protected FProperty values are named `EncodedPropertyFlags` and `EncodedOffset`;
- the unvalidated protected `FFieldClass::ClassFlags` member is omitted;
- zero-sized native structs with valid reflected members use their reflected member end as a conservative size fallback;
- FText is emitted as opaque storage of the reflected size because its internal data-pointer layout is intentionally not actively probed.

The report is the authoritative record for protected reflection storage. A consumer that needs to inspect FField names or encoded FProperty members at runtime must implement the recorded decoder rather than treating those bytes as ordinary fields.

## Live validation, July 18 2026

The current `fb7af7f2` build completed a clean live dump in about 13.8 seconds. The game process remained running throughout and after generation.

Values from that run, included only as validation evidence and not as inputs, were:

- protected object global RVA `0x0D888A30`;
- `FUObjectItem` stride `0x14`, index at `+0x0C`, and `0x10000` elements per chunk;
- `FName::AppendString` RVA `0x00249EC0`;
- ProcessEvent vtable index `0x4D`, wrapper RVA `0x004AAFC0`, dispatcher RVA `0x004A2EF0`;
- `UFunction::FunctionFlags` at `+0x120`, XOR `0x2`;
- FField Name/Next/Class/Owner at `+0x30/+0x48/+0x50/+0x58`;
- FProperty flags/ArrayDim/ElementSize/value-offset at `+0x70/+0x78/+0x7C/+0x8C`;
- FProperty size `0xD0` and FText size `0x18`.

An independent `/proc/<pid>/mem` Python validator previously recovered the same object-global location and chunk geometry. The live DLL then recovered the remaining layers internally and generated the SDK, mappings, IDA mappings, Dumpspace, and report.

That successful run used the extracted current-family template. The first live test of the new semantic scanner terminated the game while scanning the executable image. Its scan had incorrectly treated an entire PE section as one readable buffer. The scanner now divides every executable section with `VirtualQuery` and passes Capstone only committed, readable, non-guarded region bounds. Per request, the corrected semantic build has only been compiled and statically inspected; it has not been loaded again.

The generated CoreUObject function unit passes a MinGW C++23 syntax check with its layout assertions enabled. Compiling `Basic.cpp` together with every transitively included package still exposes unrelated stock Dumper-7 generator issues in other engine types, including missing `<cmath>` declarations, invalid reflected enum widths, and several pre-existing tail-padding assertions. Those are broader SDK-generator correctness issues, not failures in the Discovery bootstrap or protected CoreUObject decoder.

## What can still break after a rebuild

This is automated, not claimed to be universally update-proof. It should survive ordinary address movement, register allocation changes, legacy-SSE versus VEX encoding changes, reordered supported operations, and changed embedded constants because the accessor is evaluated at runtime. It will intentionally stop if a rebuild changes a semantic instruction family or ABI beyond the bounded evaluator currently understood, including:

- a protected-global accessor that adds unsupported vector operations, helper calls, or control-flow-dependent decoding;
- a different UObject hash/slot transform family;
- a different FField name transform family;
- an inlined or ABI-changed `FName::AppendString`;
- a ProcessEvent dispatcher that no longer exposes the current flag-read/native-branch semantics;
- reflection metadata that no longer provides enough independent known objects to disambiguate a layout.

`FFieldClass::ClassFlags` remains separately protected and unused by Dumper-7, so it is deliberately omitted rather than guessed. FText internals also remain opaque in the generated SDK to preserve the no-game-call validation policy.

## Test policy

Building the DLL does not load it. A live test is a separate explicit action. Runtime discovery uses readable-memory queries and guarded reads; it does not attach a debugger, suspend threads, set breakpoints, or patch the process.

For a test, preserve the previous log, inject once, and wait for either `Generating SDK took` or `Dumper-7 aborted safely`. Then verify that the process is still alive, parse `discovery-report.json`, search generated output for impossible negative sizes, and inspect the protector-aware UObject helpers.
