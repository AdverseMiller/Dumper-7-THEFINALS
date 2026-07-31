# Discovery automation

The Discovery fork bootstraps from live structure and instruction semantics. It does not resolve or decrypt the protected `GObjects` global, use a fixed `FName::AppendString` or ProcessEvent RVA, or suspend game threads.

## Automated recovery chain

The current chain is:

1. Find a likely first `FUObjectItem` allocation in committed readable memory.
2. Recover the item stride and `UObject::InternalIndex` offset from many consecutive live objects.
3. Search committed writable memory for an aligned pointer equal to the first chunk. Treat each occurrence as a possible chunk table.
4. Infer elements per chunk from `InternalIndex - slot` votes in the second chunk, with standard Unreal values retained only as fallback candidates. A candidate table is accepted only when its first entry is the independently found chunk and every consecutive chunk contains objects whose `InternalIndex` agrees with `(chunk index * elements per chunk) + slot`.
5. Scan the final validated chunk backward and derive the enumeration limit from the highest live object whose stored `InternalIndex` matches its structural position.
6. Recover the protected UObject address hash and slot geometry from the dispatcher. First treat each slot's stored low qword as its value and classify Class and Outer by object-array membership, Name by relative FName plausibility, and the fourth lane by its stable zero value. Validate every hash bucket over thousands of objects. Only if that structural low-lane model fails does the older generic SIMD instruction extractor run; there is no build-specific cipher helper.
7. Locate `FName::AppendString` semantically. Scan decoded executable pages for the numbered-name suffix operation, use the PE exception directory to recover each containing function boundary, and require that the same function resets the wide-string builder, reads `FName::Number`, appends UTF-16 `_`, and formats `Number - 1`. Require exactly one usable implementation.
8. Walk a live UObject vtable, resolve wrapper call targets, and accept ProcessEvent only when the dispatcher has the expected repeated function-flag accesses and native/script branch semantics.
9. Recover and cross-object validate `UFunction::FunctionFlags`, including its XOR key, plus `UFunction::ExecFunction`.
10. Recover `UClass::CastFlags` from the common aligned location shared by Class, Struct, Actor, and Field, accepting either plaintext or one common XOR key. Recover `UStruct::MinAlignment` from the Guid and Transform alignment relationship rather than a fixed class value or member ordering assumption.
11. Recover `UStruct::ChildProperties`, `FField::Next`, and `FField::Owner` jointly. Retain every pointer-aligned UStruct member that exposes complete Color, Guid, and Vector field chains during bootstrap. After extracting the protected FField-name decoder, require the exact known field-name sets, a single common owner member that points every field back to its containing UStruct, finite acyclic chains, and consistent results across up to 1,024 additional live UStructs. If multiple head/link pairs remain equivalent, count nearby executable references to each pair inside unwind-defined functions and require one unique best-supported pair. Member ordering is not used.
12. Recover the FField name transform and FField/FFieldClass layout by checking known fields with distinct names, cast flags, IDs, and superclass relationships.
13. Recover `FProperty::PropertyFlags` and `Offset_Internal` keys and the ArrayDim, ElementSize, property base, and derived-property member offsets from multiple known properties. Recover the bool-property base structurally from the four consecutive size/offset/mask bytes across live bool fields, without requiring build-specific property names.
14. Validate the complete FProperty layout before generation. Missing, overlapping, unaligned, or implausibly distant members stop the dump.
15. Recover `FText` size from the reflected return property of `Conv_StringToText` without calling the function.

All critical Discovery paths fail closed. A table, geometry, object, or index relationship that cannot satisfy its independent structural checks is rejected. There is no protected-global RVA, cipher template, disassembler, or fallback decoder in the object-array bootstrap.

## Generated artifacts

Each run writes `discovery-report.json` beside the SDK. It records the structural object-array strategy, runtime table address, chunk geometry, recovered RVAs for the remaining systems, transforms, selector tables, layout offsets, XOR keys, object count, and validation policy.

The generated C++ SDK is protector-aware where it needs to access UObject identity:

- `UObject::GetClass()`, `GetOuter()`, and `GetFName()` contain the recovered slot geometry and selector tables from that run, plus a generic decoder program only when the stored low lane is not already the value.
- `UObject::HasTypeFlag()` and `IsA()` apply the recovered `UClass::CastFlags` XOR key rather than reading the protected member as plaintext;
- generated UFunction wrappers use `GetClass()` rather than a nonexistent raw `Class` member;
- protected UObject Class, Outer, and Name storage is padding, not falsely emitted as ordinary fields;
- protected FField names are emitted as opaque `ProtectedName` byte arrays sized to the gap before the next recovered member;
- protected FProperty values are named `EncodedPropertyFlags` and `EncodedOffset`;
- the unvalidated protected `FFieldClass::ClassFlags` member is omitted;
- zero-sized native structs with valid reflected members use their reflected member end as a conservative size fallback;
- FText is emitted as opaque storage of the reflected size because its internal data-pointer layout is intentionally not actively probed.

There is deliberately no generated stable `GObjects` RVA. `Offsets::GObjects` is zero and IDA mappings omit the symbol because the reconstructed chunk table is a session-specific heap allocation. Consumers that need runtime object enumeration must provide their own structural resolver or initialize the generated wrapper manually with a compatible object-array representation.

The report is the authoritative record for protected reflection storage. It records whether UObject identity used structurally validated stored low lanes or the generic instruction fallback, and serializes the recovered hash and any required SIMD program. A consumer that needs to inspect FField names or encoded FProperty members at runtime must implement their separately recorded decoders rather than treating those bytes as ordinary fields.

## Validation, July 18-19 2026

The completed chain was exercised end-to-end against the archived 10.12 and 10.14 depots and the installed Steam build `24195074`. All three builds reached every generator, produced a parseable `discovery-report.json`, left the game process alive, and generated a CoreUObject unit that passes a MinGW C++23 syntax check with layout assertions enabled. The final 10.14 regression generated 3,639 files in 11.56 seconds before that archive was removed; the current-build regression also completed all C++ SDK, mappings, IDA mappings, and Dumpspace stages.

The three builds deliberately exercise materially different layouts:

| Recovered value | Archived 10.12 | Archived 10.14 | Build 24195074 |
| --- | ---: | ---: | ---: |
| `FName::AppendString` RVA | `0x240590` | `0x230470` | `0x249EC0` |
| ProcessEvent wrapper / index / dispatcher | `0x4A2720` / `0x52` / `0x49DB20` | `0x4AA0B0` / `0x4E` / `0x4BBFF0` | `0x4AAFC0` / `0x4D` / `0x4A2EF0` |
| `UClass::CastFlags` | `+0x130` | `+0x1D8` | `+0x150` |
| `UStruct::Children` / `ChildProperties` | `+0xB8` / `+0xC8` | `+0x118` / `+0xC0` | `+0xC8` / `+0xC0` |
| `UStruct::PropertiesSize` / `MinAlignment` | `+0xB0` / `+0x108` | `+0xF0` / `+0x110` | `+0x118` / `+0x108` |
| FField Name / Next / Class / Owner | `+0xA0/+0xB8/+0xB0/+0xC0` | `+0x60/+0x70/+0x80/+0x90` | `+0x30/+0x48/+0x50/+0x58` |
| FProperty flags / ArrayDim / ElementSize / value offset | `+0x100/+0xFC/+0x108/+0xCC` | `+0xA8/+0xE0/+0xE8/+0xB4` | `+0x70/+0x78/+0x7C/+0x8C` |
| FProperty size / bool-property base | `0x130` | `0x110` | `0xD0` |

These values are evidence, never resolver inputs. Both tested builds used a zero `UClass::CastFlags` XOR key, while the generated helpers still apply the dynamically recovered key so a future nonzero encoding is represented correctly.

The current `fb7af7f2` build completed its post-10.14 regression dump in 14.13 seconds. The game process remained running throughout and after generation. It generated 3,739 files, produced a parseable report, and its CoreUObject unit passed a MinGW C++23 syntax check with generated layout assertions enabled.

Values from that run, included only as historical validation evidence and not as inputs, were:

- protected object global RVA `0x0D888A30`;
- `FUObjectItem` stride `0x14`, index at `+0x0C`, and `0x10000` elements per chunk;
- `FName::AppendString` RVA `0x00249EC0`;
- ProcessEvent vtable index `0x4D`, wrapper RVA `0x004AAFC0`, dispatcher RVA `0x004A2EF0`;
- `UFunction::FunctionFlags` at `+0x120`, XOR `0x2`;
- FField Name/Next/Class/Owner at `+0x30/+0x48/+0x50/+0x58`;
- FProperty flags/ArrayDim/ElementSize/value-offset at `+0x70/+0x78/+0x7C/+0x8C`;
- FProperty size `0xD0` and FText size `0x18`.

That build exposed runtime-equivalent ChildProperties heads at `+0xC0` and `+0x110`. Both traversed the same 3,569 fields across 544 structs with the same `FField::Next` and Owner layout. Executable use-site evidence selected `+0xC0`; the final live retry counted 8,602 supporting unwind functions for `+0xC0` versus 4,643 for `+0x110`. This corrects the earlier positional interpretation of `+0x110` and demonstrates why selecting the highest matching member was not stable.

The same regression exposed a generator-only protected-storage issue. This build places FField Name at `+0x30` and Next at `+0x48`, leaving a 24-byte opaque region rather than the previously assumed 16 bytes. The generator now derives the byte-array width from the next recovered member independently for FField and FFieldClass. The runtime decoder still consumes its validated 16-byte input, while the generated class preserves every intervening opaque byte and therefore satisfies its layout assertions.

The final 10.14 regression additionally exercised the case where protected `FFieldClass::Name` is the last recovered class member at `+0x60`. The predefined-structure size calculation now includes the complete array dimension instead of only one byte of opaque storage. After that correction, the same live process completed every generator, the report retained `fixed_rvas_used: false` and `process_suspended: false`, and CoreUObject passed its MinGW C++23 layout assertions. The successful log was retained outside the deleted game archive as `Dumper-7.10.14-final-automation-success.log`.

The corrected predefined-array sizing was then retested on installed build `24195074`. It again selected ChildProperties `+0xC0`, recovered FField Name/Next/Class/Owner at `+0x30/+0x48/+0x50/+0x58`, completed every generator, and passed the same CoreUObject compile assertions. This confirms the generic size correction does not regress the current layout. The retained log is `Dumper-7.latest-24195074-post-10.14-regression-success.log`.

On July 19, an independent read-only `/proc/<pid>/mem` validation exercised the replacement chain without loading a DLL:

- structural discovery found first chunk `0x7E8D0008`, item stride `0x14`, and index `+0x0C`;
- an aligned reverse-pointer scan found exactly one reference, at runtime table `0x4AE8C340`;
- all nine consecutive chunks validated against their expected internal-index ranges;
- the highest valid live index was `0x825F4`, producing enumeration limit `0x825F5`;
- the table and limit exactly matched an independent decode of the protected global.

The cipher-free C++ implementation subsequently completed a live dump in 37.6 seconds. It scanned 1175.5 MiB before finding the structurally valid table, recovered the same table, geometry, and count listed above, generated all SDK artifacts, and left the game process running. The generated report recorded `global_cipher_used: false`, no stable global RVA, nine chunks, and object count `0x825F5`.

Compiling `Basic.cpp` together with every transitively included package still exposes unrelated stock Dumper-7 generator issues in other engine types, including missing `<cmath>` declarations, invalid reflected enum widths, and several pre-existing tail-padding assertions. Those are broader SDK-generator correctness issues, not failures in the Discovery bootstrap or protected CoreUObject decoder.

On July 19, the fixed `FName::AppendString` prologue signature was replaced with the semantic selector described above. The live module exposed 449,122 unwind-defined functions and 12 decoded functions that wrote a UTF-16 underscore; only one also reset the wide-string builder and implemented the `FName::Number - 1` suffix path. It resolved the known implementation at RVA `0x00249EC0`, produced valid names through reflection and property-layout initialization, and reached SDK generation. A subsequent isolated retry resolved the same RVA and then stopped safely at the independent ProcessEvent decoder gate.

The selector deliberately scans only decoded, readable pages. Protected pages that have not executed yet remain encrypted and inaccessible, so loading Dumper-7 before normal game initialization can produce `semantic scan found no decoded implementation`. That is a timing/precondition failure rather than permission to guess an RVA; the resolver remains fail closed.

The generic protected-UObject extractor was also loaded against the archived 10.14 build. It recovered 21 scalar hash instructions and seven SIMD decoder instructions directly from the ProcessEvent dispatcher, captured the input register and constants, and validated Class, Outer, and Name selector maps over live objects. It then recovered the ProcessEvent wrapper at RVA `0x004AA0B0`, vtable index `0x4E`, dispatcher RVA `0x004BBFF0`, and `UFunction::FunctionFlags` at `+0x120`. No build-family identifier or fixed cipher recipe was used.

On July 30, build `24438055` changed the slot accessor to call a carryless-multiply helper. Read-only sampling showed that the decoded result equaled the stored low qword for all 272 tested slots across 68 live UObjects; the upper qword acted as redundant validation data. The Dumper now tries the stored-low-lane model before parsing any SIMD transform, requires Class, Outer, Name, and empty-lane structure in all four hash buckets, and falls back only to the existing generic instruction extractor used by older builds. The build-specific carryless helper and key extraction were removed.

The former 10.14 `UStruct::ChildProperties` failure was caused by an invalid ordering assumption in the stock pointer scan. That build stores `Children` at `+0x118`, while `ChildProperties` is earlier at `+0xC0`; starting the scan after `Children` could therefore never find it. The Discovery path scans a bounded UStruct member region and preserves every structurally valid property-chain head rather than choosing by position. The initial head is provisional and exists only to bootstrap the FField-name decoder. The final pass jointly resolves the head, link, and owner members from decoded names and ownership topology across many live structs. Executable head/link references provide a fail-closed tie-breaker for runtime-equivalent auxiliary property lists. Consequently, neither proximity to `PropertiesSize` nor being the first or last matching member is a resolver input.

The archived 10.12 build (`23895020`) exposed two runtime-equivalent UStruct heads at `+0xC8` and `+0xD8`. Both pointed to the same fields and produced identical decoded names, owner relationships, and cross-struct topology over 544 structs and 3,567 fields. The executable-reference tie-breaker selected `+0xC8` with 1,894 supporting unwind functions versus 1,627 for `+0xD8`. Executable functions are copied with bounded `ReadProcessMemory` calls before inspection; failed or partial snapshots are skipped. This is necessary because protected code-page permissions can change concurrently, making direct byte dereferences unsafe even after a successful `VirtualQuery`.

That build also produced a false FField-class candidate at `+0x1F0`. FProperty allocations were spaced `0x140` bytes apart, so reading `field + 0x1F0` reached the following allocation's genuine `Class` member at `nextField + 0xB0`. Validating the complete Guid, Color, and Vector chains, including each terminal field, rejected the allocation-stride alias and selected the real class member at `+0xB0`. Vector properties are validated as numeric rather than specifically float because UE5 builds may reflect FVector components as double properties.

The final guarded 10.12 run generated 3,697 files and all C++ SDK, mappings, IDA mappings, and Dumpspace outputs in 33.85 seconds. Its report parsed successfully, its CoreUObject unit passed a MinGW C++23 syntax check with generated layout assertions enabled, and the game remained running after generation.

The FField name decoder is now instruction-driven as well. It scans readable executable ranges for 16-byte field loads, extracts a bounded SIMD program, captures register or RIP-relative constants, and extracts the scalar XOR/rotate tail. The interpreter supports moves, XOR, AND, AND-NOT, OR, word and qword shifts, word addition, low-word shuffles, and byte shuffles. Candidates are accepted only when they produce plausible FNames and decode the live Guid, Vector, and Color validation fields to their expected names. Multiple equivalent implementations are permitted; the shortest validated program is retained and serialized in `discovery-report.json`.

On archived 10.14, three implementations independently validated. The selected program recovered protected FField names at `+0x60` using six vector instructions, scalar XOR `0xE0997EB5CB2F44C6`, and rotate-left 32. Structural validation then recovered FField Next/Class/Owner at `+0x70/+0x80/+0x90` and FFieldClass CastFlags/Id/SuperClass at `+0x10/+0x58/+0x50`. This differs from the newer shuffle/word-rotate implementation and was recovered without a build-family selector. After that gate, the structural bool-property scan replaced absent old-build name anchors and recovered the `0x110` property base, allowing every generation stage to complete. Unvalidated FField object flags and editor-only metadata are omitted in Discovery rather than guessed.

## What can still break after a rebuild

This is automated, not claimed to be universally update-proof. It should be unaffected by changes to the protected-global RVA, cipher constants, cipher operations, compiler register allocation, or accessor implementation because none of those are read. It will intentionally stop if a rebuild changes a structural invariant beyond the bounded models currently understood, including:

- a nonstandard `FUObjectItem` organization outside the candidate stride/index ranges;
- an unusual elements-per-chunk organization that cannot be inferred from the second chunk and is outside the fallback set;
- a chunk table that is not present in committed writable memory or does not directly contain chunk pointers;
- fewer than two populated chunks, which does not provide enough information to disambiguate geometry;
- a UObject representation whose vtable no longer points into the main module;
- a protected UObject hash/slot implementation that uses scalar or SIMD operations outside the bounded interpreter, or one whose dataflow no longer reaches the dispatcher in a recoverable form;
- an FField name implementation whose dataflow is not straight-line from a 16-byte field load, or which uses operations outside the bounded SIMD/scalar interpreter;
- a `UClass::CastFlags` encoding more complex than plaintext or one common XOR key across the validation classes;
- a UStruct layout in which ChildProperties cannot be distinguished by decoded field names, owner topology, cross-struct consistency, and executable head/link references;
- an inlined or ABI-changed `FName::AppendString`, or a run started before its protected page has been decoded;
- a ProcessEvent dispatcher that no longer exposes the current flag-read/native-branch semantics;
- reflection metadata that no longer provides enough independent known objects to disambiguate a layout.

`FFieldClass::ClassFlags` remains separately protected and unused by Dumper-7, so it is deliberately omitted rather than guessed. FText internals also remain opaque in the generated SDK to preserve the no-game-call validation policy.

## Test policy

Building the DLL does not load it. A live test is a separate explicit action. Runtime discovery uses readable-memory queries and guarded reads; it does not attach a debugger, suspend threads, set breakpoints, or patch the process.

For a test, preserve the previous log, inject once, and wait for either `Generating SDK took` or `Dumper-7 aborted safely`. Then verify that the process is still alive, parse `discovery-report.json`, search generated output for impossible negative sizes, and inspect the protector-aware UObject helpers.
