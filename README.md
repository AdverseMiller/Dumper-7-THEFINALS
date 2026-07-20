# Dumper-7 for THE FINALS

A Dumper-7 fork designated for dumping THE FINALS.

The main goal of this fork is to take as much manual work as possible out of updating the dumper. Instead of relying on a list of RVAs and cipher constants, it finds and validates the necessary UE structures at runtime through various heuristics.

## Features

- Cipher-free object-array reconstruction.
- Dynamic protected UObject and FField decoder extraction.
- Semantic AppendString and ProcessEvent discovery.
- Automated reflection-layout recovery.
- Automatic ChildProperties, FField, FFieldClass, and FProperty resolution.
- Protector-aware generated SDK helpers.
- No fixed GObjects, AppendString, or ProcessEvent RVA.
- No debugger attachment, breakpoints, or thread suspension.
- Fail-closed validation instead of silently generating a broken SDK.
- C++ SDK, mappings, IDA mappings, and Dumpspace generation.
- A detailed `discovery-report.json` for everything recovered during the dump.

Given that the game is heavily repacked with each update, there is no guarantee that every new build will work untouched. The aim is to keep any update work small and localized instead of having to reverse and rewrite the dumper again from scratch.

## Tested builds

This fork has been tested successfully against numerous game builds with very different code and reflection layouts, including:

- 10.12 (`23895020`)
- 10.14 (`23999122`)
- 11.0 (`24101480`)
- 11.1 (`24195074`)

Each completed the full SDK, mappings, IDA mappings, and Dumpspace pipeline. The generated CoreUObject SDK also passed its C++ layout assertions, and the game remained running after each final test.

For the full recovery chain and test results, see [Discovery automation](docs/discovery-automation.md).

## Building

Build the project as an x64 Release DLL. With Visual Studio 2022 and CMake:

```powershell
cmake --preset vs2022
cmake --build --preset vs2022-Release
```

The included Visual Studio solution can also be used directly.

## Using it

1. Start THE FINALS and let it finish normal initialization.
2. Load the Release DLL into `Discovery.exe` or `Discovery-d.exe`, depending on the build.
3. Wait for `Generating SDK took (...)` in the Dumper-7 log.
4. Check the generated SDK and `discovery-report.json` before using them.

Loading too early can leave protected code pages unavailable to the scanners. If discovery stops safely near startup, wait until the game is initialized and try again rather than adding a fallback RVA.

Building the DLL does not load it into the game. Loading is always a separate action.

## Output

The default output directory is:

```text
C:\Dumper-7\Discovery
```

Each dump is placed in its own game folder beneath that directory. Wine/Proton users can use `Dumper-7.ini` to redirect output to any host path exposed through the `Z:` drive.

## Configuration

Settings can be changed with `Dumper-7.ini`:

```ini
[Settings]
SleepTimeout=30
SDKNamespaceName=SDK
DumpKey=0x77
SDKGenerationPath=C:/Dumper-7/Discovery
```

- `SleepTimeout` delays the dump.
- `DumpKey` starts it with a Windows virtual key.
- `SDKNamespaceName` changes the generated namespace.
- `SDKGenerationPath` changes the output directory.

For example, a Wine/Proton installation can keep dumps outside its prefix with:

```ini
[Settings]
SDKGenerationPath=Z:/path/on/the/host/Dumper-7/Discovery
```

## Using the generated SDK

See [UsingTheSDK](UsingTheSDK.md) for SDK integration and migration notes.

## Credits

This project is based on [Encryqed/Dumper-7](https://github.com/Encryqed/Dumper-7). The general SDK generator comes from upstream; the THE FINALS automation, protected-runtime recovery, validation, reporting, and generated SDK fixes are maintained in this fork.
