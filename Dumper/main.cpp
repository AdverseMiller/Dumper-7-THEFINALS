#include <windows.h>
#include <iostream>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <format>

#include "Generators/CppGenerator.h"
#include "Generators/MappingGenerator.h"
#include "Generators/IDAMappingGenerator.h"
#include "Generators/DumpspaceGenerator.h"

#include "Generators/Generator.h"
#include "Settings.h"
#include "Unreal/Discovery.h"
#include "Unreal/ObjectArray.h"

namespace
{
	void DumpDiscoveryProperty(const UEStruct Owner, const char* const MemberName)
	{
		const UEProperty Property = Owner.FindMember(MemberName, EClassCastFlags::Property);
		if (!Property)
		{
			std::cerr << std::format("Discovery property probe: {}.{} not found\n", Owner.GetName(), MemberName);
			return;
		}

		auto [UObjectClass, FieldClass] = Property.GetClass();
		std::cerr << std::format(
			"Discovery property probe: {}.{} field=0x{:X} field_class=0x{:X} cast_flags=0x{:016X} offset=0x{:X} size=0x{:X}\n",
			Owner.GetName(), MemberName,
			reinterpret_cast<uintptr_t>(Property.GetAddress()),
			reinterpret_cast<uintptr_t>(FieldClass.GetAddress()),
			static_cast<uint64>(Property.GetCastFlags()), Property.GetOffset(), Property.GetSize());

		const auto* const Bytes = static_cast<const uint8*>(Property.GetAddress());
		for (int32 Offset = 0x140; Offset < 0x190; Offset += sizeof(uintptr_t))
		{
			const auto Value = *reinterpret_cast<const uintptr_t*>(Bytes + Offset);
			std::cerr << std::format("  property +0x{:03X}: 0x{:016X}\n", Offset, Value);
		}
	}

	void RunDiscoveryPropertyProbes()
	{
		const auto Probe = [](const char* const StructName, const std::initializer_list<const char*> Members)
		{
			const UEStruct Struct = ObjectArray::FindStructFast(StructName);
			if (!Struct)
			{
				std::cerr << std::format("Discovery property probe: {} struct not found\n", StructName);
				return;
			}
			for (const char* const Member : Members)
				DumpDiscoveryProperty(Struct, Member);
		};

		Probe("Actor", { "RootComponent" });
		Probe("SceneComponent", { "RelativeLocation", "RelativeRotation", "RelativeScale3D" });
		Probe("Player", { "PlayerController" });
		Probe("GameInstance", { "LocalPlayers" });
		Probe("Controller", { "PlayerState", "Pawn", "ControlRotation" });
		Probe("PlayerController", { "PlayerCameraManager" });
		Probe("PlayerCameraManager", { "CameraCachePrivate", "CameraCache" });
		Probe("GameStateBase", { "PlayerArray" });
		Probe("PlayerState", { "PawnPrivate", "PlayerNamePrivate" });

		const UEClass PlayerController = ObjectArray::FindClassFast("PlayerController");
		const UEFunction Project = PlayerController.GetFunction("PlayerController", "ProjectWorldLocationToScreen");
		if (Project)
		{
			DumpDiscoveryProperty(Project, "WorldLocation");
			DumpDiscoveryProperty(Project, "ScreenLocation");
			DumpDiscoveryProperty(Project, "bPlayerViewportRelative");
			DumpDiscoveryProperty(Project, "ReturnValue");
		}
	}
}

enum class EFortToastType : uint8
{
    Default                                  = 0,
    Subdued                                  = 1,
    Impactful                                = 2,
    Lock                                     = 3,
    EFortToastType_MAX                       = 4,
};

DWORD MainThread(HMODULE Module)
{
	AllocConsole();
	FILE* Dummy = nullptr;
	freopen_s(&Dummy, "CONIN$", "r", stdin);

	try
	{

	Settings::Config::Load();
	std::filesystem::create_directories(Settings::Generator::SDKGenerationPath);
	const auto LogPath = std::filesystem::path(Settings::Generator::SDKGenerationPath) / "Dumper-7.log";
	freopen_s(&Dummy, LogPath.string().c_str(), "w", stderr);
	std::cerr.clear(); // clear internal error flags on cerr after redirect
	std::cerr << std::boolalpha << std::hex;

	std::cerr << "Initializing [Dumper-7]\n";
	std::cerr << "SDK Generation Path: " << Settings::Generator::SDKGenerationPath << "\n";
	Settings::Config::DelayDumperStart();

	std::cerr << "Started Generation [Dumper-7]!\n";
	auto DumpStartTime = std::chrono::high_resolution_clock::now();

	Generator::InitEngineCore();
	std::cerr << "Discovery milestone: engine core initialized\n";
	Generator::InitInternal();
	std::cerr << "Discovery milestone: internal package/struct managers initialized\n";

	if constexpr (Discovery::ProbeOnly)
	{
		RunDiscoveryPropertyProbes();
		std::cerr << "Discovery milestone: property probe completed; SDK generation intentionally skipped\n";
		fclose(stderr);
		if (Dummy)
			fclose(Dummy);
		FreeConsole();
		return 0;
	}

	if (Settings::Generator::GameName.empty() && Settings::Generator::GameVersion.empty())
	{
		// Only Possible in Main()
		FString Name;
		FString Version;
		UEClass Kismet = ObjectArray::FindClassFast("KismetSystemLibrary");
		UEFunction GetGameName = Kismet.GetFunction("KismetSystemLibrary", "GetGameName");
		UEFunction GetEngineVersion = Kismet.GetFunction("KismetSystemLibrary", "GetEngineVersion");

		Kismet.ProcessEvent(GetGameName, &Name);
		Kismet.ProcessEvent(GetEngineVersion, &Version);

		Settings::Generator::GameName = Name.ToString();
		Settings::Generator::GameVersion = Version.ToString();
	}

	std::cerr << "GameName: " << Settings::Generator::GameName << "\n";
	std::cerr << "GameVersion: " << Settings::Generator::GameVersion << "\n\n";

	std::cerr << "FolderName: " << (Settings::Generator::GameVersion + '-' + Settings::Generator::GameName) << "\n\n";

	std::cerr << "Discovery milestone: generating C++ SDK\n";
	Generator::Generate<CppGenerator>();
	std::cerr << "Discovery milestone: generating mappings\n";
	Generator::Generate<MappingGenerator>();
	std::cerr << "Discovery milestone: generating IDA mappings\n";
	Generator::Generate<IDAMappingGenerator>();
	std::cerr << "Discovery milestone: generating Dumpspace\n";
	Generator::Generate<DumpspaceGenerator>();
	Generator::WriteDiscoveryReport();

	auto DumpFinishTime = std::chrono::high_resolution_clock::now();

	std::chrono::duration<double, std::milli> DumpTime = DumpFinishTime - DumpStartTime;

	std::cerr << "\n\nGenerating SDK took (" << DumpTime.count() << "ms)\n\n\n";

	if (Settings::Debug::bExecuteSDKTestScript)
	{
		/* Executes a python script to test if the SDK compiles correctly. */
		CppGenerator::ExecuteSDKCompilationTestScript();
	}

	// Manual-mapped images are not registered with the loader, so attempting
	// FreeLibraryAndExitThread on them is unsafe. Discovery runs once and then
	// lets its worker thread terminate while the mapped image remains resident.
	if (Discovery::Enabled)
	{
		fclose(stderr);
		if (Dummy)
		{
			fclose(Dummy);
		}
		FreeConsole();
		return 0;
	}

	std::cerr << "\n\nPress F6 to unload\n\n\n";

	while (true)
	{
		if (GetAsyncKeyState(VK_F6) & 1)
		{
			fclose(stderr);
			if (Dummy) 
			{
				fclose(Dummy);
			}
			FreeConsole();

			FreeLibraryAndExitThread(Module, 0);
		}

		Sleep(100);
	}

	return 0;
	}
	catch (const std::exception& Exception)
	{
		std::cerr << "Dumper-7 aborted safely: " << Exception.what() << '\n';
		fclose(stderr);
		if (Dummy)
			fclose(Dummy);
		FreeConsole();
		return 1;
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, 0);
		break;
	}

	return TRUE;
}
