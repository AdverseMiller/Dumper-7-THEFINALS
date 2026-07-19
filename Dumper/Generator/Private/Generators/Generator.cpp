
#include "Generators/Generator.h"
#include "Managers/StructManager.h"
#include "Managers/EnumManager.h"
#include "Managers/MemberManager.h"
#include "Managers/PackageManager.h"

#include "HashStringTable.h"
#include "Utils.h"

#include "Platform.h"
#include "Json/json.hpp"
#include "Unreal/Discovery.h"

#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

inline void InitSettings()
{
	Settings::InitWeakObjectPtrSettings();
	Settings::InitLargeWorldCoordinateSettings();

	Settings::InitObjectPtrPropertySettings();
	Settings::InitArrayDimSizeSettings();
}


void Generator::InitEngineCore()
{
	/* manual override */
	//ObjectArray::Init(/*GObjects*/, /*Layout = Default*/); // FFixedUObjectArray (UEVersion < UE4.21)
	//ObjectArray::Init(/*GObjects*/, /*ChunkSize*/, /*Layout = Default*/); // FChunkedFixedUObjectArray (UEVersion >= UE4.21)

	//FName::Init(/*bForceGNames = false*/);
	//FName::Init(/*AppendString, FName::EOffsetOverrideType::AppendString*/);
	//FName::Init(/*ToString, FName::EOffsetOverrideType::ToString*/);
	//FName::Init(/*GNames, FName::EOffsetOverrideType::GNames, true/false*/);
 
	//Off::InSDK::ProcessEvent::InitPE(/*PEIndex*/);

	/* Back4Blood (requires manual GNames override) */
	//InitObjectArrayDecryption([](void* ObjPtr) -> uint8* { return reinterpret_cast<uint8*>(uint64(ObjPtr) ^ 0x8375); });

	/* Multiversus [Unsupported, weird GObjects-struct] */
	//InitObjectArrayDecryption([](void* ObjPtr) -> uint8* { return reinterpret_cast<uint8*>(uint64(ObjPtr) ^ 0x1B5DEAFD6B4068C); });

	if (Discovery::Enabled)
	{
		ObjectArray::InitDiscovery();
		FName::InitDiscovery();
	}
	else
	{
		ObjectArray::Init();
		CALL_PLATFORM_SPECIFIC_FUNCTION(FName::Init);
	}

	if (Discovery::Enabled)
		CALL_PLATFORM_SPECIFIC_FUNCTION(Off::InSDK::ProcessEvent::InitDiscoveryPE);

	Off::Init();
	if (Discovery::Enabled)
	{
		const UEFunction ConvStringToText = ObjectArray::FindObjectFast<UEFunction>("Conv_StringToText", EClassCastFlags::Function);
		UEProperty ReturnProperty = nullptr;
		if (ConvStringToText)
		{
			for (UEProperty Property : ConvStringToText.GetProperties())
			{
				if (Property.HasPropertyFlags(EPropertyFlags::ReturnParm))
				{
					ReturnProperty = Property;
					break;
				}
			}
		}
		if (!ReturnProperty || ReturnProperty.GetSize() < static_cast<int32>(sizeof(void*)) || ReturnProperty.GetSize() > 0x40)
			throw std::runtime_error("Discovery could not derive a plausible FText size from Conv_StringToText");
		Off::InSDK::Text::TextSize = ReturnProperty.GetSize();
		std::cerr << std::format("Discovery FText size recovered from reflection: 0x{:X}\n", Off::InSDK::Text::TextSize);
	}
	PropertySizes::Init();

	if (!Discovery::Enabled)
		CALL_PLATFORM_SPECIFIC_FUNCTION(Off::InSDK::ProcessEvent::InitPE); // Must be at this position, relies on offsets initialized in Off::Init()

	if (Discovery::Enabled)
	{
		// Both stock probes walk/call live engine state and are unnecessary for
		// reflection generation. Keep the Discovery dump path read-only.
		std::cerr << "Discovery: skipping active GWorld and FText probes\n\n";
	}
	else
	{
		Off::InSDK::World::InitGWorld(); // Must be at this position, relies on offsets initialized in Off::Init()
		Off::InSDK::Text::InitTextOffsets(); // Must be at this position, relies on offsets initialized in Off::InitPE()
	}

	InitSettings();
}

void Generator::InitInternal()
{
	// Initialize PackageManager with all packages, their names, structs, classes enums, functions and dependencies
	PackageManager::Init();

	// Initialize StructManager with all structs and their names
	StructManager::Init();
	
	// Initialize EnumManager with all enums and their names
	EnumManager::Init();
	
	// Initialized all Member-Name collisions
	MemberManager::Init();

	// Post-Initialize PackageManager after StructManager has been initialized. 'PostInit()' handles Cyclic-Dependencies detection
	PackageManager::PostInit();
}

void Generator::WriteDiscoveryReport()
{
	if (!Discovery::Enabled || DumperFolder.empty())
		return;

	auto Hex = [](const auto Value)
	{
		return std::format("0x{:X}", Value);
	};
	auto BytesToHex = [](const auto& Bytes)
	{
		std::ostringstream Stream;
		Stream << std::hex << std::setfill('0');
		for (const std::uint8_t Byte : Bytes)
			Stream << std::setw(2) << static_cast<unsigned>(Byte);
		return Stream.str();
	};

	nlohmann::json Report;
	Report["schema_version"] = 2;
	Report["game"]["name"] = Settings::Generator::GameName;
	Report["game"]["version"] = Settings::Generator::GameVersion;
	Report["validation"]["mode"] = "read-only, fail-closed";
	Report["validation"]["fixed_rvas_used"] = false;
	Report["validation"]["process_suspended"] = false;
	Report["generated_sdk"]["uobject_identity_access"] = "protector-aware GetClass/GetOuter/GetFName accessors";
	Report["generated_sdk"]["ffield_name_storage"] = "opaque protected bytes";
	Report["generated_sdk"]["fproperty_protected_storage"] = "encoded members explicitly labeled";
	Report["generated_sdk"]["ffield_class_flags"] = "omitted because decoder is not validated";

	Report["object_array"]["strategy"] = "structural first-chunk reverse reference";
	Report["object_array"]["global_cipher_used"] = false;
	Report["object_array"]["stable_global_rva_available"] = false;
	Report["object_array"]["chunk_table_runtime_address"] = Hex(Discovery::ChunkTableAddress);
	Report["object_array"]["chunk_count"] = Discovery::ChunkCount;
	Report["object_array"]["count_source"] = "highest structurally validated live InternalIndex plus one";
	Report["object_array"]["object_count_at_bootstrap"] = Discovery::ObjectCount;
	Report["object_array"]["elements_per_chunk"] = Discovery::ElementsPerChunk;
	Report["object_array"]["fuobjectitem_size"] = Hex(Off::InSDK::ObjArray::FUObjectItemSize);
	Report["object_array"]["internal_index_offset"] = Hex(ObjectArray::GetInternalIndexOffset());

	Report["fname"]["append_string_rva"] = Hex(Off::InSDK::Name::AppendNameToString);
	Report["ftext"]["size"] = Hex(Off::InSDK::Text::TextSize);
	Report["ftext"]["layout_status"] = "size recovered from reflected return property; internal data pointer layout not actively probed";
	Report["process_event"]["vtable_index"] = Hex(Off::InSDK::ProcessEvent::PEIndex);
	Report["process_event"]["wrapper_rva"] = Hex(Off::InSDK::ProcessEvent::PEOffset);
	Report["process_event"]["dispatcher_rva"] = Hex(Discovery::ProcessEventDispatcherRva);
	Report["process_event"]["function_flags_offset"] = Hex(Off::UFunction::FunctionFlags);
	Report["process_event"]["function_flags_xor"] = Hex(Discovery::FunctionFlagsXorKey);

	Report["uobject"]["flags_offset"] = Hex(Off::UObject::Flags);
	Report["uobject"]["index_offset"] = Hex(Off::UObject::Index);
	Report["uobject"]["protected_address_offset"] = Hex(Discovery::ProtectedAddressOffset);
	Report["uobject"]["protected_data_offset"] = Hex(Discovery::ProtectedSlotDataOffset);
	Report["uobject"]["protected_slot_stride"] = Hex(Discovery::ProtectedSlotStride);
	Report["uobject"]["protected_slot_rotate_left"] = Discovery::ProtectedSlotRotate;
	Report["uobject"]["protected_mask_hex"] = BytesToHex(Discovery::ProtectedSlotMask);
	Report["uobject"]["protected_shuffle_hex"] = BytesToHex(Discovery::ProtectedSlotShuffle);
	Report["uobject"]["class_slots"] = Discovery::ProtectedClassSlots;
	Report["uobject"]["outer_slots"] = Discovery::ProtectedOuterSlots;
	Report["uobject"]["name_slots"] = Discovery::ProtectedNameSlots;
	Report["uobject"]["hash"]["high_shift"] = Discovery::ProtectedHashHighShift;
	Report["uobject"]["hash"]["rotate_1"] = Discovery::ProtectedHashRotate1;
	Report["uobject"]["hash"]["rotate_2"] = Discovery::ProtectedHashRotate2;
	Report["uobject"]["hash"]["rotate_3"] = Discovery::ProtectedHashRotate3;
	Report["uobject"]["hash"]["final_shift"] = Discovery::ProtectedHashFinalShift;
	Report["uobject"]["hash"]["fold_shift"] = Discovery::ProtectedHashFoldShift;
	Report["uobject"]["hash"]["multiplier"] = Hex(Discovery::ProtectedHashMultiplier);
	Report["uobject"]["hash"]["addend"] = Hex(Discovery::ProtectedHashAddend);
	Report["uobject"]["hash"]["slot_mask"] = Hex(Discovery::ProtectedHashSlotMask);

	Report["ffield"]["name_offset"] = Hex(Off::FField::Name);
	Report["ffield"]["next_offset"] = Hex(Off::FField::Next);
	Report["ffield"]["class_offset"] = Hex(Off::FField::Class);
	Report["ffield"]["owner_offset"] = Hex(Off::FField::Owner);
	Report["ffield"]["name_word_rotate_left"] = Discovery::FieldNameWordRotate;
	Report["ffield"]["name_result_rotate_left"] = Discovery::FieldNameResultRotate;
	Report["ffield"]["name_xor"] = Hex(Discovery::FieldNameXorKey);
	Report["ffield"]["name_shuffle_hex"] = BytesToHex(Discovery::FieldNameShuffle);
	Report["ffield_class"]["super_offset"] = Hex(Off::FFieldClass::SuperClass);
	Report["ffield_class"]["cast_flags_offset"] = Hex(Off::FFieldClass::CastFlags);
	Report["ffield_class"]["id_offset"] = Hex(Off::FFieldClass::Id);
	Report["ffield_class"]["class_flags_status"] = "not consumed; protected member intentionally omitted from generated SDK";

	Report["fproperty"]["flags_offset"] = Hex(Off::Property::PropertyFlags);
	Report["fproperty"]["flags_xor"] = Hex(Discovery::PropertyFlagsXorKey);
	Report["fproperty"]["array_dim_offset"] = Hex(Off::Property::ArrayDim);
	Report["fproperty"]["element_size_offset"] = Hex(Off::Property::ElementSize);
	Report["fproperty"]["value_offset_offset"] = Hex(Off::Property::Offset_Internal);
	Report["fproperty"]["value_offset_xor"] = Hex(Discovery::PropertyOffsetXorKey);

	std::ofstream ReportFile(DumperFolder / "discovery-report.json");
	ReportFile << Report.dump(4);
}

bool Generator::SetupDumperFolder()
{
	try
	{
		std::string FolderName = (Settings::Generator::GameVersion + '-' + Settings::Generator::GameName);

		FileNameHelper::MakeValidFileName(FolderName);

		DumperFolder = fs::path(Settings::Generator::SDKGenerationPath) / FolderName;

		if (fs::exists(DumperFolder))
		{
			fs::path Old = DumperFolder.generic_string() + "_OLD";

			fs::remove_all(Old);

			fs::rename(DumperFolder, Old);
		}

		fs::create_directories(DumperFolder);
	}
	catch (const std::filesystem::filesystem_error& fe)
	{
		std::cerr << "Could not create required folders! Info: \n";
		std::cerr << fe.what() << std::endl;
		return false;
	}

	return true;
}

bool Generator::SetupFolders(std::string& FolderName, fs::path& OutFolder)
{
	fs::path Dummy;
	std::string EmptyName = "";
	return SetupFolders(FolderName, OutFolder, EmptyName, Dummy);
}

bool Generator::SetupFolders(std::string& FolderName, fs::path& OutFolder, std::string& SubfolderName, fs::path& OutSubFolder)
{
	FileNameHelper::MakeValidFileName(FolderName);
	FileNameHelper::MakeValidFileName(SubfolderName);

	try
	{
		OutFolder = DumperFolder / FolderName;
		OutSubFolder = OutFolder / SubfolderName;
				
		if (fs::exists(OutFolder))
		{
			fs::path Old = OutFolder.generic_string() + "_OLD";

			fs::remove_all(Old);

			fs::rename(OutFolder, Old);
		}

		fs::create_directories(OutFolder);

		if (!SubfolderName.empty())
			fs::create_directories(OutSubFolder);
	}
	catch (const std::filesystem::filesystem_error& fe)
	{
		std::cerr << "Could not create required folders! Info: \n";
		std::cerr << fe.what() << std::endl;
		return false;
	}

	return true;
}


void DumpEditorOnlyMetadata(const fs::path& DumperFolder)
{
	if (Off::FField::EditorOnlyMetadata == -1)
		return;

	nlohmann::json MetadataJson;
	MetadataJson["GameName"] = Settings::Generator::GameName;
	MetadataJson["GameVersion"] = Settings::Generator::GameVersion;

	for (UEObject Obj : ObjectArray())
	{
		if (!Obj.IsA(EClassCastFlags::Struct))
			continue;

		UEStruct Struct = Obj.Cast<UEStruct>();

		auto ChildProperties = Struct.GetProperties();

		if (ChildProperties.empty())
			continue;

		auto& StructMembers = MetadataJson[Struct.GetCppName()];

		for (UEProperty Prop : Struct.GetProperties())
		{
			auto& Entries = StructMembers[Prop.GetValidName()];

			for (const auto& [Key, Value] : Prop.Cast<UEFField>().GetMetaData())
			{
				if (Key.empty() && Value.empty())
					continue;

				Entries[Key] = Value;
			}
		}
	}

	std::ofstream MetadataFile(DumperFolder / "Metadata.json");
	MetadataFile << MetadataJson.dump(4);
}
