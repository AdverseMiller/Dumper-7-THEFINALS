
#include <algorithm>
#include <array>
#include <format>
#include <set>
#include <stdexcept>

#include "Unreal/UnrealTypes.h"
#include "Unreal/NameArray.h"

#include "Encoding/UnicodeNames.h"

#include "Architecture.h"

namespace
{
	struct DiscoveryRegisterAliases
	{
		std::array<bool, 16> FName{};
		std::array<bool, 16> Builder{};
	};

	bool DecodeRegisterMove(const uint8_t* Instruction, const uint8_t* End, uint8_t& Destination, uint8_t& Source, std::size_t& Length)
	{
		if (End - Instruction < 3 || (Instruction[0] & 0xF8) != 0x48 || Instruction[1] != 0x89 || (Instruction[2] & 0xC0) != 0xC0)
			return false;

		const uint8_t Rex = Instruction[0];
		const uint8_t ModRm = Instruction[2];
		Source = static_cast<uint8_t>(((ModRm >> 3) & 0x7) | ((Rex & 0x4) ? 0x8 : 0x0));
		Destination = static_cast<uint8_t>((ModRm & 0x7) | ((Rex & 0x1) ? 0x8 : 0x0));
		Length = 3;
		return true;
	}

	void RecoverDiscoveryArgumentAliases(const uint8_t* Begin, const uint8_t* End, DiscoveryRegisterAliases& Aliases)
	{
		Aliases.FName[1] = true;
		Aliases.Builder[2] = true;

		const uint8_t* Cursor = Begin;
		const uint8_t* AliasEnd = std::min(End, Begin + 0x60);
		while (Cursor < AliasEnd)
		{
			uint8_t Destination = 0;
			uint8_t Source = 0;
			std::size_t Length = 0;
			if (DecodeRegisterMove(Cursor, AliasEnd, Destination, Source, Length))
			{
				if (Aliases.FName[Source])
					Aliases.FName[Destination] = true;
				if (Aliases.Builder[Source])
					Aliases.Builder[Destination] = true;
				Cursor += Length;
				continue;
			}

			Cursor++;
		}
	}

	bool HasDiscoveryBuilderReset(const uint8_t* Begin, const uint8_t* End, const DiscoveryRegisterAliases& Aliases)
	{
		const uint8_t* SearchEnd = std::min(End, Begin + 0x80);
		for (const uint8_t* Cursor = Begin; Cursor + 7 <= SearchEnd; Cursor++)
		{
			const uint8_t LoadRex = Cursor[0];
			const uint8_t LoadModRm = Cursor[2];
			const uint8_t StoreRex = Cursor[3];
			const uint8_t StoreModRm = Cursor[5];
			if ((LoadRex & 0xF8) != 0x48 || Cursor[1] != 0x8B || (LoadModRm & 0xC0) != 0x00)
				continue;
			if ((StoreRex & 0xF8) != 0x48 || Cursor[4] != 0x89 || (StoreModRm & 0xC0) != 0x40 || Cursor[6] != 0x08)
				continue;

			const uint8_t LoadBase = static_cast<uint8_t>((LoadModRm & 0x7) | ((LoadRex & 0x1) ? 0x8 : 0x0));
			const uint8_t LoadDestination = static_cast<uint8_t>(((LoadModRm >> 3) & 0x7) | ((LoadRex & 0x4) ? 0x8 : 0x0));
			const uint8_t StoreBase = static_cast<uint8_t>((StoreModRm & 0x7) | ((StoreRex & 0x1) ? 0x8 : 0x0));
			const uint8_t StoreSource = static_cast<uint8_t>(((StoreModRm >> 3) & 0x7) | ((StoreRex & 0x4) ? 0x8 : 0x0));
			if (LoadBase == StoreBase && LoadDestination == StoreSource && Aliases.Builder[LoadBase])
				return true;
		}

		return false;
	}

	bool DecodeNumberRead(const uint8_t* Instruction, const uint8_t* End, const DiscoveryRegisterAliases& Aliases, uint8_t& Destination, std::size_t& Length)
	{
		if (Instruction >= End)
			return false;

		const uint8_t* Cursor = Instruction;
		uint8_t Rex = 0;
		if ((*Cursor & 0xF0) == 0x40)
		{
			Rex = *Cursor++;
			if (Cursor >= End)
				return false;
		}

		if (End - Cursor < 3 || Cursor[0] != 0x8B || (Cursor[1] & 0xC0) != 0x40 || Cursor[2] != 0x04)
			return false;

		const uint8_t ModRm = Cursor[1];
		const uint8_t Base = static_cast<uint8_t>((ModRm & 0x7) | ((Rex & 0x1) ? 0x8 : 0x0));
		if (!Aliases.FName[Base])
			return false;

		Destination = static_cast<uint8_t>(((ModRm >> 3) & 0x7) | ((Rex & 0x4) ? 0x8 : 0x0));
		Length = static_cast<std::size_t>((Cursor - Instruction) + 3);
		return true;
	}

	bool IsTestOfRegister(const uint8_t* Instruction, const uint8_t* End, const uint8_t Register)
	{
		if (End - Instruction < 2 || Instruction[0] != 0x85 || (Instruction[1] & 0xC0) != 0xC0)
			return false;

		const uint8_t ModRm = Instruction[1];
		return ((ModRm >> 3) & 0x7) == (Register & 0x7) && (ModRm & 0x7) == (Register & 0x7);
	}

	bool HasDecrementOfRegister(const uint8_t* Begin, const uint8_t* End, const uint8_t Register)
	{
		for (const uint8_t* Cursor = Begin; Cursor < End; Cursor++)
		{
			const uint8_t* Opcode = Cursor;
			uint8_t Rex = 0;
			if ((*Opcode & 0xF0) == 0x40)
			{
				Rex = *Opcode++;
				if (Opcode >= End)
					break;
			}

			if (End - Opcode >= 2 && Opcode[0] == 0xFF && (Opcode[1] & 0xF8) == 0xC8)
			{
				const uint8_t Operand = static_cast<uint8_t>((Opcode[1] & 0x7) | ((Rex & 0x1) ? 0x8 : 0x0));
				if (Operand == Register)
					return true;
			}

			if (End - Opcode >= 3 && Opcode[0] == 0x83 && (Opcode[1] & 0xF8) == 0xE8 && Opcode[2] == 0x01)
			{
				const uint8_t Operand = static_cast<uint8_t>((Opcode[1] & 0x7) | ((Rex & 0x1) ? 0x8 : 0x0));
				if (Operand == Register)
					return true;
			}
		}

		return false;
	}

	bool IsDiscoveryAppendStringFunction(const uint8_t* Begin, const uint8_t* End)
	{
		if (End <= Begin || End - Begin < 0x80 || End - Begin > 0x400)
			return false;

		DiscoveryRegisterAliases Aliases;
		RecoverDiscoveryArgumentAliases(Begin, End, Aliases);
		if (!HasDiscoveryBuilderReset(Begin, End, Aliases))
			return false;

		const uint8_t* Underscore = nullptr;
		for (const uint8_t* Cursor = Begin; Cursor + 5 <= End; Cursor++)
		{
			if (Cursor[0] == 0x66 && Cursor[1] == 0xC7 && ((Cursor[2] >> 3) & 0x7) == 0 && Cursor[3] == 0x5F && Cursor[4] == 0x00)
			{
				Underscore = Cursor;
				break;
			}
		}
		if (!Underscore)
			return false;

		for (const uint8_t* Cursor = Begin; Cursor < Underscore; Cursor++)
		{
			uint8_t NumberRegister = 0;
			std::size_t ReadLength = 0;
			if (!DecodeNumberRead(Cursor, Underscore, Aliases, NumberRegister, ReadLength))
				continue;

			const uint8_t* Test = Cursor + ReadLength;
			if (!IsTestOfRegister(Test, Underscore, NumberRegister))
				continue;

			if (HasDecrementOfRegister(Underscore + 5, std::min(End, Underscore + 0x40), NumberRegister))
				return true;
		}

		return false;
	}

	const RUNTIME_FUNCTION* FindRuntimeFunction(const RUNTIME_FUNCTION* Functions, const std::size_t Count, const DWORD Rva)
	{
		std::size_t Left = 0;
		std::size_t Right = Count;
		while (Left < Right)
		{
			const std::size_t Middle = Left + ((Right - Left) / 2);
			if (Functions[Middle].BeginAddress <= Rva)
				Left = Middle + 1;
			else
				Right = Middle;
		}

		if (Left == 0)
			return nullptr;

		const RUNTIME_FUNCTION* Function = &Functions[Left - 1];
		return Rva < Function->EndAddress ? Function : nullptr;
	}

	void* FindDiscoveryAppendString(const char* const ModuleName)
	{
		const std::uintptr_t ModuleBase = Platform::GetModuleBase(ModuleName);
		if (!ModuleBase)
			throw std::runtime_error("Discovery FName::AppendString scan could not locate the main module");

		const auto* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(ModuleBase);
		if (Platform::IsBadReadPtr(DosHeader) || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			throw std::runtime_error("Discovery FName::AppendString scan found an invalid DOS header");

		const auto* NtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(ModuleBase + DosHeader->e_lfanew);
		if (Platform::IsBadReadPtr(NtHeaders) || NtHeaders->Signature != IMAGE_NT_SIGNATURE)
			throw std::runtime_error("Discovery FName::AppendString scan found an invalid NT header");

		const IMAGE_DATA_DIRECTORY& ExceptionDirectory = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (!ExceptionDirectory.VirtualAddress || ExceptionDirectory.Size < sizeof(RUNTIME_FUNCTION))
			throw std::runtime_error("Discovery FName::AppendString scan found no exception directory");

		const auto* RuntimeFunctions = reinterpret_cast<const RUNTIME_FUNCTION*>(ModuleBase + ExceptionDirectory.VirtualAddress);
		const std::size_t RuntimeFunctionCount = ExceptionDirectory.Size / sizeof(RUNTIME_FUNCTION);
		const std::uintptr_t ModuleEnd = ModuleBase + NtHeaders->OptionalHeader.SizeOfImage;
		std::set<DWORD> Matches;

		Platform::IterateMemoryRegionsWithCallback([&](void* Base, const size_t Size) -> bool
		{
			const std::uintptr_t RegionStart = reinterpret_cast<std::uintptr_t>(Base);
			const std::uintptr_t RegionEnd = RegionStart + Size;
			const std::uintptr_t SearchStart = std::max(RegionStart, ModuleBase);
			const std::uintptr_t SearchEnd = std::min(RegionEnd, ModuleEnd);
			if (SearchEnd <= SearchStart || SearchEnd - SearchStart < 5)
				return false;

			for (std::uintptr_t Cursor = SearchStart; Cursor + 5 <= SearchEnd; Cursor++)
			{
				const auto* Bytes = reinterpret_cast<const uint8_t*>(Cursor);
				if (Bytes[0] != 0x66 || Bytes[1] != 0xC7 || ((Bytes[2] >> 3) & 0x7) != 0 || Bytes[3] != 0x5F || Bytes[4] != 0x00)
					continue;

				const DWORD CandidateRva = static_cast<DWORD>(Cursor - ModuleBase);
				const RUNTIME_FUNCTION* RuntimeFunction = FindRuntimeFunction(RuntimeFunctions, RuntimeFunctionCount, CandidateRva);
				if (!RuntimeFunction || Matches.contains(RuntimeFunction->BeginAddress))
					continue;

				const auto* FunctionBegin = reinterpret_cast<const uint8_t*>(ModuleBase + RuntimeFunction->BeginAddress);
				const auto* FunctionEnd = reinterpret_cast<const uint8_t*>(ModuleBase + RuntimeFunction->EndAddress);
				if (!Platform::IsBadReadPtr(FunctionBegin) && !Platform::IsBadReadPtr(FunctionEnd - 1) && IsDiscoveryAppendStringFunction(FunctionBegin, FunctionEnd))
					Matches.insert(RuntimeFunction->BeginAddress);
			}

			return false;
		}, false);

		if (Matches.size() > 1)
			throw std::runtime_error("Discovery FName::AppendString semantic scan matched multiple functions");
		if (Matches.empty())
			throw std::runtime_error("Discovery FName::AppendString semantic scan found no decoded implementation");

		return reinterpret_cast<void*>(ModuleBase + *Matches.begin());
	}
}


std::string MakeNameValid(std::wstring&& Name)
{
	static constexpr const wchar_t* Numbers[10] =
	{
		L"Zero",
		L"One",
		L"Two",
		L"Three",
		L"Four",
		L"Five",
		L"Six",
		L"Seven",
		L"Eight",
		L"Nine"
	};

	if (Name == L"bool")
		return "Bool";

	if (Name == L"NULL")
		return "NULLL";

	/* Replace 0 with Zero or 9 with Nine, if it is the first letter of the name. */
	if (Name[0] <= '9' && Name[0] >= '0')
	{
		Name.replace(0, 1, Numbers[Name[0] - '0']);
	}
	
	std::u32string Strrr;
	Strrr += UtfN::utf_cp32_t{ 200 };

	std::u32string Utf32Name = UtfN::Utf16StringToUtf32String<std::u32string>(Name);

	bool bIsFirstIteration = true;
	for (auto It = UtfN::utf32_iterator<std::u32string::iterator>(Utf32Name); It; ++It)
	{
		if (bIsFirstIteration && !IsUnicodeCharXIDStart(Name[0]))
		{
			/* Replace invalid starting character with 'm' character. 'm' for "member" */
			Name[0] = 'm';

			bIsFirstIteration = false;
		}

		if (!IsUnicodeCharXIDContinue((*It).Get()))
			It.Replace('_');
	}

	return  UtfN::Utf32StringToUtf8String<std::string>(Utf32Name);;
}


FName::FName(const void* Ptr)
	: Address(static_cast<const uint8*>(Ptr))
{
}

FName::FName(uint64 Value)
	: Address(reinterpret_cast<const uint8*>(&InlineValue)), InlineValue(Value), bOwnsInlineValue(true)
{
}

FName::FName(const FName& Other)
	: Address(Other.Address), InlineValue(Other.InlineValue), bOwnsInlineValue(Other.bOwnsInlineValue)
{
	if (bOwnsInlineValue)
		Address = reinterpret_cast<const uint8*>(&InlineValue);
}

FName& FName::operator=(const FName& Other)
{
	if (this == &Other)
		return *this;

	InlineValue = Other.InlineValue;
	bOwnsInlineValue = Other.bOwnsInlineValue;
	Address = bOwnsInlineValue ? reinterpret_cast<const uint8*>(&InlineValue) : Other.Address;
	return *this;
}

void FName::Init_Windows(bool bForceGNames)
{
#ifdef PLATFORM_WINDOWS

#if defined(_WIN64)
	constexpr std::array<const char*, 6> PossibleSigs = 
	{ 
		"48 8D ? ? 48 8D ? ? E8",
		"48 8D ? ? ? 48 8D ? ? E8",
		"48 8D ? ? 49 8B ? E8",
		"48 8D ? ? ? 49 8B ? E8",
		"48 8D ? ? 48 8B ? E8",
		"48 8D ? ? ? 48 8B ? E8",
	};
#elif defined(_WIN32)
	constexpr std::array<const char*, 1> PossibleSigs = 
	{
		"8D 44 24 ? 8D 4C 24 ? 50 E8",
	};
#endif

	const void* StringRef = Platform::FindByStringInAllSections("ForwardShadingQuality_", 0x0, 0x0, Settings::General::bSearchOnlyExecutableSectionsForStrings);
	
	bool bFoundPotentiallyOverlappingSig = false;

	if (StringRef)
	{
		const char* MatchingSig = nullptr;

		for (int i = 0; !AppendString && i < PossibleSigs.size(); i++)
		{
			AppendString = reinterpret_cast<decltype(AppendString)>(Platform::FindPatternInRange(PossibleSigs[i], StringRef, 0x50, true, -1/* auto */));

			if (AppendString)
				MatchingSig = PossibleSigs[i];
		}

		// This signature partially overlaps with the signature for an inlined FName::AppendString call (see comment below)
		bFoundPotentiallyOverlappingSig = MatchingSig && strcmp(MatchingSig, "48 8D ? ? ? 48 8B ? E8") == 0;
	}

	// Test if AppendString was inlined
	if ((!AppendString || bFoundPotentiallyOverlappingSig) && !bForceGNames && StringRef)
	{
		/*
		* 0x00: 8B ? ?          mov     ecx, [...]
		* 0x03: E8 ? ? ? ?      call    FName::GetComparisonNameEntry
		* 0x08: 48 8D ? ?       lea     rdx, [...]
		* 0x0B: 48 8B C8        mov     rcx, rax
		* 0x10: E8 ? ? ? ?      call    FNameEntry::GetName
		*/
		if (void* SigScanResult = Platform::FindPatternInRange("8B ? ? E8 ? ? ? ? 48 8D ? ? ? 48 8B C8 E8 ? ? ? ?", StringRef, 0x180))
		{
			const uintptr_t ResultAsInt = reinterpret_cast<const uintptr_t>(SigScanResult);

			GetNameEntryFromName = reinterpret_cast<decltype(GetNameEntryFromName)>(Architecture_x86_64::Resolve32BitRelativeCall(ResultAsInt + 0x3));
			AppendString = reinterpret_cast<decltype(AppendString)>(Architecture_x86_64::Resolve32BitRelativeCall(ResultAsInt + 0x10));

			Off::InSDK::Name::GetNameEntryFromName = Platform::GetOffset(GetNameEntryFromName);
			Off::InSDK::Name::bIsAppendStringInlinedAndUsed = true;

			ToStr = [](const void* Name) -> std::wstring
			{
				thread_local FFreableString TempString(1024);

				AppendString(GetNameEntryFromName(FName(Name).GetCompIdx()), TempString);

				std::wstring OutputString = TempString.ToWString();
				TempString.ResetNum();

				const uint32 Number = FName(Name).GetNumber();

				if (Number > 0)
					return OutputString + L'_' + std::to_wstring(Number - 1);

				return OutputString;
			};
		}
	}

	if (AppendString == nullptr)
		AppendString = reinterpret_cast<decltype(AppendString)>(TryFindApendStringBackupStringRef_Windows());

	Off::InSDK::Name::AppendNameToString = AppendString && !bForceGNames ? Platform::GetOffset(AppendString) : 0x0;

	if (!AppendString || bForceGNames)
	{
		const bool bInitializedSuccessfully = NameArray::TryInit();

		if (bInitializedSuccessfully)
		{
			ToStr = [](const void* Name) -> std::wstring
			{
				if (!Settings::Internal::bUseOutlineNumberName)
				{
					const uint32 Number = FName(Name).GetNumber();

					if (Number > 0)
						return NameArray::GetNameEntry(Name).GetWString() + L'_' + std::to_wstring(Number - 1);
				}

				return NameArray::GetNameEntry(Name).GetWString();
			};

			return;
		}
		else /* Attempt to find FName::ToString as a final fallback */
		{
			/* Initialize GNames offset without committing to use GNames during the dumping process or in the SDK */
			NameArray::SetGNamesWithoutCommitting();
			FName::InitFallback();
		}
	}

	std::cerr << std::format("Found FName::{} at Offset 0x{:X}\n\n", (Off::InSDK::Name::bIsUsingAppendStringOverToString ? "AppendString" : "ToString"), Off::InSDK::Name::AppendNameToString);

	/* Initialize GNames offset without committing to use GNames during the dumping process or in the SDK */
	NameArray::SetGNamesWithoutCommitting();

	if (ToStr)
		return;

	ToStr = [](const void* Name) -> std::wstring
	{
		thread_local FFreableString TempString(1024);

		AppendString(Name, TempString);

		std::wstring OutputString = TempString.ToWString();
		TempString.ResetNum();

		return OutputString;
	};

#endif // PLATFORM_WINDOWS
}

void FName::Init(int32 OverrideOffset, EOffsetOverrideType OverrideType, bool bIsNamePool, const char* const ModuleName)
{
	if (OverrideType == EOffsetOverrideType::GNames)
	{
		const bool bInitializedSuccessfully = NameArray::TryInit(OverrideOffset, bIsNamePool, ModuleName);

		if (bInitializedSuccessfully)
		{
			ToStr = [](const void* Name) -> std::wstring
			{
				if (!Settings::Internal::bUseOutlineNumberName)
				{
					const uint32 Number = FName(Name).GetNumber();

					if (Number > 0)
						return NameArray::GetNameEntry(Name).GetWString() + L'_' + std::to_wstring(Number - 1);
				}

				return NameArray::GetNameEntry(Name).GetWString();
			};
		}

		return;
	}

	AppendString = reinterpret_cast<decltype(AppendString)>(Platform::GetModuleBase(ModuleName) + OverrideOffset);

	Off::InSDK::Name::AppendNameToString = OverrideOffset;
	Off::InSDK::Name::bIsUsingAppendStringOverToString = OverrideType == EOffsetOverrideType::AppendString;

	ToStr = [](const void* Name) -> std::wstring
	{
		thread_local FFreableString TempString(1024);

		AppendString(Name, TempString);

		std::wstring OutputString = TempString.ToWString();
		TempString.ResetNum();

		return OutputString;
	};

	std::cerr << std::format("Manual-Override: FName::{} --> Offset 0x{:X}\n\n", (Off::InSDK::Name::bIsUsingAppendStringOverToString ? "AppendString" : "ToString"), Off::InSDK::Name::AppendNameToString);
}

void FName::InitDiscovery(const char* const ModuleName)
{
	struct WideStringBuilder
	{
		wchar_t* Begin;
		wchar_t* Current;
		wchar_t* End;
	};

	using DiscoveryAppendString = void(*)(const void*, WideStringBuilder&);
	static DiscoveryAppendString Function = nullptr;
	Function = reinterpret_cast<DiscoveryAppendString>(FindDiscoveryAppendString(ModuleName));
	const int32 OverrideOffset = static_cast<int32>(Platform::GetOffset(Function, ModuleName));

	Off::InSDK::Name::AppendNameToString = OverrideOffset;
	Off::InSDK::Name::bIsUsingAppendStringOverToString = true;
	Off::InSDK::Name::bIsAppendStringInlinedAndUsed = false;

	ToStr = [](const void* Name) -> std::wstring
	{
		thread_local wchar_t Buffer[1024];
		WideStringBuilder Builder{ Buffer, Buffer, Buffer + (sizeof(Buffer) / sizeof(Buffer[0])) };
		Function(Name, Builder);
		return std::wstring(Builder.Begin, Builder.Current);
	};

	std::cerr << std::format("Discovery FName::AppendString located dynamically at RVA 0x{:X}\n\n", OverrideOffset);
}


void* FName::TryFindApendStringBackupStringRef_Windows()
{

#ifdef PLATFORM_WINDOWS

#if defined(_WIN64)
	constexpr std::array<const char*, 3> PossibleSigs =
	{
		"48 8B ? 48 8B ? ? E8",
		"48 8B ? ? 48 89 ? ? E8",
		"48 8B ? 48 89 ? ? ? E8"
	};
#elif defined(_WIN32)
	constexpr std::array<const char*, 0> PossibleSigs =
	{
		// Todo I guess.
	};
#endif

	const void* StringRef = Platform::FindByStringInAllSections(L" Bone: ", 0x0, 0x0, Settings::General::bSearchOnlyExecutableSectionsForStrings);

	if (StringRef)
	{
		const char* MatchingSig = nullptr;

		// AppendString comes before the string ref, so search upwards (in IDA terms)
		const uintptr_t SigSearchStartAddress = reinterpret_cast<uintptr_t>(StringRef) - 0xB0;

		for (int i = 0; !AppendString && i < PossibleSigs.size(); i++)
		{
			AppendString = reinterpret_cast<decltype(AppendString)>(Platform::FindPatternInRange(PossibleSigs[i], SigSearchStartAddress, 0x100, true, -1/* auto */));

			if (AppendString)
				return reinterpret_cast<void*>(AppendString);
		}
	}
#endif // PLATFORM_WINDOWS

	return nullptr;
}

void FName::InitFallback()
{
	Off::InSDK::Name::bIsUsingAppendStringOverToString = false;

	void* Conv_NameToStringAddress = FindUnrealExecFunctionByString("Conv_NameToString");

	constexpr std::array<const char*, 3> PossibleSigs =
	{
		"89 44 ? ? 48 01 ? ? E8",
		"48 89 ? ? 48 8D ? ? ? E8",
		"48 89 ? ? ? 48 89 ? ? E8",
	};

	int i = 0;
	while (!AppendString && i < PossibleSigs.size())
	{
		AppendString = reinterpret_cast<decltype(AppendString)>(Platform::FindPatternInRange(PossibleSigs[i], Conv_NameToStringAddress, 0x90, -1 /* auto */));

		i++;
	}

	Off::InSDK::Name::AppendNameToString = AppendString ? Platform::GetOffset(AppendString) : 0x0;
}


std::wstring FName::ToRawWString() const
{
	if (!Address)
		return L"None";

	return ToStr(Address);
}

std::wstring FName::ToWString() const
{
	std::wstring OutputString = ToRawWString();

	size_t pos = OutputString.rfind('/');

	if (pos == std::wstring::npos)
		return OutputString;

	return OutputString.substr(pos + 1);
}

std::string FName::ToRawString() const
{
	if (!Address)
		return "None";

	return UtfN::WStringToString(ToRawWString());
}

std::string FName::ToString() const
{
	if (!Address)
		return "None";

	return UtfN::WStringToString(ToWString());
}

std::string FName::ToValidString() const
{
	return MakeNameValid(ToWString());
}

int32 FName::GetCompIdx() const 
{
	return *reinterpret_cast<const int32*>(Address + Off::FName::CompIdx);
}

uint32 FName::GetNumber() const
{
	if (Settings::Internal::bUseOutlineNumberName)
		return 0x0;

	if (Settings::Internal::bUseNamePool)
		return *reinterpret_cast<const uint32*>(Address + Off::FName::Number); // The number is uint32 on versions <= UE4.23 

	return static_cast<uint32_t>(*reinterpret_cast<const int32*>(Address + Off::FName::Number));
}

bool FName::operator==(FName Other) const
{
	return GetCompIdx() == Other.GetCompIdx();
}

bool FName::operator!=(FName Other) const
{
	return GetCompIdx() != Other.GetCompIdx();
}

std::string FName::CompIdxToString(int CmpIdx)
{
	if (!Settings::Internal::bUseCasePreservingName)
	{
		struct FakeFName
		{
			int CompIdx;
			uint8 Pad[0x4];
		} Name(CmpIdx);

		return FName(&Name).ToString();
	}
	else
	{
		struct FakeFName
		{
			int CompIdx;
			uint8 Pad[0xC];
		} Name(CmpIdx);

		return FName(&Name).ToString();
	}
}

void* FName::DEBUGGetAppendString()
{
	return (void*)(AppendString);
}
