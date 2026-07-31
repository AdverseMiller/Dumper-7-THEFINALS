#include <algorithm>
#include <array>
#include <cstring>
#include <set>
#include <tuple>
#include <vector>
#include <random>
#include <format>

#include "OffsetFinder/OffsetFinder.h"
#include "Unreal/ObjectArray.h"
#include "Unreal/Discovery.h"

#include "Platform.h"

namespace
{
	std::vector<int32_t> DiscoveryChildPropertiesCandidates;

	bool IsDiscoveryPropertyFieldPointer(const void* const Address)
	{
		if (!Address || (reinterpret_cast<std::uintptr_t>(Address) & (alignof(void*) - 1)))
			return false;

		const auto* Field = static_cast<const std::uint8_t*>(Address);
		if (Platform::IsBadReadPtr(Field + Off::FField::Class + sizeof(void*) - 1))
			return false;

		const auto* FieldClass = *reinterpret_cast<const std::uint8_t* const*>(Field + Off::FField::Class);
		if (!FieldClass || Platform::IsBadReadPtr(FieldClass + Off::FFieldClass::CastFlags + sizeof(std::uint64_t) - 1))
			return false;

		const auto CastFlags = *reinterpret_cast<const std::uint64_t*>(FieldClass + Off::FFieldClass::CastFlags);
		return (CastFlags & static_cast<std::uint64_t>(EClassCastFlags::Property)) != 0;
	}

	bool IsDiscoveryObjectPointer(const void* const Address, const EClassCastFlags Type)
	{
		if (!Address || (reinterpret_cast<std::uintptr_t>(Address) & (alignof(void*) - 1)))
			return false;

		const auto* Object = static_cast<const std::uint8_t*>(Address);
		const int32_t IndexOffset = static_cast<int32_t>(ObjectArray::GetInternalIndexOffset());
		if (Platform::IsBadReadPtr(Object + IndexOffset + sizeof(int32_t) - 1))
			return false;

		const int32_t Index = *reinterpret_cast<const int32_t*>(Object + IndexOffset);
		if (Index < 0 || Index >= ObjectArray::Num())
			return false;

		const UEObject IndexedObject = ObjectArray::GetByIndex(Index);
		return IndexedObject.GetAddress() == Address && IndexedObject.IsA(Type);
	}

	int32_t FindDiscoveryDerivedPropertyPointers(const EClassCastFlags Type, const int32_t PointerCount, const int32_t PropertySize, const char* const Name)
	{
		std::vector<const std::uint8_t*> Properties;
		for (const UEProperty Property : AllFieldIterator())
		{
			if (!Property || !Property.IsA(Type))
				continue;
			Properties.push_back(static_cast<const std::uint8_t*>(Property.GetAddress()));
			if (Properties.size() == 128)
				break;
		}

		if (Properties.size() < 8)
		{
			std::cerr << std::format("Discovery {} structural scan found only {} samples\n", Name, Properties.size());
			return OffsetFinder::OffsetNotFound;
		}

		std::vector<int32_t> Candidates;
		for (int32_t Offset = PropertySize; Offset <= PropertySize + 0x40; Offset += sizeof(void*))
		{
			bool MatchesAll = true;
			for (const std::uint8_t* Property : Properties)
			{
				for (int32_t PointerIndex = 0; PointerIndex < PointerCount; ++PointerIndex)
				{
					const auto* PointerAddress = Property + Offset + PointerIndex * sizeof(void*);
					if (Platform::IsBadReadPtr(PointerAddress + sizeof(void*) - 1))
					{
						MatchesAll = false;
						break;
					}
					const void* const Value = *reinterpret_cast<void* const*>(PointerAddress);
					if (!IsDiscoveryPropertyFieldPointer(Value))
					{
						MatchesAll = false;
						break;
					}
				}
				if (!MatchesAll)
					break;
			}
			if (MatchesAll)
				Candidates.push_back(Offset);
		}

		std::cerr << std::format("Discovery {} structural scan found {} candidate offsets from {} samples", Name, Candidates.size(), Properties.size());
		for (const int32_t Candidate : Candidates)
			std::cerr << std::format(" +0x{:X}", Candidate);
		std::cerr << '\n';
		return Candidates.size() == 1 ? Candidates[0] : OffsetFinder::OffsetNotFound;
	}

	int32_t FindDiscoveryObjectPropertyPointer(const EClassCastFlags PropertyType, const EClassCastFlags ObjectType, const int32_t PropertySize, const char* const Name)
	{
		std::vector<const std::uint8_t*> Properties;
		for (const UEProperty Property : AllFieldIterator())
		{
			if (!Property || !Property.IsA(PropertyType))
				continue;
			Properties.push_back(static_cast<const std::uint8_t*>(Property.GetAddress()));
			if (Properties.size() == 512)
				break;
		}
		if (Properties.size() < 8)
		{
			std::cerr << std::format("Discovery {} scan found only {} samples\n", Name, Properties.size());
			return OffsetFinder::OffsetNotFound;
		}

		struct Candidate
		{
			int32_t Offset = 0;
			int Matches = 0;
		};
		std::vector<Candidate> Candidates;
		for (int32_t Offset = PropertySize; Offset <= PropertySize + 0x40; Offset += sizeof(void*))
		{
			Candidate Current{ Offset };
			for (const std::uint8_t* Property : Properties)
			{
				const auto* PointerAddress = Property + Offset;
				if (Platform::IsBadReadPtr(PointerAddress + sizeof(void*) - 1))
					continue;
				if (IsDiscoveryObjectPointer(*reinterpret_cast<void* const*>(PointerAddress), ObjectType))
					++Current.Matches;
			}
			if (Current.Matches >= 8)
				Candidates.push_back(Current);
		}

		const int RequiredMatches = static_cast<int>((Properties.size() * 95 + 99) / 100);
		std::erase_if(Candidates, [&](const Candidate& Candidate)
		{
			return Candidate.Matches < RequiredMatches;
		});
		std::cerr << std::format("Discovery {} scan found {} candidate offsets from {} samples", Name, Candidates.size(), Properties.size());
		for (const Candidate& Candidate : Candidates)
			std::cerr << std::format(" +0x{:X}[{}]", Candidate.Offset, Candidate.Matches);
		std::cerr << '\n';
		return Candidates.size() == 1 ? Candidates[0].Offset : OffsetFinder::OffsetNotFound;
	}
}

/* UObject */
int32_t OffsetFinder::FindUObjectFlagsOffset()
{
	constexpr auto EnumFlagValueToSearch = 0x43;

	/* We're looking for a commonly occuring flag and this number basically defines the minimum number that counts ad "commonly occuring". */
	constexpr auto MinNumFlagValuesRequiredAtOffset = 0xA0;

	for (int i = 0; i < 0x20; i++)
	{
		int Offset = 0x0;
		while (Offset != OffsetNotFound)
		{
			// Look for 0x43 in this object, as it is a really common value for UObject::Flags
			Offset = FindOffset(std::vector{ std::pair{ ObjectArray::GetByIndex(i).GetAddress(), EnumFlagValueToSearch } }, Offset, 0x40);

			if (Offset == OffsetNotFound)
				break; // Early exit

			/* We're looking for a common flag. To check if the flag  is common we're checking the first 0x100 objects to see how often the flag occures at this offset. */
			int32 NumObjectsWithFlagAtOffset = 0x0;

			int Counter = 0;
			for (UEObject Obj : ObjectArray())
			{
				// Only check the (possible) flags of the first 0x100 objects
				if (Counter++ == 0x100)
					break;

				const int32 TypedValueAtOffset = *reinterpret_cast<int32*>(reinterpret_cast<uintptr_t>(Obj.GetAddress()) + Offset);

				if (TypedValueAtOffset == EnumFlagValueToSearch)
					NumObjectsWithFlagAtOffset++;
			}

			if (NumObjectsWithFlagAtOffset > MinNumFlagValuesRequiredAtOffset)
				return Offset;
		}
	}

	return OffsetNotFound;
}

int32_t OffsetFinder::FindUObjectIndexOffset()
{
	std::vector<std::pair<void*, int32_t>> Infos;

	Infos.emplace_back(ObjectArray::GetByIndex(0x055).GetAddress(), 0x055);
	Infos.emplace_back(ObjectArray::GetByIndex(0x123).GetAddress(), 0x123);

	return FindOffset<4>(Infos, sizeof(void*)); // Skip VTable
}

int32_t OffsetFinder::FindUObjectClassOffset()
{
	/* Checks for a pointer that points to itself in the end. The UObject::Class pointer of "Class CoreUObject.Class" will point to "Class CoreUObject.Class". */
	auto IsValidCyclicUClassPtrOffset = [](const uint8_t* ObjA, const uint8_t* ObjB, int32_t ClassPtrOffset)
	{
		/* Will be advanced before they are used. */
		const uint8_t* NextClassA = ObjA;
		const uint8_t* NextClassB = ObjB;

		for (int MaxLoopCount = 0; MaxLoopCount < 0x10; MaxLoopCount++)
		{
			const uint8_t* CurrentClassA = NextClassA;
			const uint8_t* CurrentClassB = NextClassB;

			NextClassA = *reinterpret_cast<const uint8_t* const*>(NextClassA + ClassPtrOffset);
			NextClassB = *reinterpret_cast<const uint8_t* const*>(NextClassB + ClassPtrOffset);

			/* If this was UObject::Class it would never be invalid. The pointer would simply point to itself.*/
			if (!NextClassA || !NextClassB || Platform::IsBadReadPtr(NextClassA) || Platform::IsBadReadPtr(NextClassB))
				return false;

			if (CurrentClassA == NextClassA && CurrentClassB == NextClassB)
				return true;
		}

		return false;
	};

	const uint8_t* const ObjA = static_cast<const uint8_t*>(ObjectArray::GetByIndex(0x055).GetAddress());
	const uint8_t* const ObjB = static_cast<const uint8_t*>(ObjectArray::GetByIndex(0x123).GetAddress());

	int32_t Offset = 0;
	while (Offset != OffsetNotFound)
	{
		Offset = GetValidPointerOffset<true>(ObjA, ObjB, Offset + sizeof(void*), 0x50);

		if (IsValidCyclicUClassPtrOffset(ObjA, ObjB, Offset))
			return Offset;
	}

	return OffsetNotFound;
}

/*
* IsPotentialValidOffset: A function to filter offsets that can not possibly be valid for UObject::Name or FField::Name.
*						  Example for UObject::Name: it can 100% not be at the same offset as UObject::Class
* 
* DataGatherer: A function to gather values at the offsets not filterd by 'IsPotentialValidOffset'. Data is later used to filter more offsets, until hopefully only one is left.
*/
template<typename IteratorType>
int32_t FindNameOffsetForSomeClass(std::function<bool(int32_t Value)> IsPotentialValidOffset, IteratorType DataSetStartIterator, IteratorType DataSetEndIterator)
{
	/*
	* Requirements:
	*	- CmpIdx > 0x10 && CmpIdx < 0xF0000000
	*	- AverageValue >= 0x100 && AverageValue <= 0xFF00000;
	*	- Offset != { OtherOffsets }
	*/

	/* A struct describing the value */
	struct ValueInfo
	{
		int32 Offset;					   // Offset from the UObject start to this value
		int32 NumNamesWithLowCmpIdx = 0x0; // The number of names where the comparison index is in the range [0, 16]. Usually this should be far less than 0x20 names.
		uint64 TotalValue = 0x0;		   // The total value of the int32 data at this offset over all objects in GObjects
		bool bIsValidCmpIdxRange = true;   // Whether this value could be a valid FName::ComparisonIndex
	};


	std::vector<ValueInfo> PossibleOffsets;

	constexpr auto MaxAllowedComparisonIndexValue = 0x4000000; // Somewhat arbitrary limit. Make sure this isn't too low for games on FNamePool with lots of names and 0x14 block-size bits

	constexpr auto MaxAllowedAverageComparisonIndexValue = MaxAllowedComparisonIndexValue / 2; // Also somewhat arbitrary limit, but the average value shouldn't be as high as the max allowed one
	constexpr auto MinAllowedAverageComparisonIndexValue = 0x280; // If the average name is below 0x100 it is either the smallest UE application ever, or not the right offset

	constexpr auto LowComparisonIndexUpperCap = 0x10; // The upper limit of what is considered a "low" comparison index
	constexpr auto MaxAllowedNamesWithLowCmpIdx = 0x40;


	for (int i = sizeof(void*); i <= 0x40; i += 0x4)
	{
		if (!IsPotentialValidOffset(i))
			continue;

		PossibleOffsets.push_back(ValueInfo{ i });
	}

	auto GetDataAtOffsetAsInt = [](const void* Ptr, int32 Offset) -> uint32 { return *reinterpret_cast<const uint32*>(reinterpret_cast<const uintptr_t>(Ptr) + Offset); };

	int NumObjectsConsidered = 0;

	for (; DataSetStartIterator != DataSetEndIterator; ++DataSetStartIterator)
	{
		constexpr auto X86SmallPageSize = 0x1000;
		constexpr auto MaxAccessedSizeInUObject = 0x44;

		const void* CurrentObjectOrField = (*DataSetStartIterator).GetAddress();

		/*
		* Purpose: Make sure all offsets in the UObject::Name finder can be accessed
		* Reasoning: Objects are allocated in Blocks, these allocations are page-aligned in both size and base. If an object + MaxAccessedSizeInUObject goes past the page-bounds
		*            it might also go past the extends of an allocation. There's no reliable way of getting the size of UObject without knowing it's offsets first.
		*/
		const bool bIsGoingPastPageBounds = (reinterpret_cast<const uintptr_t>(CurrentObjectOrField) & (X86SmallPageSize - 1)) > (X86SmallPageSize - MaxAccessedSizeInUObject);
		if (bIsGoingPastPageBounds)
			continue;

		NumObjectsConsidered++;

		for (ValueInfo& Info : PossibleOffsets)
		{
			const uint32 ValueAtOffset = GetDataAtOffsetAsInt(CurrentObjectOrField, Info.Offset);

			Info.TotalValue += ValueAtOffset;
			Info.bIsValidCmpIdxRange = Info.bIsValidCmpIdxRange && ValueAtOffset < MaxAllowedComparisonIndexValue;
			Info.NumNamesWithLowCmpIdx += (ValueAtOffset <= LowComparisonIndexUpperCap);
		}
	}

	int32 FirstValidOffset = -1;
	for (const ValueInfo& Info : PossibleOffsets)
	{
		const auto AverageValue = (Info.TotalValue / NumObjectsConsidered);

		if (Info.bIsValidCmpIdxRange && Info.NumNamesWithLowCmpIdx <= MaxAllowedNamesWithLowCmpIdx
			&& AverageValue >= MinAllowedAverageComparisonIndexValue && AverageValue <= MaxAllowedAverageComparisonIndexValue)
		{
			if (FirstValidOffset == -1)
			{
				FirstValidOffset = Info.Offset;
				continue;
			}

			/* This shouldn't be the case, so log it as an info but continue, as the first offset is still likely the right one. */
			std::cerr << std::format("Dumper-7: Another [UObject/FField]::Name offset (0x{:04X}) is also considered valid.\n", Info.Offset);
		}
	}

	return FirstValidOffset;
}

int32_t OffsetFinder::FindUObjectNameOffset()
{
	auto IsPotentiallyValidOffset = [](int32 Offset) -> bool
	{
		// Make sure 0x4 aligned Offsets are neither the start, nor the middle of a pointer-member. Irrelevant for 32-bit, because the 2nd check will be 0x2 aligned then.
		return Offset != Off::UObject::Class && Offset != (Off::UObject::Class + (sizeof(void*) / 2))
			&& Offset != Off::UObject::Outer && Offset != (Off::UObject::Outer + (sizeof(void*) / 2))
			&& Offset != Off::UObject::Flags
			&& Offset != Off::UObject::Index
			&& Offset != Off::UObject::Vft && Offset != (Off::UObject::Vft + (sizeof(void*) / 2));
	};

	return FindNameOffsetForSomeClass(IsPotentiallyValidOffset, ObjectArray().begin(), ObjectArray().end());
}

int32_t OffsetFinder::FindUObjectOuterOffset()
{
	int32_t LowestFoundOffset = 0xFFFF;

	const int32 NumObjects = ObjectArray::Num();
	if (NumObjects < 2)
		return OffsetNotFound;

	/* Seed with the address of the first object so it varies per game but is deterministic per run. */
	std::mt19937 Rng(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ObjectArray::GetByIndex(0).GetAddress())));
	const int32_t UpperBound = (NumObjects - 1 < 0x3FF) ? (NumObjects - 1) : 0x3FF;
	std::uniform_int_distribution<int32_t> Dist(0, UpperBound);

	// loop a few times in case we accidentally choose a UPackage (which doesn't have an Outer) to find Outer
	for (int i = 0; i < 0x10; i++)
	{
		int32_t Offset = 0;

		const int32_t IndexA = Dist(Rng);
		int32_t IndexB = Dist(Rng);
		if (IndexB == IndexA)
			IndexB = (IndexA + 1) % (UpperBound + 1);

		const void* ObjA = ObjectArray::GetByIndex(IndexA).GetAddress();
		const void* ObjB = ObjectArray::GetByIndex(IndexB).GetAddress();

		while (Offset != OffsetNotFound)
		{
			Offset = GetValidPointerOffset(ObjA, ObjB, Offset + sizeof(void*), 0x50);

			// Make sure we didn't re-find the Class offset or Index (if the Index filed is a valid pionter for some ungodly reason). 
			if (Offset != Off::UObject::Class && Offset != Off::UObject::Index)
				break;
		}

		if (Offset != OffsetNotFound && Offset < LowestFoundOffset)
			LowestFoundOffset = Offset;
	}

	return LowestFoundOffset == 0xFFFF ? OffsetNotFound : LowestFoundOffset;
}

void OffsetFinder::FixupHardcodedOffsets()
{
	if (Settings::Internal::bUseCasePreservingName)
	{
		Off::FField::Flags += 0x8;

		Off::FFieldClass::Id += 0x08;
		Off::FFieldClass::CastFlags += 0x08;
		Off::FFieldClass::ClassFlags += 0x08;
		Off::FFieldClass::SuperClass += 0x08;
	}

	if (Settings::Internal::bUseFProperty)
	{
		/*
		* On versions below 5.1.1: class FFieldVariant { void*, bool } -> extends to { void*, bool, uint8[0x7] }
		* ON versions since 5.1.1: class FFieldVariant { void* }
		*
		* Check:
		* if FFieldVariant contains a bool, the memory at the bools offset will not be a valid pointer
		* if FFieldVariant doesn't contain a bool, the memory at the bools offset will be the next member of FField, the Next ptr [valid]
		*/

		const int32 OffsetToCheck = Off::FField::Owner + 0x8;
		void* PossibleNextPtrOrBool0 = *(void**)((uint8*)ObjectArray::FindClassFast("Actor").GetChildProperties().GetAddress() + OffsetToCheck);
		void* PossibleNextPtrOrBool1 = *(void**)((uint8*)ObjectArray::FindClassFast("ActorComponent").GetChildProperties().GetAddress() + OffsetToCheck);
		void* PossibleNextPtrOrBool2 = *(void**)((uint8*)ObjectArray::FindClassFast("Pawn").GetChildProperties().GetAddress() + OffsetToCheck);

		auto IsValidPtr = [](void* a) -> bool
		{
			return !Platform::IsBadReadPtr(a) && (uintptr_t(a) & 0x1) == 0; // realistically, there wont be any pointers to unaligned memory
		};

		if (IsValidPtr(PossibleNextPtrOrBool0) && IsValidPtr(PossibleNextPtrOrBool1) && IsValidPtr(PossibleNextPtrOrBool2))
		{
			std::cerr << "Applying fix to hardcoded offsets \n" << std::endl;

			Settings::Internal::bUseMaskForFieldOwner = true;

			Off::FField::Next -= 0x08;
			Off::FField::Name -= 0x08;
			Off::FField::Flags -= 0x08;
		}
	}
}

void OffsetFinder::InitDiscoveryFFieldLayout()
{
	const std::uintptr_t ModuleBase = Platform::GetModuleBase(Settings::General::DefaultModuleName);
	const auto* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(ModuleBase);
	if (!ModuleBase || Platform::IsBadReadPtr(DosHeader) || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		throw std::runtime_error("Discovery FField scan could not read the main module");

	const auto* NtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(ModuleBase + DosHeader->e_lfanew);
	if (Platform::IsBadReadPtr(NtHeaders) || NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("Discovery FField scan found an invalid NT header");

	const std::uintptr_t ModuleEnd = ModuleBase + NtHeaders->OptionalHeader.SizeOfImage;
	struct Decoder
	{
		std::uint32_t NameOffset = 0;
		std::uint8_t InputRegister = 0;
		std::uint64_t ScalarXor = 0;
		std::uint8_t ScalarRotate = 0;
		std::vector<Discovery::ProtectedVectorInstruction> Instructions;
	};

	std::vector<std::pair<const std::uint8_t*, std::size_t>> ReadableRanges;
	const auto* Section = IMAGE_FIRST_SECTION(NtHeaders);
	for (std::uint16_t SectionIndex = 0; SectionIndex < NtHeaders->FileHeader.NumberOfSections; ++SectionIndex, ++Section)
	{
		if (!(Section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
			continue;

		const auto* SectionBegin = reinterpret_cast<const std::uint8_t*>(ModuleBase + Section->VirtualAddress);
		const auto* SectionEnd = SectionBegin + std::min<std::size_t>(Section->Misc.VirtualSize, ModuleEnd - reinterpret_cast<std::uintptr_t>(SectionBegin));
		for (const std::uint8_t* Cursor = SectionBegin; Cursor < SectionEnd;)
		{
			MEMORY_BASIC_INFORMATION MemoryInfo{};
			if (!VirtualQuery(Cursor, &MemoryInfo, sizeof(MemoryInfo)))
				break;
			const auto* RegionEnd = std::min(SectionEnd, reinterpret_cast<const std::uint8_t*>(MemoryInfo.BaseAddress) + MemoryInfo.RegionSize);
			if (RegionEnd <= Cursor)
				break;

			constexpr DWORD ReadableMask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
			constexpr DWORD InaccessibleMask = PAGE_GUARD | PAGE_NOACCESS;
			if (MemoryInfo.State == MEM_COMMIT && (MemoryInfo.Protect & ReadableMask) && !(MemoryInfo.Protect & InaccessibleMask))
			{
				const std::size_t RegionSize = static_cast<std::size_t>(RegionEnd - Cursor);
				if (!ReadableRanges.empty() && ReadableRanges.back().first + ReadableRanges.back().second == Cursor)
					ReadableRanges.back().second += RegionSize;
				else if (RegionSize >= 0x100)
					ReadableRanges.emplace_back(Cursor, RegionSize);
			}
			Cursor = RegionEnd;
		}
	}

	const UEObject GuidObject = ObjectArray::FindObjectFast("Guid");
	const UEObject VectorObject = ObjectArray::FindObjectFast("Vector");
	const UEObject ColorObject = ObjectArray::FindObjectFast("Color");
	if (!GuidObject || !VectorObject || !ColorObject)
		throw std::runtime_error("Discovery FField decoder could not resolve validation structs");
	if (DiscoveryChildPropertiesCandidates.empty())
		DiscoveryChildPropertiesCandidates.push_back(Off::UStruct::ChildProperties);
	if (DiscoveryChildPropertiesCandidates.empty())
		throw std::runtime_error("Discovery FField decoder could not resolve validation fields");

	auto ReadConstant = [&](const std::uint8_t* InstructionEnd, const std::int32_t Relative, std::array<std::uint8_t, 16>& Constant, const std::size_t Size)
	{
		const auto* Address = InstructionEnd + Relative;
		if (Size > Constant.size() || reinterpret_cast<std::uintptr_t>(Address) < ModuleBase || reinterpret_cast<std::uintptr_t>(Address + Size) > ModuleEnd || Platform::IsBadReadPtr(Address + Size - 1))
			return false;
		Constant.fill(0);
		std::memcpy(Constant.data(), Address, Size);
		return true;
	};

	auto FindVectorConstant = [&](const std::uint8_t* Begin, const std::uint8_t* End, const std::uint8_t Register, std::array<std::uint8_t, 16>& Constant)
	{
		bool Found = false;
		for (const std::uint8_t* Cursor = Begin; Cursor + 8 <= End; ++Cursor)
		{
			const std::uint8_t Prefix = *Cursor;
			if (Prefix != 0x66 && Prefix != 0xF3)
				continue;
			const std::uint8_t* Instruction = Cursor + 1;
			std::uint8_t Rex = 0;
			if ((*Instruction & 0xF0) == 0x40)
				Rex = *Instruction++;
			if (Instruction + 7 > End || Instruction[0] != 0x0F || (Instruction[1] != 0x6F && Instruction[1] != 0x7E))
				continue;
			const std::uint8_t ModRm = Instruction[2];
			const std::uint8_t Destination = ((ModRm >> 3) & 0x7) | ((Rex & 0x4) ? 0x8 : 0x0);
			if (Destination != Register || (ModRm >> 6) != 0 || (ModRm & 0x7) != 5)
				continue;
			std::int32_t Relative = 0;
			std::memcpy(&Relative, Instruction + 3, sizeof(Relative));
			Found = ReadConstant(Instruction + 7, Relative, Constant, Prefix == 0xF3 || Instruction[1] == 0x7E ? 8 : 16);
		}
		return Found;
	};

	auto FindScalarImmediate = [](const std::uint8_t* Begin, const std::uint8_t* End, const std::uint8_t Register, std::uint64_t& Immediate)
	{
		bool Found = false;
		for (const std::uint8_t* Cursor = Begin; Cursor + 10 <= End; ++Cursor)
		{
			const std::uint8_t Rex = Cursor[0];
			if ((Rex & 0xF8) != 0x48 || Cursor[1] < 0xB8 || Cursor[1] > 0xBF)
				continue;
			const std::uint8_t Destination = (Cursor[1] - 0xB8) | ((Rex & 0x1) ? 0x8 : 0x0);
			if (Destination != Register)
				continue;
			std::memcpy(&Immediate, Cursor + 2, sizeof(Immediate));
			Found = true;
		}
		return Found;
	};

	auto ParseDecoder = [&](const std::uint8_t* Load, const std::uint8_t* RangeBegin, const std::uint8_t* RangeEnd, Decoder& Result)
	{
		const std::uint8_t* Cursor = Load;
		if (Cursor >= RangeEnd || *Cursor++ != 0x66)
			return false;
		std::uint8_t Rex = 0;
		if (Cursor < RangeEnd && (*Cursor & 0xF0) == 0x40)
			Rex = *Cursor++;
		if (Cursor + 4 > RangeEnd || Cursor[0] != 0x0F || Cursor[1] != 0x6F)
			return false;
		Cursor += 2;
		const std::uint8_t LoadModRm = *Cursor++;
		const std::uint8_t LoadMode = LoadModRm >> 6;
		if (LoadMode != 1 && LoadMode != 2)
			return false;
		const std::uint8_t InputRegister = ((LoadModRm >> 3) & 0x7) | ((Rex & 0x4) ? 0x8 : 0x0);
		std::int32_t NameOffset = 0;
		if (LoadMode == 1)
			NameOffset = static_cast<std::int8_t>(*Cursor++);
		else
		{
			if (Cursor + 4 > RangeEnd)
				return false;
			std::memcpy(&NameOffset, Cursor, sizeof(NameOffset));
			Cursor += 4;
		}
		if (NameOffset <= 0 || NameOffset > 0x100 || (NameOffset & 0x7))
			return false;

		Result = {};
		Result.NameOffset = static_cast<std::uint32_t>(NameOffset);
		Result.InputRegister = InputRegister;
		std::array<bool, 16> DefinedRegisters{};
		DefinedRegisters[InputRegister] = true;
		const std::uint8_t* PreludeBegin = Load - std::min<std::ptrdiff_t>(Load - RangeBegin, 0x80);

		while (Cursor < RangeEnd && Result.Instructions.size() + 1 < Discovery::FieldNameProgram.size())
		{
			const std::uint8_t Prefix = *Cursor++;
			if (Prefix != 0x66 && Prefix != 0xF2)
				return false;
			Rex = 0;
			if (Cursor < RangeEnd && (*Cursor & 0xF0) == 0x40)
				Rex = *Cursor++;
			if (Cursor + 2 > RangeEnd || *Cursor++ != 0x0F)
				return false;
			bool ThreeByteOpcode = false;
			std::uint8_t Opcode = *Cursor++;
			if (Opcode == 0x38)
			{
				if (Cursor >= RangeEnd)
					return false;
				ThreeByteOpcode = true;
				Opcode = *Cursor++;
			}
			if (Cursor >= RangeEnd)
				return false;
			const std::uint8_t ModRm = *Cursor++;
			const std::uint8_t Mode = ModRm >> 6;
			const std::uint8_t Register = ((ModRm >> 3) & 0x7) | ((Rex & 0x4) ? 0x8 : 0x0);
			const std::uint8_t Rm = (ModRm & 0x7) | ((Rex & 0x1) ? 0x8 : 0x0);

			if (!ThreeByteOpcode && Opcode == 0x7E && Prefix == 0x66 && (Rex & 0x8) && Mode == 3)
			{
				const std::uint8_t VectorOutput = Register;
				std::uint8_t ScalarRegister = Rm;
				const std::uint8_t* ScalarEnd = std::min(RangeEnd, Cursor + 0x40);
				for (const std::uint8_t* Scalar = Cursor; Scalar + 3 <= ScalarEnd; ++Scalar)
				{
					if ((Scalar[0] & 0xF8) != 0x48)
						continue;
					const std::uint8_t ScalarRex = Scalar[0];
					if ((Scalar[1] == 0x31 || Scalar[1] == 0x33) && (Scalar[2] >> 6) == 3)
					{
						const std::uint8_t Reg = ((Scalar[2] >> 3) & 0x7) | ((ScalarRex & 0x4) ? 0x8 : 0x0);
						const std::uint8_t RmRegister = (Scalar[2] & 0x7) | ((ScalarRex & 0x1) ? 0x8 : 0x0);
						const std::uint8_t Destination = Scalar[1] == 0x31 ? RmRegister : Reg;
						const std::uint8_t Source = Scalar[1] == 0x31 ? Reg : RmRegister;
						const std::uint8_t ConstantRegister = Destination == ScalarRegister ? Source : (Source == ScalarRegister ? Destination : 0xFF);
						std::uint64_t Immediate = 0;
						if (ConstantRegister != 0xFF && FindScalarImmediate(PreludeBegin, Scalar, ConstantRegister, Immediate))
						{
							Result.ScalarXor = Immediate;
							ScalarRegister = Destination;
						}
					}
					else if (Scalar[1] == 0xC1 && (Scalar[2] >> 6) == 3 && ((Scalar[2] >> 3) & 0x7) == 0)
					{
						const std::uint8_t Destination = (Scalar[2] & 0x7) | ((ScalarRex & 0x1) ? 0x8 : 0x0);
						if (Destination == ScalarRegister && Scalar[3] > 0 && Scalar[3] < 64)
						{
							Result.ScalarRotate = Scalar[3];
							Result.Instructions.push_back({
								.Opcode = Discovery::ProtectedVectorOpcode::ReturnLowQword,
								.Source = VectorOutput,
							});
							return true;
						}
					}
				}
				return false;
			}

			Discovery::ProtectedVectorInstruction Instruction{};
			Instruction.Destination = Register;
			Instruction.Source = Rm;
			if (!ThreeByteOpcode && (Opcode == 0x71 || Opcode == 0x72 || Opcode == 0x73) && Mode == 3)
			{
				if (Cursor >= RangeEnd)
					return false;
				Instruction.Destination = Rm;
				Instruction.Source = Rm;
				Instruction.Immediate = *Cursor++;
				const std::uint8_t Group = (ModRm >> 3) & 0x7;
				if (Opcode == 0x71 && Group == 2)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::ShiftRightWords;
				else if (Opcode == 0x71 && Group == 6)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::ShiftLeftWords;
				else if (Opcode == 0x72 && Group == 2)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::ShiftRightDwords;
				else if (Opcode == 0x72 && Group == 6)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::ShiftLeftDwords;
				else if (Opcode == 0x73 && Group == 2)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::ShiftRightQwords;
				else if (Opcode == 0x73 && Group == 6)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::ShiftLeftQwords;
				else
					return false;
			}
			else if (!ThreeByteOpcode && Opcode == 0x70 && Prefix == 0xF2 && Mode == 3)
			{
				if (Cursor >= RangeEnd)
					return false;
				Instruction.Opcode = Discovery::ProtectedVectorOpcode::ShuffleLowWords;
				Instruction.Immediate = *Cursor++;
			}
			else
			{
				if (!ThreeByteOpcode && Opcode == 0x6F)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::Move;
				else if (!ThreeByteOpcode && Opcode == 0xEF)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::Xor;
				else if (!ThreeByteOpcode && Opcode == 0xFD)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::AddWords;
				else if (!ThreeByteOpcode && Opcode == 0xFE)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::AddDwords;
				else if (!ThreeByteOpcode && Opcode == 0xEB)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::Or;
				else if (!ThreeByteOpcode && Opcode == 0xDB)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::And;
				else if (!ThreeByteOpcode && Opcode == 0xDF)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::AndNot;
				else if (ThreeByteOpcode && Opcode == 0x00)
					Instruction.Opcode = Discovery::ProtectedVectorOpcode::ShuffleBytes;
				else
					return false;

				if (Mode == 0 && (ModRm & 0x7) == 5)
				{
					if (Cursor + 4 > RangeEnd)
						return false;
					std::int32_t Relative = 0;
					std::memcpy(&Relative, Cursor, sizeof(Relative));
					Cursor += 4;
					Instruction.SourceIsConstant = true;
					if (!ReadConstant(Cursor, Relative, Instruction.Constant, 16))
						return false;
				}
				else if (Mode == 3)
				{
					if (!DefinedRegisters[Rm] && Rm != Register)
					{
						Instruction.SourceIsConstant = FindVectorConstant(PreludeBegin, Cursor, Rm, Instruction.Constant);
						if (!Instruction.SourceIsConstant)
							return false;
					}
				}
				else
					return false;
			}

			DefinedRegisters[Instruction.Destination] = true;
			Result.Instructions.push_back(Instruction);
		}
		return false;
	};

	std::vector<Decoder> ValidDecoders;
	std::size_t ExtractedPrograms = 0;
	for (const auto& [Begin, Size] : ReadableRanges)
	{
		for (std::size_t Offset = 0x80; Offset + 0x80 < Size; ++Offset)
		{
			Decoder Candidate;
			if (!ParseDecoder(Begin + Offset, Begin, Begin + Size, Candidate))
				continue;
			++ExtractedPrograms;
			if (Candidate.Instructions.empty() || Candidate.Instructions.size() > Discovery::FieldNameProgram.size())
				continue;

			Discovery::FieldNameOffset = Candidate.NameOffset;
			Discovery::FieldNameInputRegister = Candidate.InputRegister;
			Discovery::FieldNameProgramSize = static_cast<std::uint32_t>(Candidate.Instructions.size());
			std::copy(Candidate.Instructions.begin(), Candidate.Instructions.end(), Discovery::FieldNameProgram.begin());
			Discovery::FieldNameScalarXor = Candidate.ScalarXor;
			Discovery::FieldNameScalarRotate = Candidate.ScalarRotate;

			auto IsPlausibleName = [](const std::uint64_t Value)
			{
				return static_cast<std::uint32_t>(Value) > 0 && static_cast<std::uint32_t>(Value) < 0x04000000 && static_cast<std::uint32_t>(Value >> 32) < 0x00100000;
			};
			bool ValidatedAgainstKnownFields = false;
			for (const int32_t HeadOffset : DiscoveryChildPropertiesCandidates)
			{
				const auto* GuidChild = *reinterpret_cast<const std::uint8_t* const*>(static_cast<const std::uint8_t*>(GuidObject.GetAddress()) + HeadOffset);
				const auto* VectorChild = *reinterpret_cast<const std::uint8_t* const*>(static_cast<const std::uint8_t*>(VectorObject.GetAddress()) + HeadOffset);
				const auto* ColorChild = *reinterpret_cast<const std::uint8_t* const*>(static_cast<const std::uint8_t*>(ColorObject.GetAddress()) + HeadOffset);
				if (!GuidChild || !VectorChild || !ColorChild || Platform::IsBadReadPtr(GuidChild) || Platform::IsBadReadPtr(VectorChild) || Platform::IsBadReadPtr(ColorChild))
					continue;
				const std::uint64_t GuidRaw = Discovery::GetFieldName(GuidChild);
				const std::uint64_t VectorRaw = Discovery::GetFieldName(VectorChild);
				const std::uint64_t ColorRaw = Discovery::GetFieldName(ColorChild);
				if (!IsPlausibleName(GuidRaw) || !IsPlausibleName(VectorRaw) || !IsPlausibleName(ColorRaw))
					continue;
				const std::string GuidName = FName(GuidRaw).ToString();
				const std::string VectorName = FName(VectorRaw).ToString();
				const std::string ColorName = FName(ColorRaw).ToString();
				if ((GuidName == "A" || GuidName == "B" || GuidName == "C" || GuidName == "D") && (VectorName == "X" || VectorName == "Y" || VectorName == "Z") && (ColorName == "A" || ColorName == "B" || ColorName == "G" || ColorName == "R"))
				{
					ValidatedAgainstKnownFields = true;
					break;
				}
			}
			if (ValidatedAgainstKnownFields)
				ValidDecoders.push_back(std::move(Candidate));
		}
	}

	if (ValidDecoders.empty())
		throw std::runtime_error(std::format("Discovery FField instruction extractor validated no decoders from {} extracted programs across {} ranges", ExtractedPrograms, ReadableRanges.size()));
	const auto SelectedIterator = std::min_element(ValidDecoders.begin(), ValidDecoders.end(), [](const Decoder& Left, const Decoder& Right)
	{
		return Left.Instructions.size() < Right.Instructions.size();
	});
	const Decoder& Selected = *SelectedIterator;
	Discovery::FieldNameOffset = Selected.NameOffset;
	Discovery::FieldNameInputRegister = Selected.InputRegister;
	Discovery::FieldNameProgramSize = static_cast<std::uint32_t>(Selected.Instructions.size());
	std::copy(Selected.Instructions.begin(), Selected.Instructions.end(), Discovery::FieldNameProgram.begin());
	Discovery::FieldNameScalarXor = Selected.ScalarXor;
	Discovery::FieldNameScalarRotate = Selected.ScalarRotate;
	Discovery::FieldNameDecoderReady = true;
	std::cerr << std::format("Discovery FField instruction decoder recovered: name +0x{:X}, input xmm{}, {} vector instructions, scalar xor 0x{:016X}, rotl {} ({} validated implementations)\n", Selected.NameOffset, Selected.InputRegister, Selected.Instructions.size(), Selected.ScalarXor, Selected.ScalarRotate, ValidDecoders.size());

	const UEStruct Guid = GuidObject.Cast<UEStruct>();
	const UEStruct Vector = VectorObject.Cast<UEStruct>();
	const UEStruct Color = ColorObject.Cast<UEStruct>();

	auto IsField = [&](const std::uint8_t* Field)
	{
		if (!Field || (reinterpret_cast<std::uintptr_t>(Field) & 0x7) || Platform::IsBadReadPtr(Field))
			return false;
		const std::uintptr_t Vft = *reinterpret_cast<const std::uintptr_t*>(Field);
		return Vft >= ModuleBase && Vft < ModuleEnd;
	};
	auto ReadChain = [&](const std::uint8_t* Field, const int32 Offset)
	{
		std::vector<const std::uint8_t*> Chain;
		while (Field && Chain.size() < 512)
		{
			if (!IsField(Field) || std::find(Chain.begin(), Chain.end(), Field) != Chain.end() || Platform::IsBadReadPtr(Field + Offset))
				return std::vector<const std::uint8_t*>{};
			Chain.push_back(Field);
			Field = *reinterpret_cast<const std::uint8_t* const*>(Field + Offset);
		}
		return Field ? std::vector<const std::uint8_t*>{} : Chain;
	};
	auto HasExpectedNames = [&](const std::vector<const std::uint8_t*>& Chain, const std::set<std::string>& Expected)
	{
		if (Chain.size() != Expected.size())
			return false;
		std::set<std::string> Names;
		for (const std::uint8_t* Field : Chain)
		{
			const std::string Name = FName(Discovery::GetFieldName(Field)).ToString();
			if (!Expected.contains(Name))
				return false;
			Names.insert(Name);
		}
		return Names == Expected;
	};

	struct SemanticCandidate
	{
		int32 Head = OffsetNotFound;
		int32 Next = OffsetNotFound;
		int32 Owner = OffsetNotFound;
		int StructMatches = 0;
		int FieldMatches = 0;
		int InvalidHeads = 0;
		int References = 0;
	};
	std::vector<SemanticCandidate> SemanticCandidates;
	const std::array<const std::uint8_t*, 3> StructAddresses{
		static_cast<const std::uint8_t*>(Color.GetAddress()),
		static_cast<const std::uint8_t*>(Guid.GetAddress()),
		static_cast<const std::uint8_t*>(Vector.GetAddress()),
	};
	const std::array<std::set<std::string>, 3> ExpectedNames{
		std::set<std::string>{ "A", "B", "G", "R" },
		std::set<std::string>{ "A", "B", "C", "D" },
		std::set<std::string>{ "X", "Y", "Z" },
	};
	for (const int32 HeadOffset : DiscoveryChildPropertiesCandidates)
	{
		std::array<const std::uint8_t*, 3> Heads{};
		for (std::size_t Index = 0; Index < Heads.size(); ++Index)
			Heads[Index] = *reinterpret_cast<const std::uint8_t* const*>(StructAddresses[Index] + HeadOffset);
		for (int32 NextOffset = 0x8; NextOffset < 0x200; NextOffset += sizeof(void*))
		{
			std::array<std::vector<const std::uint8_t*>, 3> Chains;
			bool NamesMatch = true;
			for (std::size_t Index = 0; Index < Chains.size(); ++Index)
			{
				Chains[Index] = ReadChain(Heads[Index], NextOffset);
				if (!HasExpectedNames(Chains[Index], ExpectedNames[Index]))
				{
					NamesMatch = false;
					break;
				}
			}
			if (!NamesMatch)
				continue;

			std::vector<int32> OwnerCandidates;
			for (int32 OwnerOffset = 0x8; OwnerOffset < 0x200; OwnerOffset += sizeof(void*))
			{
				bool OwnersMatch = true;
				for (std::size_t StructIndex = 0; StructIndex < Chains.size() && OwnersMatch; ++StructIndex)
				{
					for (const std::uint8_t* Field : Chains[StructIndex])
					{
						if (Platform::IsBadReadPtr(Field + OwnerOffset) || ((*reinterpret_cast<const std::uintptr_t*>(Field + OwnerOffset) & ~1ull) != reinterpret_cast<std::uintptr_t>(StructAddresses[StructIndex])))
						{
							OwnersMatch = false;
							break;
						}
					}
				}
				if (OwnersMatch)
					OwnerCandidates.push_back(OwnerOffset);
			}
			if (OwnerCandidates.size() == 1)
				SemanticCandidates.push_back({ HeadOffset, NextOffset, OwnerCandidates[0] });
		}
	}

	std::sort(SemanticCandidates.begin(), SemanticCandidates.end(), [](const SemanticCandidate& Left, const SemanticCandidate& Right)
	{
		return std::tie(Left.Head, Left.Next, Left.Owner) < std::tie(Right.Head, Right.Next, Right.Owner);
	});
	SemanticCandidates.erase(std::unique(SemanticCandidates.begin(), SemanticCandidates.end(), [](const SemanticCandidate& Left, const SemanticCandidate& Right)
	{
		return Left.Head == Right.Head && Left.Next == Right.Next && Left.Owner == Right.Owner;
	}), SemanticCandidates.end());

	for (SemanticCandidate& Candidate : SemanticCandidates)
	{
		for (const UEObject Object : ObjectArray())
		{
			if (!Object || (!Object.IsA(EClassCastFlags::Struct) && !Object.IsA(EClassCastFlags::Function)))
				continue;
			const auto* StructAddress = static_cast<const std::uint8_t*>(Object.GetAddress());
			if (Platform::IsBadReadPtr(StructAddress + Candidate.Head))
				continue;
			const auto* Head = *reinterpret_cast<const std::uint8_t* const*>(StructAddress + Candidate.Head);
			if (!Head)
				continue;
			if (!IsField(Head))
			{
				++Candidate.InvalidHeads;
				continue;
			}
			const auto Chain = ReadChain(Head, Candidate.Next);
			if (Chain.empty())
			{
				++Candidate.InvalidHeads;
				continue;
			}

			bool Valid = true;
			std::set<std::uint64_t> Names;
			for (const std::uint8_t* Field : Chain)
			{
				if (Platform::IsBadReadPtr(Field + Candidate.Owner) || ((*reinterpret_cast<const std::uintptr_t*>(Field + Candidate.Owner) & ~1ull) != reinterpret_cast<std::uintptr_t>(StructAddress)))
				{
					Valid = false;
					break;
				}
				const std::uint64_t Name = Discovery::GetFieldName(Field);
				if (static_cast<std::uint32_t>(Name) == 0 || static_cast<std::uint32_t>(Name) >= 0x04000000 || static_cast<std::uint32_t>(Name >> 32) >= 0x00100000 || !Names.insert(Name).second)
				{
					Valid = false;
					break;
				}
			}
			if (Valid)
			{
				++Candidate.StructMatches;
				Candidate.FieldMatches += static_cast<int>(Chain.size());
			}
			else
				++Candidate.InvalidHeads;
		}
	}
	if (SemanticCandidates.size() > 1)
	{
		const int FewestInvalidHeads = std::min_element(SemanticCandidates.begin(), SemanticCandidates.end(), [](const SemanticCandidate& Left, const SemanticCandidate& Right)
		{
			return Left.InvalidHeads < Right.InvalidHeads;
		})->InvalidHeads;
		std::erase_if(SemanticCandidates, [&](const SemanticCandidate& Candidate)
		{
			return Candidate.InvalidHeads != FewestInvalidHeads;
		});
	}
	if (SemanticCandidates.size() > 1)
	{
		const auto BestSemanticScore = std::max_element(SemanticCandidates.begin(), SemanticCandidates.end(), [](const SemanticCandidate& Left, const SemanticCandidate& Right)
		{
			return std::tie(Left.StructMatches, Left.FieldMatches) < std::tie(Right.StructMatches, Right.FieldMatches);
		});
		const int BestStructMatches = BestSemanticScore->StructMatches;
		const int BestFieldMatches = BestSemanticScore->FieldMatches;
		std::erase_if(SemanticCandidates, [&](const SemanticCandidate& Candidate)
		{
			return Candidate.StructMatches != BestStructMatches || Candidate.FieldMatches != BestFieldMatches;
		});
	}

	auto FindDisplacementReferences = [](const std::uint8_t* Begin, const std::uint8_t* End, const int32 Displacement)
	{
		std::vector<std::size_t> References;
		const std::size_t Size = static_cast<std::size_t>(End - Begin);
		if (Size < 8 || Size > 0x10000)
			return References;
		std::vector<std::uint8_t> Bytes(Size);
		SIZE_T BytesRead = 0;
		if (!ReadProcessMemory(GetCurrentProcess(), Begin, Bytes.data(), Bytes.size(), &BytesRead) || BytesRead != Bytes.size())
			return References;
		const std::uint8_t* BufferBegin = Bytes.data();
		const std::uint8_t* BufferEnd = BufferBegin + Bytes.size();
		for (const std::uint8_t* Cursor = BufferBegin; Cursor + 8 <= BufferEnd; ++Cursor)
		{
			const std::uint8_t* Instruction = Cursor;
			while (Instruction < BufferEnd && (*Instruction == 0x66 || *Instruction == 0xF2 || *Instruction == 0xF3))
				++Instruction;
			if (Instruction < BufferEnd && (*Instruction & 0xF0) == 0x40)
				++Instruction;
			if (Instruction >= BufferEnd)
				continue;
			const std::uint8_t Opcode = *Instruction++;
			bool HasModRm = Opcode == 0x8B || Opcode == 0x89 || Opcode == 0x8D || Opcode == 0x39 || Opcode == 0x3B || Opcode == 0x85 || Opcode == 0x81 || Opcode == 0x83 || Opcode == 0xC7 || Opcode == 0xFF;
			if (Opcode == 0x0F && Instruction < BufferEnd)
			{
				const std::uint8_t SecondOpcode = *Instruction++;
				HasModRm = SecondOpcode == 0x10 || SecondOpcode == 0x11 || SecondOpcode == 0xB6 || SecondOpcode == 0xB7 || SecondOpcode == 0xBE || SecondOpcode == 0xBF;
			}
			if (!HasModRm || Instruction >= BufferEnd)
				continue;
			const std::uint8_t ModRm = *Instruction++;
			const std::uint8_t Mode = ModRm >> 6;
			if (Mode != 1 && Mode != 2)
				continue;
			if ((ModRm & 0x7) == 4)
			{
				if (Instruction >= BufferEnd)
					continue;
				++Instruction;
			}
			if (Mode == 1)
			{
				if (Instruction < BufferEnd && static_cast<int32>(static_cast<std::int8_t>(*Instruction)) == Displacement)
					References.push_back(static_cast<std::size_t>(Cursor - BufferBegin));
			}
			else if (Instruction + sizeof(int32) <= BufferEnd)
			{
				int32 Value = 0;
				std::memcpy(&Value, Instruction, sizeof(Value));
				if (Value == Displacement)
					References.push_back(static_cast<std::size_t>(Cursor - BufferBegin));
			}
		}
		return References;
	};

	if (SemanticCandidates.size() > 1)
	{
		const IMAGE_DATA_DIRECTORY& ExceptionDirectory = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		const auto* RuntimeFunctions = reinterpret_cast<const RUNTIME_FUNCTION*>(ModuleBase + ExceptionDirectory.VirtualAddress);
		const std::size_t RuntimeFunctionCount = ExceptionDirectory.Size / sizeof(RUNTIME_FUNCTION);
		for (SemanticCandidate& Candidate : SemanticCandidates)
		{
			for (std::size_t FunctionIndex = 0; FunctionIndex < RuntimeFunctionCount; ++FunctionIndex)
			{
				const auto* FunctionBegin = reinterpret_cast<const std::uint8_t*>(ModuleBase + RuntimeFunctions[FunctionIndex].BeginAddress);
				const auto* FunctionEnd = reinterpret_cast<const std::uint8_t*>(ModuleBase + RuntimeFunctions[FunctionIndex].EndAddress);
				if (FunctionBegin >= FunctionEnd || reinterpret_cast<std::uintptr_t>(FunctionEnd) > ModuleEnd)
					continue;
				const bool EntireFunctionIsReadable = std::any_of(ReadableRanges.begin(), ReadableRanges.end(), [&](const auto& Range)
				{
					return FunctionBegin >= Range.first && FunctionEnd <= Range.first + Range.second;
				});
				if (!EntireFunctionIsReadable)
					continue;
				const auto HeadReferences = FindDisplacementReferences(FunctionBegin, FunctionEnd, Candidate.Head);
				if (HeadReferences.empty())
					continue;
				const auto NextReferences = FindDisplacementReferences(FunctionBegin, FunctionEnd, Candidate.Next);
				bool PairFound = false;
				for (const std::size_t HeadReference : HeadReferences)
				{
					for (const std::size_t NextReference : NextReferences)
					{
						const std::size_t Distance = HeadReference > NextReference ? HeadReference - NextReference : NextReference - HeadReference;
						if (Distance <= 0x100)
						{
							PairFound = true;
							break;
						}
					}
					if (PairFound)
						break;
				}
				if (PairFound)
					++Candidate.References;
			}
		}
	}

	std::cerr << std::format("Discovery ChildProperties semantic scan matched {} head/link pairs", SemanticCandidates.size());
	for (const SemanticCandidate& Candidate : SemanticCandidates)
		std::cerr << std::format(" +0x{:X}/+0x{:X}/owner+0x{:X}/structs{}/fields{}/invalid{}/refs{}", Candidate.Head, Candidate.Next, Candidate.Owner, Candidate.StructMatches, Candidate.FieldMatches, Candidate.InvalidHeads, Candidate.References);
	std::cerr << '\n';
	if (SemanticCandidates.size() > 1)
	{
		const int HighestReferenceCount = std::max_element(SemanticCandidates.begin(), SemanticCandidates.end(), [](const SemanticCandidate& Left, const SemanticCandidate& Right)
		{
			return Left.References < Right.References;
		})->References;
		std::erase_if(SemanticCandidates, [&](const SemanticCandidate& Candidate)
		{
			return Candidate.References != HighestReferenceCount;
		});
		if (HighestReferenceCount == 0 || SemanticCandidates.size() != 1)
			throw std::runtime_error(std::format("Discovery ChildProperties remained ambiguous after semantic and executable-reference validation (best reference score {}, {} tied candidates)", HighestReferenceCount, SemanticCandidates.size()));
	}
	if (SemanticCandidates.size() != 1)
		throw std::runtime_error(std::format("Discovery ChildProperties semantic scan matched {} candidates", SemanticCandidates.size()));
	const int MaximumTransientInvalidHeads = std::max(16, SemanticCandidates[0].StructMatches / 1000);
	if (SemanticCandidates[0].InvalidHeads > MaximumTransientInvalidHeads)
		throw std::runtime_error(std::format("Discovery ChildProperties best candidate had {} invalid non-null heads, exceeding the transient-object limit of {}", SemanticCandidates[0].InvalidHeads, MaximumTransientInvalidHeads));
	if (SemanticCandidates[0].InvalidHeads != 0)
		std::cerr << std::format("Discovery ChildProperties accepted {} transient invalid heads across {} valid owners (limit {})\n", SemanticCandidates[0].InvalidHeads, SemanticCandidates[0].StructMatches, MaximumTransientInvalidHeads);

	Off::UStruct::ChildProperties = SemanticCandidates[0].Head;
	Off::FField::Next = SemanticCandidates[0].Next;
	Off::FField::Owner = SemanticCandidates[0].Owner;
	std::cerr << std::format("Discovery ChildProperties resolved semantically at +0x{:X} with FField::Next +0x{:X} and Owner +0x{:X}\n", Off::UStruct::ChildProperties, Off::FField::Next, Off::FField::Owner);

	const auto* GuidChild = static_cast<const std::uint8_t*>(Guid.GetChildProperties().GetAddress());
	const auto* VectorChild = static_cast<const std::uint8_t*>(Vector.GetChildProperties().GetAddress());
	const auto* ColorChild = static_cast<const std::uint8_t*>(Color.GetChildProperties().GetAddress());
	if (!GuidChild || !VectorChild || !ColorChild)
		throw std::runtime_error("Discovery FField layout validation could not read known child-property chains");

	const std::string GuidName = FName(Discovery::GetFieldName(GuidChild)).ToString();
	const std::string VectorName = FName(Discovery::GetFieldName(VectorChild)).ToString();
	if ((GuidName != "A" && GuidName != "B" && GuidName != "C" && GuidName != "D") || (VectorName != "X" && VectorName != "Y" && VectorName != "Z"))
		throw std::runtime_error(std::format("Discovery FField name decoder failed known-name validation: Guid={}, Vector={}", GuidName, VectorName));

	const std::uint64_t IntCast = static_cast<std::uint64_t>(EClassCastFlags::Field | EClassCastFlags::Property | EClassCastFlags::NumericProperty | EClassCastFlags::IntProperty);
	const std::uint64_t ByteCast = static_cast<std::uint64_t>(EClassCastFlags::Field | EClassCastFlags::Property | EClassCastFlags::NumericProperty | EClassCastFlags::ByteProperty);
	const std::uint64_t NumericCastMask = static_cast<std::uint64_t>(EClassCastFlags::Field | EClassCastFlags::Property | EClassCastFlags::NumericProperty);
	const auto GuidChain = ReadChain(GuidChild, Off::FField::Next);
	const auto ColorChain = ReadChain(ColorChild, Off::FField::Next);
	const auto VectorChain = ReadChain(VectorChild, Off::FField::Next);
	std::vector<std::pair<int32, int32>> ClassCandidates;
	for (int32 ClassOffset = 0x8; ClassOffset < 0x200; ClassOffset += sizeof(void*))
	{
		if (Platform::IsBadReadPtr(GuidChild + ClassOffset) || Platform::IsBadReadPtr(ColorChild + ClassOffset) || Platform::IsBadReadPtr(VectorChild + ClassOffset))
			continue;
		const auto* GuidClass = *reinterpret_cast<const std::uint8_t* const*>(GuidChild + ClassOffset);
		const auto* ColorClass = *reinterpret_cast<const std::uint8_t* const*>(ColorChild + ClassOffset);
		const auto* VectorClass = *reinterpret_cast<const std::uint8_t* const*>(VectorChild + ClassOffset);
		if (!GuidClass || GuidClass == ColorClass || GuidClass == VectorClass || ColorClass == VectorClass || reinterpret_cast<std::uintptr_t>(GuidClass) < ModuleBase || reinterpret_cast<std::uintptr_t>(GuidClass) >= ModuleEnd || reinterpret_cast<std::uintptr_t>(ColorClass) < ModuleBase || reinterpret_cast<std::uintptr_t>(ColorClass) >= ModuleEnd || reinterpret_cast<std::uintptr_t>(VectorClass) < ModuleBase || reinterpret_cast<std::uintptr_t>(VectorClass) >= ModuleEnd)
			continue;
		for (int32 CastOffset = 0; CastOffset < 0x180; CastOffset += sizeof(std::uint64_t))
		{
			if (Platform::IsBadReadPtr(GuidClass + CastOffset) || Platform::IsBadReadPtr(ColorClass + CastOffset) || Platform::IsBadReadPtr(VectorClass + CastOffset))
				continue;
			const std::uint64_t VectorCast = *reinterpret_cast<const std::uint64_t*>(VectorClass + CastOffset);
			if (*reinterpret_cast<const std::uint64_t*>(GuidClass + CastOffset) != IntCast || *reinterpret_cast<const std::uint64_t*>(ColorClass + CastOffset) != ByteCast || (VectorCast & NumericCastMask) != NumericCastMask)
				continue;
			auto ChainUsesClass = [&](const std::vector<const std::uint8_t*>& Chain, const std::uint8_t* ExpectedClass)
			{
				return std::all_of(Chain.begin(), Chain.end(), [&](const std::uint8_t* Field)
				{
					return !Platform::IsBadReadPtr(Field + ClassOffset) && *reinterpret_cast<const std::uint8_t* const*>(Field + ClassOffset) == ExpectedClass;
				});
			};
			if (ChainUsesClass(GuidChain, GuidClass) && ChainUsesClass(ColorChain, ColorClass) && ChainUsesClass(VectorChain, VectorClass))
				ClassCandidates.emplace_back(ClassOffset, CastOffset);
		}
	}
	if (ClassCandidates.size() != 1)
		throw std::runtime_error(std::format("Discovery FField class/cast layout matched {} pairs", ClassCandidates.size()));
	Off::FField::Class = ClassCandidates[0].first;
	Off::FFieldClass::CastFlags = ClassCandidates[0].second;
	Off::FField::Name = Discovery::FieldNameOffset;
	Off::FField::Flags = OffsetFinder::OffsetNotFound;
	Off::FFieldClass::Name = Discovery::FieldNameOffset;

	const auto* IntClass = *reinterpret_cast<const std::uint8_t* const*>(GuidChild + Off::FField::Class);
	const auto* ByteClass = *reinterpret_cast<const std::uint8_t* const*>(ColorChild + Off::FField::Class);
	std::vector<int32> IdCandidates;
	for (int32 Offset = 0; Offset < 0x180; Offset += sizeof(std::uint64_t))
	{
		if (Platform::IsBadReadPtr(IntClass + Offset) || Platform::IsBadReadPtr(ByteClass + Offset))
			continue;
		if (*reinterpret_cast<const EFieldClassID*>(IntClass + Offset) == EFieldClassID::Int && *reinterpret_cast<const EFieldClassID*>(ByteClass + Offset) == EFieldClassID::Byte)
			IdCandidates.push_back(Offset);
	}
	if (IdCandidates.size() != 1)
		throw std::runtime_error(std::format("Discovery FFieldClass::Id matched {} offsets", IdCandidates.size()));
	Off::FFieldClass::Id = IdCandidates[0];

	const std::uint64_t NumericCast = static_cast<std::uint64_t>(EClassCastFlags::Field | EClassCastFlags::Property | EClassCastFlags::NumericProperty);
	std::vector<int32> SuperCandidates;
	for (int32 Offset = 0; Offset < 0x180; Offset += sizeof(void*))
	{
		if (Platform::IsBadReadPtr(IntClass + Offset) || Platform::IsBadReadPtr(ByteClass + Offset))
			continue;
		const auto* IntSuper = *reinterpret_cast<const std::uint8_t* const*>(IntClass + Offset);
		const auto* ByteSuper = *reinterpret_cast<const std::uint8_t* const*>(ByteClass + Offset);
		if (!IntSuper || IntSuper != ByteSuper || reinterpret_cast<std::uintptr_t>(IntSuper) < ModuleBase || reinterpret_cast<std::uintptr_t>(IntSuper) >= ModuleEnd)
			continue;
		if (*reinterpret_cast<const std::uint64_t*>(IntSuper + Off::FFieldClass::CastFlags) == NumericCast)
			SuperCandidates.push_back(Offset);
	}
	if (SuperCandidates.size() != 1)
		throw std::runtime_error(std::format("Discovery FFieldClass::SuperClass matched {} offsets", SuperCandidates.size()));
	Off::FFieldClass::SuperClass = SuperCandidates[0];

	// This separately protected member is not consumed by the dumper. Do not emit
	// a guessed raw field into generated output.
	Off::FFieldClass::ClassFlags = OffsetFinder::OffsetNotFound;
	Settings::Internal::bUseMaskForFieldOwner = true;
	std::cerr << std::format("Discovery FField decoder/layout recovered: name +0x{:X}, next +0x{:X}, class +0x{:X}, owner +0x{:X}, cast +0x{:X}, id +0x{:X}, super +0x{:X}\n", Off::FField::Name, Off::FField::Next, Off::FField::Class, Off::FField::Owner, Off::FFieldClass::CastFlags, Off::FFieldClass::Id, Off::FFieldClass::SuperClass);
}

void OffsetFinder::InitFNameSettings()
{
	UEObject FirstObject = ObjectArray::GetByIndex(0);

	const uint8* NameAddress = static_cast<const uint8*>(FirstObject.GetFName().GetAddress());

	const int32 FNameFirstInt /* ComparisonIndex */ = *reinterpret_cast<const int32*>(NameAddress);
	const int32 FNameSecondInt /* [Number/DisplayIndex] */ = *reinterpret_cast<const int32*>(NameAddress + 0x4);

	/* Some games move 'Name' before 'Class'. Just substract the offset of 'Name' with the offset of the member that follows right after it, to get an estimate of sizeof(FName). */
	const int32 FNameSize = !Settings::Internal::bIsObjectNameBeforeClass ? (Off::UObject::Outer - Off::UObject::Name) : (Off::UObject::Class - Off::UObject::Name);

	Off::FName::CompIdx = 0x0;
	Off::FName::Number = 0x4; // defaults for check

	 // FNames for which FName::Number == [1...4]
	auto GetNumNamesWithNumberOneToFour = []() -> int32
	{
		int32 NamesWithNumberOneToFour = 0x0;

		for (UEObject Obj : ObjectArray())
		{
			const uint32 Number = Obj.GetFName().GetNumber();

			if (Number > 0x0 && Number < 0x5)
				NamesWithNumberOneToFour++;
		}

		return NamesWithNumberOneToFour;
	};

	/*
	* Games without FNAME_OUTLINE_NUMBER have a min. percentage of 6% of all object-names for which FName::Number is in a [1...4] range
	* On games with FNAME_OUTLINE_NUMBER the (random) integer after FName::ComparisonIndex is in the range from [1...4] about 2% (or less) of times.
	*
	* The minimum percentage of names is set to 3% to give both normal names, as well as outline-numer names a buffer-zone.
	*
	* This doesn't work on some very small UE template games, which is why PostInitFNameSettings() was added to fix the incorrect behavior of this function
	*/
	constexpr float MinPercentage = 0.03f;

	/* Minimum required ammount of names for which FName::Number is in a [1...4] range */
	const int32 FNameNumberThreashold = (ObjectArray::Num() * MinPercentage);

	Off::FName::CompIdx = 0x0;

	if (FNameSize == 0x8 && FNameFirstInt == FNameSecondInt) /* WITH_CASE_PRESERVING_NAME + FNAME_OUTLINE_NUMBER */
	{
		Settings::Internal::bUseCasePreservingName = true;
		Settings::Internal::bUseOutlineNumberName = true;

		Off::FName::Number = -0x1;
		Off::InSDK::Name::FNameSize = 0x8;
	}
	else if (FNameSize == 0x10) /* WITH_CASE_PRESERVING_NAME */
	{
		Settings::Internal::bUseCasePreservingName = true;

		Off::FName::Number = FNameFirstInt == FNameSecondInt ? 0x8 : 0x4;

		Off::InSDK::Name::FNameSize = 0xC;
	}
	else if (GetNumNamesWithNumberOneToFour() < FNameNumberThreashold) /* FNAME_OUTLINE_NUMBER */
	{
		Settings::Internal::bUseOutlineNumberName = true;

		Off::FName::Number = -0x1;

		Off::InSDK::Name::FNameSize = 0x4;
	}
	else /* Default */
	{
		Off::FName::Number = 0x4;

		Off::InSDK::Name::FNameSize = 0x8;
	}
}

void OffsetFinder::PostInitFNameSettings()
{
	const UEClass PlayerStart = ObjectArray::FindClassFast("PlayerStart");

	const int32 FNameSize = PlayerStart.FindMember("PlayerStartTag").GetSize();

	/* Nothing to do for us, everything is fine! */
	if (Off::InSDK::Name::FNameSize == FNameSize)
		return;

	/* We've used the wrong FNameSize to determine the offset of FField::Flags. Substract the old, wrong, size and add the new one.*/
	Off::FField::Flags = (Off::FField::Flags - Off::InSDK::Name::FNameSize) + FNameSize;

	const uint8* NameAddress = static_cast<const uint8*>(PlayerStart.GetFName().GetAddress());

	const int32 FNameFirstInt /* ComparisonIndex */ = *reinterpret_cast<const int32*>(NameAddress);
	const int32 FNameSecondInt /* [Number/DisplayIndex] */ = *reinterpret_cast<const int32*>(NameAddress + 0x4);

	if (FNameSize == 0x8 && FNameFirstInt == FNameSecondInt) /* WITH_CASE_PRESERVING_NAME + FNAME_OUTLINE_NUMBER */
	{
		Settings::Internal::bUseCasePreservingName = true;
		Settings::Internal::bUseOutlineNumberName = true;

		Off::FName::Number = -0x1;
		Off::InSDK::Name::FNameSize = 0x8;
	}
	else if (FNameSize > 0x8) /* WITH_CASE_PRESERVING_NAME */
	{
		Settings::Internal::bUseOutlineNumberName = false;
		Settings::Internal::bUseCasePreservingName = true;

		Off::FName::Number = FNameFirstInt == FNameSecondInt ? 0x8 : 0x4;

		Off::InSDK::Name::FNameSize = 0xC;
	}
	else if (FNameSize == 0x4) /* FNAME_OUTLINE_NUMBER */
	{
		Settings::Internal::bUseOutlineNumberName = true;
		Settings::Internal::bUseCasePreservingName = false;

		Off::FName::Number = -0x1;

		Off::InSDK::Name::FNameSize = 0x4;
	}
	else /* Default */
	{
		Settings::Internal::bUseOutlineNumberName = false;
		Settings::Internal::bUseCasePreservingName = false;

		Off::FName::Number = 0x4;
		Off::InSDK::Name::FNameSize = 0x8;
	}
}

/* UField */
int32_t OffsetFinder::FindUFieldNextOffset()
{
	const void* KismetSystemLibraryChild = ObjectArray::FindObjectFast<UEStruct>("KismetSystemLibrary").GetChild().GetAddress();
	const void* KismetStringLibraryChild = ObjectArray::FindObjectFast<UEStruct>("KismetStringLibrary").GetChild().GetAddress();

#undef max
	const auto HighestUObjectOffset = std::max({ Off::UObject::Index, Off::UObject::Name, Off::UObject::Flags, Off::UObject::Outer, Off::UObject::Class });
#define max(a,b)            (((a) > (b)) ? (a) : (b))

	const int32_t SearchEnd = Discovery::Enabled ? 0xD0 : 0x60;
	return GetValidPointerOffset(KismetSystemLibraryChild, KismetStringLibraryChild, Align(HighestUObjectOffset + 0x4, static_cast<int>(sizeof(void*))), SearchEnd);
}

/* FField */
int32_t OffsetFinder::FindFFieldNextOffset()
{
	const void* GuidChildren = ObjectArray::FindStructFast("Guid").GetChildProperties().GetAddress();
	const void* VectorChildren = ObjectArray::FindStructFast("Vector").GetChildProperties().GetAddress();

	if (Discovery::Enabled)
	{
		std::cerr << std::format("Discovery Guid ChildProperties: 0x{:X}\n", reinterpret_cast<uintptr_t>(GuidChildren));
		std::cerr << std::format("Discovery Vector ChildProperties: 0x{:X}\n", reinterpret_cast<uintptr_t>(VectorChildren));
		for (int32_t Offset = 0; Offset < 0x60; Offset += sizeof(void*))
		{
			const auto GuidValue = *reinterpret_cast<const uintptr_t*>(static_cast<const uint8_t*>(GuidChildren) + Offset);
			const auto VectorValue = *reinterpret_cast<const uintptr_t*>(static_cast<const uint8_t*>(VectorChildren) + Offset);
			std::cerr << std::format("  FField +0x{:02X}: Guid=0x{:016X} Vector=0x{:016X}\n", Offset, GuidValue, VectorValue);
		}
	}

	const int32_t SearchEnd = Discovery::Enabled ? 0xB0 : 0x48;
	return GetValidPointerOffset(GuidChildren, VectorChildren, Off::FField::Owner + 0x8, SearchEnd);
}

int32_t OffsetFinder::FindFFieldNameOffset()
{
	UEFField GuidChild = ObjectArray::FindStructFast("Guid").GetChildProperties();
	UEFField VectorChild = ObjectArray::FindStructFast("Vector").GetChildProperties();

	std::string GuidChildName = GuidChild.GetName();
	std::string VectorChildName = VectorChild.GetName();

	if ((GuidChildName == "A" || GuidChildName == "D") && (VectorChildName == "X" || VectorChildName == "Z"))
		return Off::FField::Name;

	for (Off::FField::Name = Off::FField::Owner; Off::FField::Name < 0x40; Off::FField::Name += 4)
	{
		GuidChildName = GuidChild.GetName();
		VectorChildName = VectorChild.GetName();

		if ((GuidChildName == "A" || GuidChildName == "D") && (VectorChildName == "X" || VectorChildName == "Z"))
			return Off::FField::Name;
	}

	return OffsetNotFound;
}

int32_t OffsetFinder::NewFindFFieldNameOffset()
{
	auto IsPotentiallyValidOffset = [](int32 Offset) -> bool
	{
		// Make sure 0x4 aligned Offsets are neither the start, nor the middle of a pointer-member. Irrelevant for 32-bit, because the 2nd check will be 0x2 aligned then.
		return Offset != Off::FField::Class && Offset != (Off::FField::Class + (sizeof(void*) / 2))
			&& Offset != Off::FField::Next && Offset != (Off::FField::Next + (sizeof(void*) / 2))
			&& Offset != Off::FField::Vft && Offset != (Off::FField::Vft + (sizeof(void*) / 2));
	};

	AllFieldIterator TmpIt;

	return FindNameOffsetForSomeClass(IsPotentiallyValidOffset, TmpIt.begin(), TmpIt.end());
}

int32_t OffsetFinder::FindFFieldEditorOnlyMetaDataOffset()
{
	const UEFField GuidChild1 = ObjectArray::FindStructFast("Guid").GetChildProperties();
	const UEFField GuidChild2 = GuidChild1.GetNext();

	auto IsPotentiallyValidOffset = [](int32 Offset) -> bool
		{
			// Make sure 0x4 aligned Offsets are neither the start, nor the middle of a pointer-member. Irrelevant for 32-bit, because the 2nd check will be 0x2 aligned then.
			return Offset != Off::FField::Class && Offset != (Off::FField::Class + (sizeof(void*) / 2))
				&& Offset != Off::FField::Next && Offset != (Off::FField::Next + (sizeof(void*) / 2))
				&& Offset != Off::FField::Vft && Offset != (Off::FField::Vft + (sizeof(void*) / 2))
				&& Offset != Off::FField::Name && Offset != (Off::FField::Name + Off::InSDK::Name::FNameSize);
		};

	int32 StartingOffset = 0x8;

	// Only pay attention to the 0x8 aligned size-options of FName, since the pair in the TMap is 0x8 aligned because of FString
	struct alignas(0x4) Name08Byte { uint8 Pad[0x08]; };
	struct alignas(0x4) Name16Byte { uint8 Pad[0x10]; };

	static auto AreValidMetadataMaps = []<typename NameType>(const TMap<NameType, FString>* MetadataMap1, const TMap<NameType, FString>* MetadataMap2)
	{
		if (!MetadataMap1->IsValid() || !MetadataMap2->IsValid())
			return false;

		const FString& Value1 = MetadataMap1->operator[](0).Value();
		const FString& Value2 = MetadataMap2->operator[](0).Value();

		return Value1.IsValid() && Value2.IsValid();
	};

	while (true)
	{
		if (!IsPotentiallyValidOffset(StartingOffset))
		{
			StartingOffset += sizeof(void*);
			continue;
		}

		const int32 Offset = GetValidPointerOffset<false>(GuidChild1.GetAddress(), GuidChild2.GetAddress(), StartingOffset, 0x40);
		StartingOffset = Offset + sizeof(void*);

		if (Offset == OffsetNotFound)
			break;

		if (!IsPotentiallyValidOffset(Offset))
			continue;

		const TMap<Name08Byte, FString>* PossibleMetaDataPtr1 = *reinterpret_cast<TMap<Name08Byte, FString>**>(reinterpret_cast<uintptr_t>(GuidChild1.GetAddress()) + Offset);
		const TMap<Name08Byte, FString>* PossibleMetaDataPtr2 = *reinterpret_cast<TMap<Name08Byte, FString>**>(reinterpret_cast<uintptr_t>(GuidChild2.GetAddress()) + Offset);

		if (!PossibleMetaDataPtr1 || !PossibleMetaDataPtr2 || Platform::IsBadReadPtr(PossibleMetaDataPtr1) || Platform::IsBadReadPtr(PossibleMetaDataPtr2))
			continue;

		if (!PossibleMetaDataPtr1->IsValid() || !PossibleMetaDataPtr2->IsValid())
			continue;

		if (PossibleMetaDataPtr1->Num() <= 0 || PossibleMetaDataPtr2->Num() <= 0)
			continue;

		if (PossibleMetaDataPtr1->Num() >= 0x10 || PossibleMetaDataPtr2->Num() >= 0x10)
			continue;

		auto GetDataPtrOfArrayInMap = [](const auto& Map) -> const void*
		{
			// TMap data is stored at offset 0x0, this is a hacky way to get the TArray::Data member of the map
			return *reinterpret_cast<const void* const*>(&Map);
		};

		if (Platform::IsBadReadPtr(GetDataPtrOfArrayInMap(PossibleMetaDataPtr1)) || Platform::IsBadReadPtr(GetDataPtrOfArrayInMap(PossibleMetaDataPtr2)))
			continue;

		if (Off::InSDK::Name::FNameSize <= 0x8)
		{
			if (AreValidMetadataMaps(PossibleMetaDataPtr1, PossibleMetaDataPtr2))
				return Offset;
		}
		else
		{
			if (AreValidMetadataMaps(reinterpret_cast<const TMap<Name16Byte, FString>*>(PossibleMetaDataPtr1), reinterpret_cast<const TMap<Name16Byte, FString>*>(PossibleMetaDataPtr1)))
				return Offset;
		}
	}

	return OffsetNotFound;
}

int32_t OffsetFinder::FindFFieldClassOffset()
{
	const UEFField GuidChild = ObjectArray::FindStructFast("Guid").GetChildProperties();
	const UEFField VectorChild = ObjectArray::FindStructFast("Vector").GetChildProperties();

	return GetValidPointerOffset<false>(GuidChild.GetAddress(), VectorChild.GetAddress(), 0x8, 0x30, true);
}

// This function assumes that the EnumObj passed in is valid and that the values of the enum are starting at 0
void InializeUEnumSettings(const void* EnumObj, const uint32_t UEnumNumValuesOffset)
{
	constexpr uintptr_t UE5EnumDynamicAllocationTag = 0x1;

	{
		// On UE5.6+ there are two arrays, one for just the FName*/UTF8Char* and one for just int64* values. Check if the array before NumValues contains just Values or TPair<Name, Value>.
		const uintptr_t PossibleValueArrayTaggedPtr = *reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(EnumObj) + UEnumNumValuesOffset - sizeof(void*));
		const int64* PossibleValueArrayPtr = reinterpret_cast<const int64*>(PossibleValueArrayTaggedPtr & ~UE5EnumDynamicAllocationTag);

		if (!Platform::IsBadReadPtr(PossibleValueArrayPtr) && !Platform::IsBadReadPtr(PossibleValueArrayPtr + 1) && !Platform::IsBadReadPtr(PossibleValueArrayPtr + 2))
		{
			if (PossibleValueArrayPtr[0] == 0 && PossibleValueArrayPtr[1] == 1 && PossibleValueArrayPtr[2] == 2)
			{
				Settings::Internal::bIsNewUE5EnumNamesContainer = true;
				return;
			}
		}
	}

	using ValueType = std::conditional_t<sizeof(void*) == 0x8, int64, int32>;
	struct Name08Byte { uint8 Pad[0x08]; };
	struct Name16Byte { uint8 Pad[0x10]; };

	const uint8* ArrayAddress = static_cast<const uint8*>(EnumObj) + UEnumNumValuesOffset - 0x8;

	auto InitEnumSettings = []<typename NameType>(const TArray<TPair<NameType, ValueType>>&ArrayOfNameValuePairs)
	{
		if (ArrayOfNameValuePairs[1].Second == 1)
			return;

		if constexpr (Settings::EngineCore::bCheckEnumNamesInUEnum)
		{
			if (static_cast<uint8_t>(ArrayOfNameValuePairs[1].Second) == 1 && static_cast<uint8_t>(ArrayOfNameValuePairs[2].Second) == 2)
			{

				Settings::Internal::bIsSmallEnumValue = true;
				return;
			}
		}

		Settings::Internal::bIsEnumNameOnly = true;
	};


	if (Settings::Internal::bUseCasePreservingName)
	{
		InitEnumSettings(*reinterpret_cast<const TArray<TPair<Name16Byte, ValueType>>*>(ArrayAddress));
	}
	else
	{
		InitEnumSettings(*reinterpret_cast<const TArray<TPair<Name08Byte, ValueType>>*>(ArrayAddress));
	}
}

/* FFieldClass */
int32_t OffsetFinder::FindFieldClassCastFlagsOffset()
{
	std::vector<std::pair<void*, EClassCastFlags>> Infos;

	const UEFField GuidChild = ObjectArray::FindStructFast("Guid").GetChildProperties();
	const UEFField ColourChild = ObjectArray::FindStructFast("Color").GetChildProperties();

	Infos.push_back({ GuidChild.GetClass().GetAddress(),   EClassCastFlags::Field | EClassCastFlags::Property | EClassCastFlags::NumericProperty | EClassCastFlags::IntProperty  });
	Infos.push_back({ ColourChild.GetClass().GetAddress(), EClassCastFlags::Field | EClassCastFlags::Property | EClassCastFlags::NumericProperty | EClassCastFlags::ByteProperty });

	const int32_t Offset = FindOffset(Infos, sizeof(void*), 0x30);

	return Offset != OffsetNotFound ? Offset : 0x10;
}

/* UEnum */
int32_t OffsetFinder::FindEnumNamesOffset()
{
	std::vector<std::pair<void*, int32_t>> Infos;

	Infos.push_back({ ObjectArray::FindObjectFast("ENetRole", EClassCastFlags::Enum).GetAddress(), 0x5 });
	Infos.push_back({ ObjectArray::FindObjectFast("ETraceTypeQuery", EClassCastFlags::Enum).GetAddress(), 0x22 });

	int UEnumNumValuesOffset = FindOffset(Infos);

	if (UEnumNumValuesOffset == OffsetNotFound)
	{
		Infos[0] = { ObjectArray::FindObjectFast("EAlphaBlendOption", EClassCastFlags::Enum).GetAddress(), 0x10 };
		Infos[1] = { ObjectArray::FindObjectFast("EUpdateRateShiftBucket", EClassCastFlags::Enum).GetAddress(), 0x8 };

		UEnumNumValuesOffset = FindOffset(Infos);
	}

	InializeUEnumSettings(Infos[0].first, UEnumNumValuesOffset);

	return UEnumNumValuesOffset - sizeof(void*);
}

int32_t OffsetFinder::FindEnumUnderlayingTypeOffset()
{
	std::vector<std::pair<void*, UEEnum::EUnderlyingType>> Infos;
	Infos.push_back({ ObjectArray::FindObjectFast("ENetRole", EClassCastFlags::Enum).GetAddress(), UEEnum::EUnderlyingType::uint8 });
	Infos.push_back({ ObjectArray::FindObjectFast("ETraceTypeQuery", EClassCastFlags::Enum).GetAddress(), UEEnum::EUnderlyingType::uint8 });

	int UEnumUnderlayingTypeOffset = FindOffset(Infos, OffsetFinderMinValue, 0xA0);

	if (UEnumUnderlayingTypeOffset == OffsetNotFound)
	{
		Infos[0] = { ObjectArray::FindObjectFast("EAlphaBlendOption", EClassCastFlags::Enum).GetAddress(), UEEnum::EUnderlyingType::uint8 };
		Infos[1] = { ObjectArray::FindObjectFast("EUpdateRateShiftBucket", EClassCastFlags::Enum).GetAddress(), UEEnum::EUnderlyingType::uint8 };

		UEnumUnderlayingTypeOffset = FindOffset(Infos, OffsetFinderMinValue, 0xA0);
	}

	Settings::Internal::bHasUnderlayingTypeInUEnum = UEnumUnderlayingTypeOffset != OffsetNotFound;

	return UEnumUnderlayingTypeOffset;
}

/* UStruct */
int32_t OffsetFinder::FindSuperOffset()
{
	std::vector<std::pair<void*, void*>> Infos;

	Infos.push_back({ ObjectArray::FindObjectFast("Struct").GetAddress(), ObjectArray::FindObjectFast("Field").GetAddress() });
	Infos.push_back({ ObjectArray::FindObjectFast("Class").GetAddress(), ObjectArray::FindObjectFast("Struct").GetAddress() });

	// Thanks to the ue4 dev who decided UStruct should be spelled Ustruct
	if (Infos[0].first == nullptr)
		Infos[0].first = Infos[1].second = ObjectArray::FindObjectFast("struct").GetAddress();

	return FindOffset(Infos);
}

int32_t OffsetFinder::FindChildOffset()
{
	std::vector<std::pair<void*, void*>> Infos;

	if (ObjectArray::FindObject("ObjectProperty Engine.Controller.TransformComponent", EClassCastFlags::ObjectProperty))
	{
		Infos.push_back({ ObjectArray::FindObjectFast("Vector").GetAddress(), ObjectArray::FindObjectFastInOuter("X", "Vector").GetAddress() });
		Infos.push_back({ ObjectArray::FindObjectFast("Vector4").GetAddress(), ObjectArray::FindObjectFastInOuter("X", "Vector4").GetAddress() });
		Infos.push_back({ ObjectArray::FindObjectFast("Vector2D").GetAddress(), ObjectArray::FindObjectFastInOuter("X", "Vector2D").GetAddress() });
		Infos.push_back({ ObjectArray::FindObjectFast("Guid").GetAddress(), ObjectArray::FindObjectFastInOuter("A","Guid").GetAddress() });

		return FindOffset(Infos, 0x14);
	}

	Infos.push_back({ ObjectArray::FindObjectFast("PlayerController").GetAddress(), ObjectArray::FindObjectFastInOuter("WasInputKeyJustReleased", "PlayerController").GetAddress() });
	Infos.push_back({ ObjectArray::FindObjectFast("Controller").GetAddress(), ObjectArray::FindObjectFastInOuter("UnPossess", "Controller").GetAddress() });

	Settings::Internal::bUseFProperty = true;

	return FindOffset(Infos);
}

int32_t OffsetFinder::FindChildPropertiesOffset()
{
	const void* ObjA = ObjectArray::FindObjectFast("Color").GetAddress();
	const void* ObjB = ObjectArray::FindObjectFast("Guid").GetAddress();

	if (!Discovery::Enabled)
		return GetValidPointerOffset(ObjA, ObjB, Off::UStruct::Children + 0x08, 0x80);

	const void* ObjC = ObjectArray::FindObjectFast("Vector").GetAddress();
	if (!ObjA || !ObjB || !ObjC || Off::UStruct::SuperStruct == OffsetNotFound || Off::UStruct::Size == OffsetNotFound)
	{
		std::cerr << std::format("Discovery ChildProperties prerequisites failed: Color=0x{:X}, Guid=0x{:X}, Vector=0x{:X}, SuperStruct=0x{:X}, PropertiesSize=0x{:X}\n", reinterpret_cast<uintptr_t>(ObjA), reinterpret_cast<uintptr_t>(ObjB), reinterpret_cast<uintptr_t>(ObjC), Off::UStruct::SuperStruct, Off::UStruct::Size);
		return OffsetNotFound;
	}

	const std::array<const uint8_t*, 3> Structs{
		static_cast<const uint8_t*>(ObjA),
		static_cast<const uint8_t*>(ObjB),
		static_cast<const uint8_t*>(ObjC),
	};
	std::vector<int32_t> Candidates;
	const int32_t SearchStart = 0x40;
	const int32_t HighestKnownMember = (std::max)({ Off::UStruct::Children, Off::UStruct::Size, Off::UStruct::MinAlignment });
	const int32_t SearchEnd = (std::min)(Align(HighestKnownMember + 0x100, static_cast<int32_t>(sizeof(void*))), 0x300);
	for (int32_t Offset = SearchStart; Offset < SearchEnd; Offset += sizeof(void*))
	{
		std::array<const void*, 3> Fields{};
		bool IsCandidate = true;
		for (std::size_t Index = 0; Index < Structs.size(); ++Index)
		{
			Fields[Index] = *reinterpret_cast<const void* const*>(Structs[Index] + Offset);
			if (!Fields[Index] || (reinterpret_cast<uintptr_t>(Fields[Index]) & (alignof(void*) - 1)) || Platform::IsBadReadPtr(Fields[Index]))
			{
				IsCandidate = false;
				break;
			}

			const void* Vft = *reinterpret_cast<const void* const*>(Fields[Index]);
			if (!Platform::IsAddressInProcessRange(Vft))
			{
				IsCandidate = false;
				break;
			}
		}

		if (IsCandidate && Fields[0] != Fields[1] && Fields[0] != Fields[2] && Fields[1] != Fields[2])
			Candidates.push_back(Offset);
	}
	std::cerr << std::format("Discovery ChildProperties pointer scan found {} candidate offsets", Candidates.size());
	for (const int32_t Offset : Candidates)
	{
		const auto* ColorField = *reinterpret_cast<const void* const*>(Structs[0] + Offset);
		const auto* GuidField = *reinterpret_cast<const void* const*>(Structs[1] + Offset);
		const auto* VectorField = *reinterpret_cast<const void* const*>(Structs[2] + Offset);
		std::cerr << std::format(" +0x{:X}[0x{:X}/0x{:X}/0x{:X}]", Offset, reinterpret_cast<std::uintptr_t>(ColorField), reinterpret_cast<std::uintptr_t>(GuidField), reinterpret_cast<std::uintptr_t>(VectorField));
	}
	std::cerr << '\n';

	auto IsField = [](const uint8_t* Field)
	{
		if (!Field || (reinterpret_cast<uintptr_t>(Field) & (alignof(void*) - 1)) || Platform::IsBadReadPtr(Field))
			return false;
		return Platform::IsAddressInProcessRange(*reinterpret_cast<const void* const*>(Field));
	};
	auto ChainLength = [&](const uint8_t* Field, const int32_t NextOffset)
	{
		int32_t Length = 0;
		std::array<const uint8_t*, 16> Seen{};
		while (Field && Length < static_cast<int32_t>(Seen.size()))
		{
			if (!IsField(Field) || std::find(Seen.begin(), Seen.begin() + Length, Field) != Seen.begin() + Length)
				return -1;
			Seen[Length++] = Field;
			Field = *reinterpret_cast<const uint8_t* const*>(Field + NextOffset);
		}
		return Field ? -1 : Length;
	};

	std::vector<int32_t> ChainValidatedCandidates;
	for (const int32_t Candidate : Candidates)
	{
		const auto* ColorField = *reinterpret_cast<const uint8_t* const*>(Structs[0] + Candidate);
		const auto* GuidField = *reinterpret_cast<const uint8_t* const*>(Structs[1] + Candidate);
		const auto* VectorField = *reinterpret_cast<const uint8_t* const*>(Structs[2] + Candidate);
		for (int32_t NextOffset = sizeof(void*); NextOffset < 0x180; NextOffset += sizeof(void*))
		{
			const int32_t ColorLength = ChainLength(ColorField, NextOffset);
			const int32_t GuidLength = ChainLength(GuidField, NextOffset);
			const int32_t VectorLength = ChainLength(VectorField, NextOffset);
			if (ColorLength > 0 && GuidLength > 0 && VectorLength > 0)
				std::cerr << std::format("Discovery FField topology candidate: UStruct +0x{:X}, Next +0x{:X}, lengths {}/{}/{}\n", Candidate, NextOffset, ColorLength, GuidLength, VectorLength);
			if (ColorLength == 4 && GuidLength == 4 && VectorLength == 3)
			{
				ChainValidatedCandidates.push_back(Candidate);
				break;
			}
		}
	}
	Candidates = std::move(ChainValidatedCandidates);

	if (Candidates.empty())
	{
		std::cerr << std::format("Discovery ChildProperties structural scan matched {} offsets in bounded UStruct range +0x{:X}..+0x{:X}", Candidates.size(), SearchStart, SearchEnd);
		for (const int32_t Offset : Candidates)
			std::cerr << std::format(" +0x{:X}", Offset);
		std::cerr << '\n';
		return OffsetNotFound;
	}

	DiscoveryChildPropertiesCandidates = Candidates;
	std::cerr << std::format("Discovery ChildProperties retained {} structural candidates for semantic resolution; provisional head +0x{:X}\n", Candidates.size(), Candidates[0]);
	return Candidates[0];
}

int32_t OffsetFinder::FindStructSizeOffset()
{
	std::vector<std::pair<void*, int32_t>> Infos;

	Infos.push_back({ ObjectArray::FindObjectFast("Color").GetAddress(), 0x04 });
	Infos.push_back({ ObjectArray::FindObjectFast("Guid").GetAddress(), 0x10 });

	return FindOffset(Infos);
}

int32_t OffsetFinder::FindMinAlignmentOffset()
{
	std::vector<std::pair<void*, int16_t>> Infos;

	if (Discovery::Enabled)
	{
		Infos.push_back({ ObjectArray::FindObjectFast("Guid").GetAddress(), 0x04 });
		Infos.push_back({ ObjectArray::FindObjectFast("Transform").GetAddress(), 0x10 });
		const int32_t SearchStart = Align(Off::UStruct::SuperStruct + static_cast<int32_t>(sizeof(void*)), 2);
		const int32_t SearchEnd = Off::UClass::CastFlags > SearchStart ? Off::UClass::CastFlags : 0x300;
		const int32_t Offset = FindOffset<2>(Infos, SearchStart, SearchEnd);
		if (Offset != OffsetNotFound)
		{
			const void* Color = ObjectArray::FindObjectFast("Color").GetAddress();
			const int16_t ColorAlignment = Color ? *reinterpret_cast<const int16_t*>(static_cast<const uint8_t*>(Color) + Offset) : 0;
			std::cerr << std::format("Discovery UStruct minimum alignment recovered from Guid/Transform at +0x{:X}; Color reports 0x{:X}\n", Offset, ColorAlignment);
		}
		return Offset;
	}

	Infos.push_back({ ObjectArray::FindObjectFast("Transform").GetAddress(), 0x10 });

	if constexpr (Platform::Is32Bit())
	{
		Infos.push_back({ ObjectArray::FindObjectFast("InterpCurveLinearColor").GetAddress(), 0x04 });
	}
	else
	{
		Infos.push_back({ ObjectArray::FindObjectFast("PlayerController").GetAddress(), 0x8 });
	}

	return FindOffset(Infos);
}

int32_t OffsetFinder::FindStructBaseChainOffset()
{
	/* FStructBaseChain was added in UE5.3, which doesn't support 32-bit anymore and always uses FProperty. */
	if (Platform::Is32Bit() || !Settings::Internal::bUseFProperty)
		return OffsetNotFound;

	// UStruct inherits from FStructBaseChain, so the members of base chain should come right after UField

	UEStruct Struct = ObjectArray::FindStructFast("Struct");
	if (!Struct)
		Struct = ObjectArray::FindStructFast("struct");

	const int32 UStructStart = Struct.GetSuper().GetStructSize();
	const int32 UStructEnd = UStructStart + Struct.GetStructSize();

	// If the members of UStruct come right after UField, FStructBaseChain either doesn't exist or is empty
	if (UStructStart == Off::UStruct::ChildProperties || UStructStart == Off::UStruct::Children)
		return OffsetNotFound;

	auto CountSuperClasses = [](const UEStruct InStruct) -> int32
	{
		int32 Count = 0;

		UEStruct CurrentSuper = InStruct.GetSuper();
		while (CurrentSuper)
		{
			Count++;
			CurrentSuper = CurrentSuper.GetSuper();
		}

		return Count;
	};

	/* Pair<UStruct, NumSuperClasses> */
	std::vector<std::pair<void*, int32_t>> Infos;

	UEStruct APlayerController = ObjectArray::FindClassFast("PlayerController");
	UEStruct AActor = ObjectArray::FindClassFast("Actor");

	Infos.push_back({ Struct.GetAddress(),              CountSuperClasses(Struct)            });
	Infos.push_back({ APlayerController.GetAddress(),   CountSuperClasses(APlayerController) });
	Infos.push_back({ AActor.GetAddress(),              CountSuperClasses(AActor)            });

	constexpr auto FStructBaseChainSize = Align(sizeof(void*) + sizeof(int32_t), alignof(void*));

	// FStructBaseChain::NumStructBasesInChainMinusOne is at offset 0x8, after a pointer
	return FindOffset(Infos, UStructStart, UStructEnd - FStructBaseChainSize) - sizeof(void*);
}

/* UFunction */
int32_t OffsetFinder::FindFunctionFlagsOffset()
{
	std::vector<std::pair<void*, EFunctionFlags>> Infos;

	Infos.push_back({ ObjectArray::FindObjectFast("WasInputKeyJustPressed", EClassCastFlags::Function).GetAddress(), EFunctionFlags::Final | EFunctionFlags::Native | EFunctionFlags::Public | EFunctionFlags::BlueprintCallable | EFunctionFlags::BlueprintPure | EFunctionFlags::Const });
	Infos.push_back({ ObjectArray::FindObjectFast("ToggleSpeaking", EClassCastFlags::Function).GetAddress(), EFunctionFlags::Exec | EFunctionFlags::Native | EFunctionFlags::Public });
	Infos.push_back({ ObjectArray::FindObjectFast("SwitchLevel", EClassCastFlags::Function).GetAddress(), EFunctionFlags::Exec | EFunctionFlags::Native | EFunctionFlags::Public });

	// Some games don't have APlayerController::SwitchLevel(), so we replace it with APlayerController::FOV() which has the same FunctionFlags
	if (Infos[2].first == nullptr)
		Infos[2].first = ObjectArray::FindObjectFast("FOV", EClassCastFlags::Function).GetAddress();

	if (Discovery::Enabled)
	{
		if (Off::UFunction::FunctionFlags == OffsetNotFound)
			return OffsetNotFound;

		bool HasKey = false;
		uint32_t CommonKey = 0;
		for (const auto& [Object, ExpectedFlags] : Infos)
		{
			if (!Object)
				return OffsetNotFound;

			const uint32_t EncodedFlags = *reinterpret_cast<const uint32_t*>(static_cast<const uint8_t*>(Object) + Off::UFunction::FunctionFlags);
			const uint32_t CandidateKey = EncodedFlags ^ static_cast<uint32_t>(ExpectedFlags);
			if (!HasKey)
			{
				CommonKey = CandidateKey;
				HasKey = true;
			}
			else if (CandidateKey != CommonKey)
			{
				return OffsetNotFound;
			}
		}

		Discovery::FunctionFlagsXorKey = CommonKey;
		std::cerr << std::format("Discovery UFunction::FunctionFlags validated at +0x{:X} with XOR key 0x{:08X}\n", Off::UFunction::FunctionFlags, CommonKey);
		return Off::UFunction::FunctionFlags;
	}

	const int32 Ret = FindOffset(Infos);

	if (Ret != OffsetNotFound)
	{
		if (Discovery::Enabled)
			Discovery::FunctionFlagsXorKey = 0;
		return Ret;
	}

	for (auto& [_, Flags] : Infos)
		Flags |= EFunctionFlags::RequiredAPI;

	const int32_t RequiredApiRet = FindOffset(Infos);
	if (Discovery::Enabled && RequiredApiRet != OffsetNotFound)
		Discovery::FunctionFlagsXorKey = static_cast<uint32_t>(EFunctionFlags::RequiredAPI);
	if (Discovery::Enabled && RequiredApiRet == OffsetNotFound)
	{
		std::cerr << "Discovery UFunction flag candidates:\n";
		for (const auto& [Object, ExpectedFlags] : Infos)
		{
			std::cerr << std::format("  function=0x{:X} expected=0x{:08X}\n", reinterpret_cast<uintptr_t>(Object), static_cast<uint32_t>(ExpectedFlags));
			if (!Object)
				continue;
			for (int32_t Offset = 0x130; Offset < 0x260; Offset += 0x10)
			{
				const auto* Values = reinterpret_cast<const uint32_t*>(static_cast<const uint8_t*>(Object) + Offset);
				std::cerr << std::format("    +0x{:03X}: {:08X} {:08X} {:08X} {:08X}\n", Offset, Values[0], Values[1], Values[2], Values[3]);
			}
		}
	}

	return RequiredApiRet;
}

int32_t OffsetFinder::FindFunctionNativeFuncOffset()
{
	std::vector<std::pair<void*, EFunctionFlags>> Infos;

	uintptr_t WasInputKeyJustPressed = reinterpret_cast<uintptr_t>(ObjectArray::FindObjectFast("WasInputKeyJustPressed", EClassCastFlags::Function).GetAddress());
	uintptr_t ToggleSpeaking = reinterpret_cast<uintptr_t>(ObjectArray::FindObjectFast("ToggleSpeaking", EClassCastFlags::Function).GetAddress());
	uintptr_t SwitchLevel_Or_FOV = reinterpret_cast<uintptr_t>(ObjectArray::FindObjectFast("SwitchLevel", EClassCastFlags::Function).GetAddress());

	// Some games don't have APlayerController::SwitchLevel(), so we replace it with APlayerController::FOV() which has the same FunctionFlags
	if (SwitchLevel_Or_FOV == NULL)
		SwitchLevel_Or_FOV = reinterpret_cast<uintptr_t>(ObjectArray::FindObjectFast("FOV", EClassCastFlags::Function).GetAddress());

	if (!WasInputKeyJustPressed || !ToggleSpeaking || !SwitchLevel_Or_FOV)
		return OffsetNotFound;

	for (int i = 0x30; i < 0x300; i += sizeof(void*))
	{
		if (Platform::IsAddressInProcessRange(*reinterpret_cast<uintptr_t*>(WasInputKeyJustPressed + i)) &&
			Platform::IsAddressInProcessRange(*reinterpret_cast<uintptr_t*>(ToggleSpeaking + i)) && Platform::IsAddressInProcessRange(*reinterpret_cast<uintptr_t*>(SwitchLevel_Or_FOV + i)))
			return i;
	}

	return 0x0;
}

/* UClass */
int32_t OffsetFinder::FindCastFlagsOffset()
{
	std::vector<std::pair<void*, EClassCastFlags>> Infos;

	Infos.push_back({ ObjectArray::FindObjectFast("Actor").GetAddress(), EClassCastFlags::Actor });
	Infos.push_back({ ObjectArray::FindObjectFast("Class").GetAddress(), EClassCastFlags::Field | EClassCastFlags::Struct | EClassCastFlags::Class });
	if (Discovery::Enabled)
	{
		Infos.push_back({ ObjectArray::FindObjectFast("Struct").GetAddress(), EClassCastFlags::Field | EClassCastFlags::Struct });
		Infos.push_back({ ObjectArray::FindObjectFast("Field").GetAddress(), EClassCastFlags::Field });
		for (const auto& [Object, _] : Infos)
		{
			if (!Object)
				return OffsetNotFound;
		}

		std::vector<std::pair<int32_t, uint64_t>> Candidates;
		for (int32_t Offset = 0xA0; Offset < 0x300; Offset += sizeof(uint64_t))
		{
			const uint64_t FirstRaw = *reinterpret_cast<const uint64_t*>(static_cast<const uint8_t*>(Infos[0].first) + Offset);
			const uint64_t CandidateKey = FirstRaw ^ static_cast<uint64_t>(Infos[0].second);
			bool MatchesAll = true;
			for (const auto& [Object, ExpectedFlags] : Infos)
			{
				const uint64_t Raw = *reinterpret_cast<const uint64_t*>(static_cast<const uint8_t*>(Object) + Offset);
				if ((Raw ^ CandidateKey) != static_cast<uint64_t>(ExpectedFlags))
				{
					MatchesAll = false;
					break;
				}
			}
			if (MatchesAll)
				Candidates.push_back({ Offset, CandidateKey });
		}

		if (Candidates.size() != 1)
		{
			std::cerr << std::format("Discovery UClass cast-flag XOR scan matched {} candidate layouts\n", Candidates.size());
			return OffsetNotFound;
		}

		Discovery::ClassCastFlagsXorKey = Candidates[0].second;
		std::cerr << std::format("Discovery UClass cast flags recovered at +0x{:X} with XOR key 0x{:016X}\n", Candidates[0].first, Candidates[0].second);
		return Candidates[0].first;
	}

	return FindOffset(Infos);
}

int32_t OffsetFinder::FindDefaultObjectOffset()
{
	std::vector<std::pair<void*, void*>> Infos;

	Infos.push_back({ ObjectArray::FindClassFast("Object").GetAddress(), ObjectArray::FindObjectFast("Default__Object").GetAddress() });
	Infos.push_back({ ObjectArray::FindClassFast("Field").GetAddress(), ObjectArray::FindObjectFast("Default__Field").GetAddress() });

	return FindOffset(Infos, 0x28, 0x200);
}

int32_t OffsetFinder::FindImplementedInterfacesOffset()
{
	UEClass Interface_AssetUserDataClass = ObjectArray::FindClassFast("Interface_AssetUserData");

	const uint8_t* ActorComponentClassPtr = reinterpret_cast<const uint8_t*>(ObjectArray::FindClassFast("ActorComponent").GetAddress());

	for (int i = Off::UClass::ClassDefaultObject; i <= (0x350 - 0x10); i += sizeof(void*))
	{
		const auto& ActorArray = *reinterpret_cast<const TArray<FImplementedInterface>*>(ActorComponentClassPtr + i);

		if (ActorArray.IsValid() && !Platform::IsBadReadPtr(ActorArray.GetDataPtr()))
		{
			if (ActorArray[0].InterfaceClass == Interface_AssetUserDataClass)
				return i;
		}
	}

	return OffsetNotFound;
}

/* Property */
int32_t OffsetFinder::FindElementSizeOffset()
{
	std::vector<std::pair<void*, int32_t>> Infos;

	UEStruct Guid = ObjectArray::FindStructFast("Guid");

	Infos.push_back({ Guid.FindMember("A").GetAddress(), 0x04 });
	Infos.push_back({ Guid.FindMember("C").GetAddress(), 0x04 });
	Infos.push_back({ Guid.FindMember("D").GetAddress(), 0x04 });

	return FindOffset(Infos);
}

int32_t OffsetFinder::FindArrayDimOffset()
{
	std::vector<std::pair<void*, int32_t>> Infos;

	UEStruct Guid = ObjectArray::FindStructFast("Guid");

	Infos.push_back({ Guid.FindMember("A").GetAddress(), 0x01 });
	Infos.push_back({ Guid.FindMember("C").GetAddress(), 0x01 });
	Infos.push_back({ Guid.FindMember("D").GetAddress(), 0x01 });

	const int32_t MinOffset = Off::Property::ElementSize - 0x10;
	const int32_t MaxOffset = Off::Property::ElementSize + 0x10;

	return FindOffset(Infos, MinOffset, MaxOffset);
}

int32_t OffsetFinder::FindPropertyFlagsOffset()
{
	std::vector<std::pair<void*, EPropertyFlags>> Infos;


	UEStruct Guid = ObjectArray::FindStructFast("Guid");
	UEStruct Color = ObjectArray::FindStructFast("Color");

	constexpr EPropertyFlags GuidMemberFlags = EPropertyFlags::Edit | EPropertyFlags::ZeroConstructor | EPropertyFlags::SaveGame | EPropertyFlags::IsPlainOldData | EPropertyFlags::NoDestructor | EPropertyFlags::HasGetValueTypeHash;
	constexpr EPropertyFlags ColorMemberFlags = EPropertyFlags::Edit | EPropertyFlags::BlueprintVisible | EPropertyFlags::ZeroConstructor | EPropertyFlags::SaveGame | EPropertyFlags::IsPlainOldData | EPropertyFlags::NoDestructor | EPropertyFlags::HasGetValueTypeHash;

	Infos.push_back({ Guid.FindMember("A").GetAddress(), GuidMemberFlags });
	Infos.push_back({ Color.FindMember("R").GetAddress(), ColorMemberFlags });

	if (Infos[1].first == nullptr) [[unlikely]]
		Infos[1].first = Color.FindMember("r").GetAddress();

	if (Discovery::Enabled)
	{
		Infos.push_back({ Guid.FindMember("C").GetAddress(), GuidMemberFlags });
		Infos.push_back({ Guid.FindMember("D").GetAddress(), GuidMemberFlags });
		Infos.push_back({ Color.FindMember("G").GetAddress(), ColorMemberFlags });
		Infos.push_back({ Color.FindMember("B").GetAddress(), ColorMemberFlags });

		for (const auto& [Object, _] : Infos)
		{
			if (!Object)
				return OffsetNotFound;
		}

		std::vector<std::pair<int32_t, uint64_t>> Candidates;
		for (int32_t Offset = 0x40; Offset < 0x180; Offset += sizeof(uint64_t))
		{
			const uint64_t FirstRawFlags = *reinterpret_cast<const uint64_t*>(static_cast<const uint8_t*>(Infos[0].first) + Offset);
			const uint64_t CandidateKey = FirstRawFlags ^ static_cast<uint64_t>(Infos[0].second);
			bool MatchesAll = true;
			for (const auto& [Object, ExpectedFlags] : Infos)
			{
				const uint64_t RawFlags = *reinterpret_cast<const uint64_t*>(static_cast<const uint8_t*>(Object) + Offset);
				if ((RawFlags ^ CandidateKey) != static_cast<uint64_t>(ExpectedFlags))
				{
					MatchesAll = false;
					break;
				}
			}

			if (MatchesAll)
				Candidates.push_back({ Offset, CandidateKey });
		}

		if (Candidates.size() != 1)
			return OffsetNotFound;

		Discovery::PropertyFlagsXorKey = Candidates[0].second;
		std::cerr << std::format("Discovery FProperty flags recovered at +0x{:X} with XOR key 0x{:016X}\n", Candidates[0].first, Candidates[0].second);
		return Candidates[0].first;
	}

	int FlagsOffset = FindOffset(Infos);

	// Same flags without AccessSpecifier
	if (FlagsOffset == OffsetNotFound)
	{
		Infos[0].second |= EPropertyFlags::NativeAccessSpecifierPublic;
		Infos[1].second |= EPropertyFlags::NativeAccessSpecifierPublic;

		FlagsOffset = FindOffset(Infos);
	}

	return FlagsOffset;
}

int32_t OffsetFinder::FindOffsetInternalOffset()
{
	std::vector<std::pair<void*, int32_t>> Infos;

	const UEStruct Color = ObjectArray::FindStructFast("Color");
	const UEStruct Guid = ObjectArray::FindStructFast("Guid");

	Infos.push_back({ Color.FindMember("B").GetAddress(), 0x00 });
	Infos.push_back({ Color.FindMember("G").GetAddress(), 0x01 });
	Infos.push_back({ Guid.FindMember("C").GetAddress(), 0x08 });

	// Thanks to the ue5 dev who decided FColor::R should be spelled FColor::r
	if (Infos[2].first == nullptr) [[unlikely]]
		Infos[2].first = Color.FindMember("r").GetAddress();

	if (!Discovery::Enabled)
		return FindOffset(Infos);

	if (!Infos[0].first || !Infos[1].first || !Infos[2].first)
		return OffsetNotFound;

	std::vector<std::pair<int32_t, uint32_t>> Candidates;
	for (int32_t Offset = 0x40; Offset < 0x180; Offset += sizeof(uint32_t))
	{
		const uint32_t Key = *reinterpret_cast<const uint32_t*>(static_cast<const uint8_t*>(Infos[0].first) + Offset);
		bool bMatches = true;
		for (const auto& [Object, Expected] : Infos)
		{
			const uint32_t Raw = *reinterpret_cast<const uint32_t*>(static_cast<const uint8_t*>(Object) + Offset);
			const uint32_t Decoded = _byteswap_ulong(Raw ^ Key);
			if (Decoded != static_cast<uint32_t>(Expected))
			{
				bMatches = false;
				break;
			}
		}

		if (bMatches)
			Candidates.emplace_back(Offset, Key);
	}

	if (Candidates.size() != 1)
	{
		std::cerr << std::format("Discovery FProperty offset decoder matched {} candidate layouts\n", Candidates.size());
		return OffsetNotFound;
	}

	Discovery::PropertyOffsetXorKey = Candidates[0].second;
	std::cerr << std::format("Discovery FProperty offset decoder recovered XOR key 0x{:08X}\n", Discovery::PropertyOffsetXorKey);
	return Candidates[0].first;
}

/* BoolProperty */
int32_t OffsetFinder::FindBoolPropertyBaseOffset()
{
	if (Discovery::Enabled)
	{
		std::vector<const uint8_t*> Properties;
		for (const UEProperty Property : AllFieldIterator())
		{
			if (!Property || !Property.IsA(EClassCastFlags::BoolProperty))
				continue;
			Properties.push_back(static_cast<const uint8_t*>(Property.GetAddress()));
			if (Properties.size() == 64)
				break;
		}

		if (Properties.size() < 16)
		{
			std::cerr << std::format("Discovery FBoolProperty structural scan found only {} samples\n", Properties.size());
			return OffsetNotFound;
		}

		auto IsPowerOfTwo = [](const uint8_t Value)
		{
			return Value && !(Value & (Value - 1));
		};
		std::vector<int32_t> Candidates;
		for (int32_t Offset = Align(Off::Property::ElementSize + static_cast<int32_t>(sizeof(int32_t)), 4); Offset < 0x180; ++Offset)
		{
			bool MatchesAll = true;
			for (const uint8_t* Property : Properties)
			{
				const uint8_t FieldSize = Property[Offset];
				const uint8_t ByteOffset = Property[Offset + 1];
				const uint8_t ByteMask = Property[Offset + 2];
				const uint8_t FieldMask = Property[Offset + 3];
				const bool ValidFieldSize = FieldSize == 1 || FieldSize == 2 || FieldSize == 4 || FieldSize == 8;
				if (!ValidFieldSize || ByteOffset >= FieldSize || !IsPowerOfTwo(ByteMask) || (FieldMask != 0xFF && (!IsPowerOfTwo(FieldMask) || FieldMask != ByteMask)))
				{
					MatchesAll = false;
					break;
				}
			}
			if (MatchesAll)
				Candidates.push_back(Offset);
		}

		if (Candidates.size() != 1)
		{
			std::cerr << std::format("Discovery FBoolProperty structural scan matched {} candidate bases", Candidates.size());
			for (const int32_t Offset : Candidates)
				std::cerr << std::format(" +0x{:X}", Offset);
			std::cerr << '\n';
			return OffsetNotFound;
		}

		std::cerr << std::format("Discovery FBoolProperty base recovered structurally from {} fields at +0x{:X}\n", Properties.size(), Candidates[0]);
		return Candidates[0];
	}

	std::vector<std::pair<void*, uint8_t>> Infos;

	UEClass Engine = ObjectArray::FindClassFast("Engine");
	Infos.push_back({ Engine.FindMember("bIsOverridingSelectedColor").GetAddress(), 0xFF });
	Infos.push_back({ Engine.FindMember("bEnableOnScreenDebugMessagesDisplay").GetAddress(), 0b00000010 });
	Infos.push_back({ ObjectArray::FindClassFast("PlayerController").FindMember("bAutoManageActiveCameraTarget").GetAddress(), 0xFF });

	const int32_t MinimumOffset = Discovery::Enabled ? Off::ObjectProperty::PropertyClass : Off::Property::Offset_Internal;
	return (FindOffset<1>(Infos, MinimumOffset) - 0x3);
}

/* ObjectPrperty */
int32_t OffsetFinder::FindObjectPropertyClassOffset()
{
	std::vector<std::pair<void*, void*>> Infos;

	const UEClass Controller = ObjectArray::FindClassFast("Controller");
	Infos.push_back({ Controller.FindMember("PlayerState").GetAddress(), ObjectArray::FindClassFast("PlayerState").GetAddress() });
	Infos.push_back({ Controller.FindMember("Pawn").GetAddress(), ObjectArray::FindClassFast("Pawn").GetAddress() });
	Infos.push_back({ ObjectArray::FindClassFast("World").FindMember("PersistentLevel").GetAddress(), ObjectArray::FindClassFast("Level").GetAddress() });

	return FindOffset(Infos, Off::Property::Offset_Internal);
}

/* EnumProperty */
int32_t OffsetFinder::FindEnumPropertyBaseOffset()
{
	std::vector<std::pair<void*, const void*>> Infos;

	const void* ComponentCreationMethod = ObjectArray::FindObjectFast("EComponentCreationMethod", EClassCastFlags::Enum).GetAddress();
	const void* AutoPossessAI = ObjectArray::FindObjectFast("EAutoPossessAI", EClassCastFlags::Enum).GetAddress();

	if (!ComponentCreationMethod || !AutoPossessAI)
		return OffsetNotFound;

	void* CreationMethodMember = ObjectArray::FindClassFast("ActorComponent").FindMember("CreationMethod", EClassCastFlags::EnumProperty).GetAddress();
	void* AutoPossessAIMember = ObjectArray::FindClassFast("Pawn").FindMember("AutoPossessAI", EClassCastFlags::EnumProperty).GetAddress();

	// UE4.15 and below don't have EnumProperty
	if (!CreationMethodMember || !AutoPossessAIMember)
		return OffsetNotFound;

	Infos.push_back({ CreationMethodMember, ComponentCreationMethod });
	Infos.push_back({ AutoPossessAIMember , AutoPossessAI });

	// EnumProperty::Enum is the 2nd member after 'NumericProperty UnderlayingType'
	return FindOffset(Infos, Off::Property::Offset_Internal) - sizeof(void*);
}

/* ByteProperty */
int32_t OffsetFinder::FindBytePropertyEnumOffset()
{
	std::vector<std::pair<void*, const void*>> Infos;

	const void* CollisionResponseEnum = ObjectArray::FindObjectFast("ECollisionResponse", EClassCastFlags::Enum).GetAddress();

	const UEStruct CollisionResponseContainer = ObjectArray::FindStructFast("CollisionResponseContainer");

	if (!CollisionResponseEnum || !CollisionResponseContainer)
		return OffsetNotFound;

	const void* GameTraceChannel1 = CollisionResponseContainer.FindMember("GameTraceChannel1", EClassCastFlags::ByteProperty).GetAddress();
	const void* GameTraceChannel2 = CollisionResponseContainer.FindMember("GameTraceChannel2", EClassCastFlags::ByteProperty).GetAddress();

	if (!GameTraceChannel1 || !GameTraceChannel2)
		return OffsetNotFound;

	Infos.push_back({ const_cast<void*>(GameTraceChannel1), CollisionResponseEnum });
	Infos.push_back({ const_cast<void*>(GameTraceChannel2), CollisionResponseEnum });

	return FindOffset(Infos, Off::Property::Offset_Internal);
}

/* StructProperty */
int32_t OffsetFinder::FindStructPropertyStructOffset()
{
	std::vector<std::pair<void*, const void*>> Infos;

	const void* VectorClass = ObjectArray::FindStructFast("Vector").GetAddress();

	if (VectorClass == nullptr)
		VectorClass = ObjectArray::FindClassFast("vector").GetAddress();

	const UEStruct TwoVectorsStruct = ObjectArray::FindStructFast("TwoVectors");

	if (!VectorClass || !TwoVectorsStruct)
		return OffsetNotFound;

	const void* v1 = TwoVectorsStruct.FindMember("v1", EClassCastFlags::StructProperty).GetAddress();
	const void* v2 = TwoVectorsStruct.FindMember("v2", EClassCastFlags::StructProperty).GetAddress();

	if (!v1 || !v2)
		return OffsetNotFound;

	Infos.push_back({ const_cast<void*>(v1), VectorClass });
	Infos.push_back({ const_cast<void*>(v2), VectorClass });

	return FindOffset(Infos, Off::Property::Offset_Internal);
}

/* DelegateProperty */
int32_t OffsetFinder::FindDelegatePropertySignatureFunctionOffset()
{
	if (Discovery::Enabled)
		return FindDiscoveryObjectPropertyPointer(EClassCastFlags::DelegateProperty, EClassCastFlags::Function, Off::InSDK::Properties::PropertySize, "FDelegateProperty::SignatureFunction");

	std::vector<std::pair<void*, const void*>> Infos;

	const void* DelegateSignature = ObjectArray::FindObjectFast("TimerDynamicDelegate__DelegateSignature", EClassCastFlags::Function).GetAddress();

	const UEStruct TwoVectorsStruct = ObjectArray::FindStructFast("TwoVectors");

	if (!DelegateSignature || !TwoVectorsStruct)
		return OffsetNotFound;

	const void* Delegate1 = ObjectArray::FindObjectFast<UEFunction>("K2_GetTimerElapsedTimeDelegate", EClassCastFlags::Function).FindMember("Delegate", EClassCastFlags::DelegateProperty).GetAddress();
	const void* Delegate2 = ObjectArray::FindObjectFast<UEFunction>("K2_GetTimerRemainingTimeDelegate", EClassCastFlags::Function).FindMember("Delegate", EClassCastFlags::DelegateProperty).GetAddress();

	if (!Delegate1 || !Delegate2)
		return OffsetNotFound;

	Infos.push_back({ const_cast<void*>(Delegate1), DelegateSignature });
	Infos.push_back({ const_cast<void*>(Delegate2), DelegateSignature });

	return FindOffset(Infos, Off::Property::Offset_Internal);
}

int32_t OffsetFinder::FindMulticastDelegatePropertySignatureFunctionOffset()
{
	if (Discovery::Enabled)
		return FindDiscoveryObjectPropertyPointer(EClassCastFlags::MulticastInlineDelegateProperty, EClassCastFlags::Function, Off::InSDK::Properties::PropertySize, "FMulticastDelegateProperty::SignatureFunction");

	return Off::DelegateProperty::SignatureFunction;
}

/* ArrayProperty */
int32_t OffsetFinder::FindInnerTypeOffset(const int32 PropertySize)
{
	if (!Settings::Internal::bUseFProperty)
		return PropertySize;
	if (Discovery::Enabled)
		return FindDiscoveryDerivedPropertyPointers(EClassCastFlags::ArrayProperty, 1, PropertySize, "FArrayProperty::Inner");

	if (const UEProperty Property = ObjectArray::FindClassFast("GameViewportClient").FindMember("DebugProperties", EClassCastFlags::ArrayProperty))
	{
		void* AddressToCheck = *reinterpret_cast<void* const*>(reinterpret_cast<const uint8*>(Property.GetAddress()) + PropertySize);

		if (Platform::IsBadReadPtr(AddressToCheck))
			return PropertySize + sizeof(void*);
	}

	return PropertySize;
}

/* SetProperty */
int32_t OffsetFinder::FindSetPropertyBaseOffset(const int32 PropertySize)
{
	if (!Settings::Internal::bUseFProperty)
		return PropertySize;
	if (Discovery::Enabled)
		return FindDiscoveryDerivedPropertyPointers(EClassCastFlags::SetProperty, 1, PropertySize, "FSetProperty::ElementProp");

	if (const auto Object = ObjectArray::FindStructFast("LevelCollection").FindMember("Levels", EClassCastFlags::SetProperty))
	{
		const void* AddressToCheck = *reinterpret_cast<void* const*>(reinterpret_cast<const uint8*>(Object.GetAddress()) + PropertySize);

		if (Platform::IsBadReadPtr(AddressToCheck))
			return PropertySize + sizeof(void*);
	}

	return PropertySize;
}


/* MapProperty */
int32_t OffsetFinder::FindMapPropertyBaseOffset(const int32 PropertySize)
{
	if (!Settings::Internal::bUseFProperty)
		return PropertySize;
	if (Discovery::Enabled)
		return FindDiscoveryDerivedPropertyPointers(EClassCastFlags::MapProperty, 2, PropertySize, "FMapProperty::Key/Value");

	if (const auto Object = ObjectArray::FindClassFast("UserDefinedEnum").FindMember("DisplayNameMap", EClassCastFlags::MapProperty))
	{
		const void* AddressToCheck = *reinterpret_cast<void* const*>(reinterpret_cast<const uint8*>(Object.GetAddress()) + PropertySize);

		if (Platform::IsBadReadPtr(AddressToCheck))
			return PropertySize + sizeof(void*);
	}

	return PropertySize;
}

/* InSDK -> ULevel */
int32_t OffsetFinder::FindLevelActorsOffset()
{
	UEObject Level = nullptr;
	uintptr_t Lvl = 0x0;

	for (auto Obj : ObjectArray())
	{
		if (Obj.HasAnyFlags(EObjectFlags::ClassDefaultObject) || !Obj.IsA(EClassCastFlags::Level))
			continue;

		Level = Obj;
		Lvl = reinterpret_cast<uintptr_t>(Obj.GetAddress());
		break;
	}

	if (Lvl == 0x0)
		return OffsetNotFound;

	/*
	class ULevel : public UObject
	{
		FURL URL;
		TArray<AActor*> Actors;
		TArray<AActor*> GCActors;
	};

	SearchStart = sizeof(UObject) + sizeof(FURL)
	SearchEnd = offsetof(ULevel, OwningWorld)
	*/
	UEClass UObjectClass = ObjectArray::FindClassFast("Object");
	if (!UObjectClass)
		UObjectClass = ObjectArray::FindClassFast("object");

	const UEStruct FURLStruct = ObjectArray::FindObjectFast<UEStruct>("URL", EClassCastFlags::Struct);

	const UEProperty Level_OwningWorldProperty = Level.GetClass().FindMember("OwningWorld");

	if (!UObjectClass || !FURLStruct || !Level_OwningWorldProperty)
		return OffsetNotFound;

	const int32 SearchStart = UObjectClass.GetStructSize() + FURLStruct.GetStructSize();
	const int32 SearchEnd = Level_OwningWorldProperty.GetOffset();

	for (int i = SearchStart; i <= (SearchEnd - 0x10); i += sizeof(void*))
	{
		const TArray<void*>& ActorArray = *reinterpret_cast<TArray<void*>*>(Lvl + i);

		if (ActorArray.IsValid() && !Platform::IsBadReadPtr(ActorArray.GetDataPtr()))
		{
			return i;
		}
	}

	return OffsetNotFound;
}


/* InSDK -> UDataTable */
int32_t OffsetFinder::FindDatatableRowMapOffset()
{
	const UEClass DataTable = ObjectArray::FindClassFast("DataTable");

	constexpr int32 UObjectOuterSize = sizeof(void*);
	constexpr int32 RowStructSize = sizeof(void*);

	if (!DataTable)
	{
		std::cerr << "\nDumper-7: [DataTable] Couldn't find \"DataTable\" class, assuming default layout.\n" << std::endl;
		return (Off::UObject::Outer + UObjectOuterSize + RowStructSize);
	}

	UEProperty RowStructProp = DataTable.FindMember("RowStruct", EClassCastFlags::ObjectProperty);

	if (!RowStructProp)
	{
		std::cerr << "\nDumper-7: [DataTable] Couldn't find \"RowStruct\" property, assuming default layout.\n" << std::endl;
		return (Off::UObject::Outer + UObjectOuterSize + RowStructSize);
	}

	return RowStructProp.GetOffset() + RowStructProp.GetSize();
}
