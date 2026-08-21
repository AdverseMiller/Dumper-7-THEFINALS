
#include <iostream>
#include <fstream>
#include <format>
#include <filesystem>
#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>

#include "Unreal/ObjectArray.h"
#include "OffsetFinder/Offsets.h"
#include "Utils.h"

#include "Platform.h"
#include "Unreal/Discovery.h"


namespace fs = std::filesystem;

namespace
{
	bool bUseDiscoveryObjectArray = false;
	bool bUseDiscoveredChunks = false;
	std::vector<std::uint8_t*> DiscoveredChunks;
	std::int32_t DiscoveredNum = 0;
	std::uint32_t DiscoveredInternalIndexOffset = 0x0C;

	struct DiscoveredObjectArray
	{
		std::vector<std::uint8_t*> Chunks;
		std::uint32_t ItemSize = 0;
		std::uint32_t InternalIndexOffset = 0;
		std::uint32_t ElementsPerChunk = 0;
		std::int32_t Num = 0;
		std::uintptr_t ChunkTableAddress = 0;
	};

	bool TryReadMemory(const void* Address, void* Destination, const std::size_t Size)
	{
		SIZE_T BytesRead = 0;
		return ReadProcessMemory(GetCurrentProcess(), Address, Destination, Size, &BytesRead) && BytesRead == Size;
	}

	template<typename T>
	bool TryReadValue(const void* Address, T& Value)
	{
		return TryReadMemory(Address, &Value, sizeof(Value));
	}

	std::uintptr_t GetModuleSize(const std::uintptr_t ModuleBase)
	{
		const auto* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(ModuleBase);
		if (Platform::IsBadReadPtr(DosHeader) || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		const auto* NtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(ModuleBase + DosHeader->e_lfanew);
		if (Platform::IsBadReadPtr(NtHeaders) || NtHeaders->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		return NtHeaders->OptionalHeader.SizeOfImage;
	}

	bool IsPlausibleObject(const std::uint8_t* Object, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd)
	{
		const std::uintptr_t ObjectAddress = reinterpret_cast<std::uintptr_t>(Object);
		if (ObjectAddress < 0x10000 || ObjectAddress > 0x00007FFFFFFFFFFF || (ObjectAddress & (alignof(void*) - 1)) != 0)
			return false;

		const void* Vft = nullptr;
		if (!TryReadValue(Object, Vft))
			return false;

		const std::uintptr_t VftAddress = reinterpret_cast<std::uintptr_t>(Vft);
		return VftAddress >= ModuleBase && VftAddress < ModuleEnd;
	}

	int ScoreObjectChunk(const std::uint8_t* Chunk, const std::uint32_t ChunkIndex, const std::uint32_t ItemSize, const std::uint32_t InternalIndexOffset, const std::uint32_t ElementsPerChunk, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd)
	{
		constexpr std::uint32_t SequentialSampleCount = 0x200;
		constexpr std::uint32_t DistributedSampleCount = 0x400;
		int Matches = 0;
		int Mismatches = 0;

		if (Platform::IsBadReadPtr(Chunk))
			return -1;

		const auto ScoreIndex = [&](const std::uint32_t Index)
		{
			const auto* Item = Chunk + (Index * ItemSize);
			if (Platform::IsBadReadPtr(Item) || Platform::IsBadReadPtr(Item + sizeof(void*) - 1))
			{
				++Mismatches;
				return;
			}

			const std::uint8_t* Object = nullptr;
			if (!TryReadValue(Item, Object))
			{
				++Mismatches;
				return;
			}

			if (!Object)
				return;

			std::int32_t ActualIndex = 0;
			if (!IsPlausibleObject(Object, ModuleBase, ModuleEnd) || !TryReadValue(Object + InternalIndexOffset, ActualIndex))
			{
				++Mismatches;
				return;
			}

			const std::int32_t ExpectedIndex = static_cast<std::int32_t>((ChunkIndex * ElementsPerChunk) + Index);
			if (ActualIndex == ExpectedIndex)
				++Matches;
			else
				++Mismatches;
		};

		for (std::uint32_t Index = 0; Index < SequentialSampleCount; ++Index)
			ScoreIndex(Index);

		for (std::uint32_t Sample = 0; Sample < DistributedSampleCount; ++Sample)
			ScoreIndex((Sample * ElementsPerChunk) / DistributedSampleCount);

		if (Matches < 0x10 || Mismatches > Matches)
			return -1;

		return Matches - Mismatches;
	}

	bool DiscoverObjectItemLayout(const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd, std::uint32_t& ItemSize, std::uint32_t& InternalIndexOffset, std::uint8_t*& FirstChunk)
	{
		constexpr std::uint32_t InitialSampleElements = 0x8000;
		constexpr std::array<std::uint32_t, 9> CandidateItemSizes = {
			Discovery::FUObjectItemSize, 0x10, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30,
		};
		constexpr std::array<std::uint32_t, 5> CandidateChunkElements = {
			0x8000, 0x10000, 0x20000, 0x40000, 0x80000,
		};

		bool bFound = false;
		const auto ScanMemory = [&](const bool LikelyChunkRegionsOnly, const std::size_t MaximumSnapshotSize)
		{
			Platform::IterateMemoryRegionsWithCallback([&](void* Base, const size_t Size) -> bool
			{
				constexpr size_t MinimumRegionSize = InitialSampleElements * 0x10;
				constexpr size_t MaximumRegionSize = 0x08000000;
				if (Size < MinimumRegionSize || Size > MaximumRegionSize)
					return false;

				if (LikelyChunkRegionsOnly)
				{
					bool IsLikelyChunkRegion = false;
					for (const std::uint32_t CandidateItemSize : CandidateItemSizes)
					{
						for (const std::uint32_t CandidateElements : CandidateChunkElements)
						{
							const size_t ChunkBytes = static_cast<size_t>(CandidateItemSize) * CandidateElements;
							if (Size >= ChunkBytes && Size <= ChunkBytes + 0x20000)
							{
								IsLikelyChunkRegion = true;
								break;
							}
						}

						if (IsLikelyChunkRegion)
							break;
					}

					if (!IsLikelyChunkRegion)
						return false;
				}

				auto* Region = static_cast<std::uint8_t*>(Base);
				const std::size_t SnapshotSize = std::min(Size, MaximumSnapshotSize);
				std::vector<std::uint8_t> Snapshot(SnapshotSize);
				if (!TryReadMemory(Region, Snapshot.data(), Snapshot.size()))
					return false;

				const std::size_t RequiredTail = SnapshotSize == Size ? 0x2000 : 0x100;
				for (size_t Offset = 0; Offset + RequiredTail < SnapshotSize; Offset += sizeof(std::uint32_t))
				{
					auto* Candidate = Region + Offset;
					const std::uint8_t* FirstObject = nullptr;
					std::memcpy(&FirstObject, Snapshot.data() + Offset, sizeof(FirstObject));

					if (!IsPlausibleObject(FirstObject, ModuleBase, ModuleEnd))
						continue;

					for (std::uint32_t IndexOffset = 0x8; IndexOffset <= 0x100; IndexOffset += sizeof(std::uint32_t))
					{
						std::int32_t FirstIndex = 0;
						if (!TryReadValue(FirstObject + IndexOffset, FirstIndex))
							continue;

						if (FirstIndex != 0)
							continue;

						for (const std::uint32_t CandidateItemSize : CandidateItemSizes)
						{
							const std::uint8_t* SecondObject = nullptr;
							std::memcpy(&SecondObject, Snapshot.data() + Offset + CandidateItemSize, sizeof(SecondObject));
							if (!IsPlausibleObject(SecondObject, ModuleBase, ModuleEnd))
								continue;

							std::int32_t SecondIndex = 0;
							if (!TryReadValue(SecondObject + IndexOffset, SecondIndex) || SecondIndex != FirstIndex + 1)
								continue;

							if (ScoreObjectChunk(Candidate, 0, CandidateItemSize, IndexOffset, InitialSampleElements, ModuleBase, ModuleEnd) < 0)
								continue;

							ItemSize = CandidateItemSize;
							InternalIndexOffset = IndexOffset;
							FirstChunk = Candidate;
							bFound = true;
							return true;
						}
					}
				}

				return false;
			}, true);
		};

		ScanMemory(true, 0x2000);
		if (!bFound)
			ScanMemory(true, std::numeric_limits<std::size_t>::max());
		if (!bFound)
			ScanMemory(false, std::numeric_limits<std::size_t>::max());

		return bFound;
	}

	bool DiscoverFirstObjectChunk(const char* const ModuleName, DiscoveredObjectArray& Result)
	{
		const std::uintptr_t ModuleBase = Platform::GetModuleBase(ModuleName);
		const std::uintptr_t ModuleSize = GetModuleSize(ModuleBase);
		if (!ModuleBase || !ModuleSize)
			return false;

		const std::uintptr_t ModuleEnd = ModuleBase + ModuleSize;
		std::uint8_t* FirstChunk = nullptr;
		if (!DiscoverObjectItemLayout(ModuleBase, ModuleEnd, Result.ItemSize, Result.InternalIndexOffset, FirstChunk))
			return false;

		Result.Chunks.push_back(FirstChunk);
		return true;
	}

	std::int32_t FindHighestLiveObjectIndex(const std::vector<std::uint8_t*>& Chunks, const std::uint32_t ElementsPerChunk, const std::uint32_t ItemSize, const std::uint32_t InternalIndexOffset, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd)
	{
		const std::size_t ChunkSize = static_cast<std::size_t>(ElementsPerChunk) * ItemSize;
		std::vector<std::uint8_t> Snapshot(ChunkSize);
		for (std::size_t ChunkIndex = Chunks.size(); ChunkIndex-- > 0;)
		{
			if (!Chunks[ChunkIndex])
				continue;

			if (!TryReadMemory(Chunks[ChunkIndex], Snapshot.data(), Snapshot.size()))
				continue;

			for (std::uint32_t InChunkIndex = ElementsPerChunk; InChunkIndex-- > 0;)
			{
				std::uint8_t* Object = nullptr;
				std::memcpy(&Object, Snapshot.data() + (static_cast<std::size_t>(InChunkIndex) * ItemSize), sizeof(Object));
				if (!Object || !IsPlausibleObject(Object, ModuleBase, ModuleEnd))
					continue;

				std::int32_t ActualIndex = -1;
				if (!TryReadValue(Object + InternalIndexOffset, ActualIndex))
					continue;

				const std::uint64_t ExpectedIndex = (ChunkIndex * ElementsPerChunk) + InChunkIndex;
				if (ExpectedIndex <= static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()) && ActualIndex == static_cast<std::int32_t>(ExpectedIndex))
					return ActualIndex;
			}
		}

		return -1;
	}

	std::uint32_t InferElementsPerChunk(std::uint8_t** Table, const DiscoveredObjectArray& Layout, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd)
	{
		constexpr std::uint32_t SampleSlots = 0x2000;
		constexpr std::uint32_t MinimumVotes = 8;
		std::uint8_t* SecondChunk = nullptr;
		if (!TryReadValue(Table + 1, SecondChunk) || !SecondChunk)
			return 0;

		std::vector<std::pair<std::uint32_t, std::uint32_t>> Votes;
		for (std::uint32_t Slot = 0; Slot < SampleSlots; ++Slot)
		{
			std::uint8_t* Object = nullptr;
			if (!TryReadValue(SecondChunk + (static_cast<std::size_t>(Slot) * Layout.ItemSize), Object) || !Object || !IsPlausibleObject(Object, ModuleBase, ModuleEnd))
				continue;

			std::int32_t ActualIndex = -1;
			if (!TryReadValue(Object + Layout.InternalIndexOffset, ActualIndex) || ActualIndex <= static_cast<std::int32_t>(Slot))
				continue;

			const std::uint32_t Candidate = static_cast<std::uint32_t>(ActualIndex) - Slot;
			if (Candidate < 0x1000 || Candidate > 0x1000000 || !std::has_single_bit(Candidate))
				continue;

			auto Existing = std::find_if(Votes.begin(), Votes.end(), [&](const auto& Vote) { return Vote.first == Candidate; });
			if (Existing == Votes.end())
				Votes.emplace_back(Candidate, 1);
			else
				++Existing->second;
		}

		std::sort(Votes.begin(), Votes.end(), [](const auto& Left, const auto& Right) { return Left.second > Right.second; });
		if (Votes.empty() || Votes[0].second < MinimumVotes)
			return 0;
		if (Votes.size() > 1 && Votes[0].second == Votes[1].second)
			return 0;

		return Votes[0].first;
	}

	bool ValidateStructuralChunkTable(std::uint8_t** Table, std::uint8_t* ExpectedFirstChunk, const DiscoveredObjectArray& Layout, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd, DiscoveredObjectArray& Result)
	{
		constexpr std::array<std::uint32_t, 5> StandardElementCounts = { 0x8000, 0x10000, 0x20000, 0x40000, 0x80000 };
		constexpr std::uint32_t MaximumChunkCount = 0x400;
		std::vector<std::uint32_t> ElementCountCandidates;
		const std::uint32_t InferredElementCount = InferElementsPerChunk(Table, Layout, ModuleBase, ModuleEnd);
		if (InferredElementCount != 0)
			ElementCountCandidates.push_back(InferredElementCount);
		for (const std::uint32_t StandardElementCount : StandardElementCounts)
		{
			if (std::find(ElementCountCandidates.begin(), ElementCountCandidates.end(), StandardElementCount) == ElementCountCandidates.end())
				ElementCountCandidates.push_back(StandardElementCount);
		}

		std::vector<DiscoveredObjectArray> Validated;

		for (const std::uint32_t ElementsPerChunk : ElementCountCandidates)
		{
			DiscoveredObjectArray Candidate = Layout;
			Candidate.Chunks.clear();
			Candidate.ElementsPerChunk = ElementsPerChunk;
			Candidate.ChunkTableAddress = reinterpret_cast<std::uintptr_t>(Table);

			for (std::uint32_t ChunkIndex = 0; ChunkIndex < MaximumChunkCount; ++ChunkIndex)
			{
				std::uint8_t* Chunk = nullptr;
				if (!TryReadValue(Table + ChunkIndex, Chunk) || !Chunk)
					break;
				if (ChunkIndex == 0 && Chunk != ExpectedFirstChunk)
					break;
				if (ScoreObjectChunk(Chunk, ChunkIndex, Layout.ItemSize, Layout.InternalIndexOffset, ElementsPerChunk, ModuleBase, ModuleEnd) < 0)
					break;

				Candidate.Chunks.push_back(Chunk);
			}

			if (Candidate.Chunks.size() < 2)
				continue;

			const std::int32_t HighestIndex = FindHighestLiveObjectIndex(Candidate.Chunks, ElementsPerChunk, Layout.ItemSize, Layout.InternalIndexOffset, ModuleBase, ModuleEnd);
			if (HighestIndex < 0)
				continue;

			Candidate.Num = HighestIndex + 1;
			const std::uint64_t MinimumCount = static_cast<std::uint64_t>(Candidate.Chunks.size() - 1) * ElementsPerChunk;
			const std::uint64_t MaximumCount = static_cast<std::uint64_t>(Candidate.Chunks.size()) * ElementsPerChunk;
			if (static_cast<std::uint64_t>(Candidate.Num) <= MinimumCount || static_cast<std::uint64_t>(Candidate.Num) > MaximumCount)
				continue;

			Validated.push_back(std::move(Candidate));
		}

		if (Validated.size() != 1)
			return false;

		Result = std::move(Validated[0]);
		return true;
	}

	bool FindStructuralChunkTable(std::uint8_t* ExpectedFirstChunk, const DiscoveredObjectArray& Layout, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd, DiscoveredObjectArray& Result)
	{
		constexpr std::size_t ScanWindowSize = 0x400000;
		bool bFound = false;
		std::uint64_t ScannedBytes = 0;

		Platform::IterateMemoryRegionsWithCallback([&](void* Base, const std::size_t Size) -> bool
		{
			const auto* Region = static_cast<const std::uint8_t*>(Base);
			std::vector<std::uint8_t> Snapshot(std::min<std::size_t>(Size, ScanWindowSize));
			for (std::size_t WindowOffset = 0; WindowOffset < Size; WindowOffset += Snapshot.size())
			{
				const std::size_t ReadSize = std::min<std::size_t>(Snapshot.size(), Size - WindowOffset);
				if (!TryReadMemory(Region + WindowOffset, Snapshot.data(), ReadSize))
					continue;
				ScannedBytes += ReadSize;

				for (std::size_t Offset = 0; Offset + sizeof(ExpectedFirstChunk) <= ReadSize; Offset += alignof(void*))
				{
					std::uint8_t* Value = nullptr;
					std::memcpy(&Value, Snapshot.data() + Offset, sizeof(Value));
					if (Value != ExpectedFirstChunk)
						continue;

					auto** Table = reinterpret_cast<std::uint8_t**>(const_cast<std::uint8_t*>(Region + WindowOffset + Offset));
					if (!ValidateStructuralChunkTable(Table, ExpectedFirstChunk, Layout, ModuleBase, ModuleEnd, Result))
						continue;

					bFound = true;
					return true;
				}
			}

			return false;
		}, true);

		std::cerr << std::format("Discovery bootstrap: scanned {:.1f} MiB while locating the chunk table\n", static_cast<double>(ScannedBytes) / 1048576.0);
		return bFound;
	}

	bool FindStructuralChunksWithoutTable(std::uint8_t* ExpectedFirstChunk, const DiscoveredObjectArray& Layout, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd, DiscoveredObjectArray& Result)
	{
		constexpr std::array<std::uint32_t, 6> ElementCountCandidates = { 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000 };
		constexpr std::size_t MaximumAllocationSlack = 0x80000;
		constexpr std::uint32_t MaximumChunkCount = 0x400;

		MEMORY_BASIC_INFORMATION FirstChunkMemory{};
		if (!VirtualQuery(ExpectedFirstChunk, &FirstChunkMemory, sizeof(FirstChunkMemory)))
			return false;

		const std::uintptr_t FirstRegionEnd = reinterpret_cast<std::uintptr_t>(FirstChunkMemory.BaseAddress) + FirstChunkMemory.RegionSize;
		const std::size_t FirstChunkAvailable = FirstRegionEnd - reinterpret_cast<std::uintptr_t>(ExpectedFirstChunk);
		std::vector<std::uint32_t> MatchingElementCounts;
		for (const std::uint32_t ElementsPerChunk : ElementCountCandidates)
		{
			const std::size_t ChunkBytes = static_cast<std::size_t>(ElementsPerChunk) * Layout.ItemSize;
			if (ChunkBytes > FirstChunkAvailable || FirstChunkAvailable - ChunkBytes > MaximumAllocationSlack)
				continue;
			if (ScoreObjectChunk(ExpectedFirstChunk, 0, Layout.ItemSize, Layout.InternalIndexOffset, ElementsPerChunk, ModuleBase, ModuleEnd) >= 0)
				MatchingElementCounts.push_back(ElementsPerChunk);
		}

		if (MatchingElementCounts.size() != 1)
		{
			std::cerr << std::format("Discovery bootstrap: allocation geometry matched {} element counts\n", MatchingElementCounts.size());
			return false;
		}

		const std::uint32_t ElementsPerChunk = MatchingElementCounts[0];
		const std::size_t ChunkBytes = static_cast<std::size_t>(ElementsPerChunk) * Layout.ItemSize;
		std::map<std::uint32_t, std::set<std::uint8_t*>> Candidates;
		Candidates[0].insert(ExpectedFirstChunk);

		Platform::IterateMemoryRegionsWithCallback([&](void* Base, const std::size_t Size) -> bool
		{
			if (Size < ChunkBytes || Size > ChunkBytes + MaximumAllocationSlack)
				return false;

			auto* Region = static_cast<std::uint8_t*>(Base);
			std::vector<std::uint8_t> Snapshot(Size);
			if (!TryReadMemory(Region, Snapshot.data(), Snapshot.size()))
				return false;

			std::set<std::uint8_t*> AttemptedBases;
			for (std::size_t Offset = 0; Offset + sizeof(void*) <= Snapshot.size(); Offset += sizeof(std::uint32_t))
			{
				std::uint8_t* Object = nullptr;
				std::memcpy(&Object, Snapshot.data() + Offset, sizeof(Object));
				if (!IsPlausibleObject(Object, ModuleBase, ModuleEnd))
					continue;

				std::int32_t InternalIndex = -1;
				if (!TryReadValue(Object + Layout.InternalIndexOffset, InternalIndex) || InternalIndex < 0)
					continue;

				const std::uint32_t ChunkIndex = static_cast<std::uint32_t>(InternalIndex) / ElementsPerChunk;
				const std::uint32_t InChunkIndex = static_cast<std::uint32_t>(InternalIndex) % ElementsPerChunk;
				if (ChunkIndex >= MaximumChunkCount)
					continue;

				const std::size_t ItemOffset = static_cast<std::size_t>(InChunkIndex) * Layout.ItemSize;
				if (Offset < ItemOffset)
					continue;
				auto* Candidate = Region + Offset - ItemOffset;
				if (Candidate < Region || Candidate + ChunkBytes > Region + Size || !AttemptedBases.insert(Candidate).second)
					continue;
				if (ScoreObjectChunk(Candidate, ChunkIndex, Layout.ItemSize, Layout.InternalIndexOffset, ElementsPerChunk, ModuleBase, ModuleEnd) < 0)
					continue;

				Candidates[ChunkIndex].insert(Candidate);
				break;
			}

			return false;
		}, true);

		if (Candidates.size() < 2 || !Candidates.contains(0) || Candidates[0].size() != 1 || *Candidates[0].begin() != ExpectedFirstChunk)
			return false;

		const std::uint32_t HighestChunkIndex = Candidates.rbegin()->first;
		Result = Layout;
		Result.Chunks.assign(static_cast<std::size_t>(HighestChunkIndex) + 1, nullptr);
		Result.ElementsPerChunk = ElementsPerChunk;
		Result.ChunkTableAddress = 0;
		for (const auto& [ChunkIndex, Addresses] : Candidates)
		{
			if (Addresses.size() != 1)
				return false;
			Result.Chunks[ChunkIndex] = *Addresses.begin();
		}

		const std::int32_t HighestIndex = FindHighestLiveObjectIndex(Result.Chunks, ElementsPerChunk, Layout.ItemSize, Layout.InternalIndexOffset, ModuleBase, ModuleEnd);
		if (HighestIndex < 0 || static_cast<std::uint32_t>(HighestIndex) / ElementsPerChunk != HighestChunkIndex)
			return false;

		Result.Num = HighestIndex + 1;
		std::cerr << std::format("Discovery bootstrap: reconstructed {} logical chunks from {} independently validated allocations; {} chunks are currently empty\n", Result.Chunks.size(), Candidates.size(), Result.Chunks.size() - Candidates.size());
		return true;
	}
}

constexpr inline std::array FFixedUObjectArrayLayouts =
{
	FFixedUObjectArrayLayout // Default UE4.11 - UE4.20
	{
		.ObjectsOffset = 0x0,								// 0x00
		.MaxObjectsOffset = sizeof(void*),					// 0x08 (64bit) OR 0x04 (32bit)
		.NumObjectsOffset = sizeof(void*) + sizeof(int)		// 0x0C (64bit) OR 0x08 (32bit)
	}
};

constexpr inline std::array FChunkedFixedUObjectArrayLayouts =
{
	FChunkedFixedUObjectArrayLayout // Default UE4.21 - UE5.7
	{
		.ObjectsOffset = 0x00,
		.MaxElementsOffset = 0x10,
		.NumElementsOffset = 0x14,
		.MaxChunksOffset = 0x18,
		.NumChunksOffset = 0x1C,
	},
	FChunkedFixedUObjectArrayLayout // UE5.8 Developement Build
	{
		.ObjectsOffset = 0x00, 
		.MaxElementsOffset = 0x0C,
		.NumElementsOffset = 0x08,
		.MaxChunksOffset = 0x14,
		.NumChunksOffset = 0x10,
	},
	FChunkedFixedUObjectArrayLayout // Back4Blood
	{
		.ObjectsOffset = 0x10, // last
		.MaxElementsOffset = 0x00,
		.NumElementsOffset = 0x04,
		.MaxChunksOffset = 0x08,
		.NumChunksOffset = 0x0C,
	},
	FChunkedFixedUObjectArrayLayout // Mutliversus
	{
		.ObjectsOffset = 0x18,
		.MaxElementsOffset = 0x10,
		.NumElementsOffset = 0x00, // first
		.MaxChunksOffset = 0x14,
		.NumChunksOffset = 0x20,
	},
	FChunkedFixedUObjectArrayLayout // MindsEye
	{
		.ObjectsOffset = 0x18,
		.MaxElementsOffset = 0x00, // first
		.NumElementsOffset = 0x14,
		.MaxChunksOffset = 0x10,
		.NumChunksOffset = 0x04,
	}
};

bool IsAddressValidGObjects(const uintptr_t Address, const FFixedUObjectArrayLayout& Layout)
{
	/* It is assumed that the FUObjectItem layout is constant amongst all games using FFixedUObjectArray for ObjObjects. */
	struct FUObjectItem
	{
		void* Object;
		uint8_t Pad[sizeof(void*) * 2];
	};

	void* Objects = *reinterpret_cast<void**>(Address + Layout.ObjectsOffset);
	const int32 MaxElements = *reinterpret_cast<const int32*>(Address + Layout.MaxObjectsOffset);
	const int32 NumElements = *reinterpret_cast<const int32*>(Address + Layout.NumObjectsOffset);

	FUObjectItem* ObjectsButDecrypted = reinterpret_cast<FUObjectItem*>(ObjectArray::DecryptPtr(Objects));

	if (NumElements > MaxElements)
		return false;

	if (MaxElements > 0x400000)
		return false;

	if (NumElements < 0x1000)
		return false;

	if (Platform::IsBadReadPtr(ObjectsButDecrypted))
		return false;

	if (Platform::IsBadReadPtr(ObjectsButDecrypted[5].Object))
		return false;

	const uintptr_t FifthObject = reinterpret_cast<uintptr_t>(ObjectsButDecrypted[0x5].Object);
	const int32 IndexOfFithobject = *reinterpret_cast<int32_t*>(FifthObject + sizeof(void*) + sizeof(int32)); // FifthObject -> InternalIndex

	if (IndexOfFithobject != 0x5)
		return false;

	return true;
}

bool IsAddressValidGObjects(const uintptr_t Address, const FChunkedFixedUObjectArrayLayout& Layout)
{
	void* Objects = *reinterpret_cast<void**>(Address + Layout.ObjectsOffset);
	const int32 MaxElements = *reinterpret_cast<const int32*>(Address + Layout.MaxElementsOffset);
	const int32 NumElements = *reinterpret_cast<const int32*>(Address + Layout.NumElementsOffset);
	const int32 MaxChunks   = *reinterpret_cast<const int32*>(Address + Layout.MaxChunksOffset);
	const int32 NumChunks   = *reinterpret_cast<const int32*>(Address + Layout.NumChunksOffset);

	void** ObjectsPtrButDecrypted = reinterpret_cast<void**>(ObjectArray::DecryptPtr(Objects));

	if (NumChunks > 0x14 || NumChunks < 0x1)
		return false;

	if (MaxChunks > 0x5FF || MaxChunks < 0x6)
		return false;

	if (NumElements <= 0x800 || MaxElements <= 0x10000)
		return false;

	if (NumElements > MaxElements || NumChunks > MaxChunks)
		return false;

	if ((MaxElements % 0x10) != 0)
		return false;

	const int32_t ElementsPerChunk = MaxElements / MaxChunks;

	if ((ElementsPerChunk % 0x10) != 0)
		return false;

	if (ElementsPerChunk < 0x8000 || ElementsPerChunk > 0x80000)
		return false;

	const bool bNumChunksFitsNumElements = ((NumElements / ElementsPerChunk) + 1) == NumChunks;

	if (!bNumChunksFitsNumElements)
		return false;

	const bool bMaxChunksFitsMaxElements = (MaxElements / ElementsPerChunk) == MaxChunks;

	if (!bMaxChunksFitsMaxElements)
		return false;

	if (!ObjectsPtrButDecrypted || Platform::IsBadReadPtr(ObjectsPtrButDecrypted))
		return false;

	for (int i = 0; i < NumChunks; i++)
	{
		if (!ObjectsPtrButDecrypted[i] || Platform::IsBadReadPtr(ObjectsPtrButDecrypted[i]))
			return false;
	}

	return true;
}


void ObjectArray::InitializeFUObjectItem(uint8_t* FirstItemPtr)
{
	for (int i = 0x0; i < 0x20; i += 4)
	{
		if (!Platform::IsBadReadPtr(*reinterpret_cast<uint8_t**>(FirstItemPtr + i)))
		{
			FUObjectItemInitialOffset = i;
			break;
		}
	}

	for (int i = FUObjectItemInitialOffset + sizeof(void*); i <= 0x38; i += 4)
	{
		void* SecondObject = *reinterpret_cast<uint8**>(FirstItemPtr + i);
		void* ThirdObject  = *reinterpret_cast<uint8**>(FirstItemPtr + (i * 2) - FUObjectItemInitialOffset);

		if (!Platform::IsBadReadPtr(SecondObject) && !Platform::IsBadReadPtr(*reinterpret_cast<void**>(SecondObject)) &&
			!Platform::IsBadReadPtr(ThirdObject) && !Platform::IsBadReadPtr(*reinterpret_cast<void**>(ThirdObject)))
		{
			SizeOfFUObjectItem = i - FUObjectItemInitialOffset;
			break;
		}
	}

	Off::InSDK::ObjArray::FUObjectItemInitialOffset = FUObjectItemInitialOffset;
	Off::InSDK::ObjArray::FUObjectItemSize = SizeOfFUObjectItem;

	std::cerr << "Off::InSDK::ObjArray::FUObjectItemSize: " << Off::InSDK::ObjArray::FUObjectItemSize << "\n" << std::endl;
}

void ObjectArray::InitDecryption(uint8_t* (*DecryptionFunction)(void* ObjPtr), const char* DecryptionLambdaAsStr)
{
	DecryptPtr = DecryptionFunction;
	DecryptionLambdaStr = DecryptionLambdaAsStr;
}

void ObjectArray::InitDiscovery(const char* const ModuleName)
{
	std::cerr << "Discovery bootstrap: scanning for the first object chunk\n";
	bUseDiscoveryObjectArray = true;
	bUseDiscoveredChunks = false;
	DiscoveredChunks.clear();
	DiscoveredNum = 0;
	DiscoveredInternalIndexOffset = 0x0C;
	Discovery::ChunkTableAddress = 0;
	Discovery::ChunkCount = 0;

	DiscoveredObjectArray DiscoveredArray;
	bool FoundObjectChunk = false;
	constexpr int32_t BootstrapAttempts = 120;
	for (int32_t Attempt = 0; Attempt < BootstrapAttempts && !FoundObjectChunk; ++Attempt)
	{
		DiscoveredArray = {};
		FoundObjectChunk = DiscoverFirstObjectChunk(ModuleName, DiscoveredArray);
		if (!FoundObjectChunk && Attempt + 1 < BootstrapAttempts)
		{
			if (Attempt == 0 || (Attempt + 1) % 20 == 0)
				std::cerr << std::format("Discovery bootstrap: reflection is not initialized yet; retry {}/{}\n", Attempt + 2, BootstrapAttempts);
			::Sleep(250);
		}
	}

	if (FoundObjectChunk)
	{
		std::cerr << std::format("Discovery bootstrap: first chunk found; item size 0x{:X}, index +0x{:X}\n", DiscoveredArray.ItemSize, DiscoveredArray.InternalIndexOffset);
		const std::uintptr_t ModuleBase = Platform::GetModuleBase(ModuleName);
		const std::uintptr_t ModuleEnd = ModuleBase + GetModuleSize(ModuleBase);
		std::cerr << "Discovery bootstrap: locating reverse references to the first chunk\n";
		DiscoveredObjectArray CompleteArray;
		if (!FindStructuralChunkTable(DiscoveredArray.Chunks[0], DiscoveredArray, ModuleBase, ModuleEnd, CompleteArray))
		{
			std::cerr << "Discovery bootstrap: no plain chunk table found; locating chunk allocations independently\n";
			if (!FindStructuralChunksWithoutTable(DiscoveredArray.Chunks[0], DiscoveredArray, ModuleBase, ModuleEnd, CompleteArray))
				throw std::runtime_error("The first object chunk was found, but neither a chunk table nor an independently validated sparse chunk set could be reconstructed");
		}

		bUseDiscoveredChunks = true;
		DiscoveredChunks = std::move(CompleteArray.Chunks);
		DiscoveredNum = CompleteArray.Num;
		DiscoveredInternalIndexOffset = CompleteArray.InternalIndexOffset;
		SizeOfFUObjectItem = CompleteArray.ItemSize;
		Discovery::ElementsPerChunk = CompleteArray.ElementsPerChunk;
		Discovery::ChunkTableAddress = CompleteArray.ChunkTableAddress;
		Discovery::ChunkCount = static_cast<std::uint32_t>(DiscoveredChunks.size());
		GObjects = nullptr;
	}
	else
	{
		throw std::runtime_error("Structural object-array discovery failed");
	}

	NumElementsPerChunk = Discovery::ElementsPerChunk;
	Discovery::ObjectCount = static_cast<std::uint32_t>(DiscoveredNum);
	FUObjectItemInitialOffset = 0x0;

	Off::FUObjectArray::bIsChunked = true;
	Off::FUObjectArray::ChunkedFixedLayout = FChunkedFixedUObjectArrayLayouts[0];
	Off::InSDK::ObjArray::GObjects = 0x0;
	Off::InSDK::ObjArray::ChunkSize = Discovery::ElementsPerChunk;
	Off::InSDK::ObjArray::FUObjectItemSize = SizeOfFUObjectItem;
	Off::InSDK::ObjArray::FUObjectItemInitialOffset = 0x0;

	if (bUseDiscoveredChunks)
	{
		std::cerr << "Discovery object array reconstructed structurally; the protected GObjects global was not read\n";
		std::cerr << std::format("Discovery chunks: {}, FUObjectItem size: 0x{:X}, UObject index offset: 0x{:X}\n", DiscoveredChunks.size(), SizeOfFUObjectItem, DiscoveredInternalIndexOffset);
		std::cerr << std::format("Discovery runtime chunk table: 0x{:X}, elements per chunk: 0x{:X}\n", Discovery::ChunkTableAddress, Discovery::ElementsPerChunk);
	}

	std::cerr << std::format("Discovery object count: 0x{:X}\n\n", Num());
}


/* We don't speak about this function... */
void ObjectArray::Init(bool bScanAllMemory, const char* const ModuleName)
{
	if (!bScanAllMemory)
	{
		std::cerr << "\nDumper-7 by me, you & him\n\n\n";
		std::cerr << "Searching for GObjects...\n\n";
	}

	auto MatchesAnyLayout = []<typename ArrayLayoutType, size_t Size>(const std::array<ArrayLayoutType, Size>& ObjectArrayLayouts, uintptr_t Address)
	{
		for (const ArrayLayoutType& Layout : ObjectArrayLayouts)
		{
			if (!IsAddressValidGObjects(Address, Layout))
				continue;

			if constexpr (std::is_same_v<ArrayLayoutType, FFixedUObjectArrayLayout>)
			{
				Off::FUObjectArray::bIsChunked = false;
				Off::FUObjectArray::FixedLayout = Layout;
			}
			else
			{
				Off::FUObjectArray::bIsChunked = true;
				Off::FUObjectArray::ChunkedFixedLayout = Layout;
			}

			return true;
		}
		
		return false;
	};

	bool bIsGObjectsChunked = false;
	auto IsAddressValidGObjects = [MatchesAnyLayout, &bIsGObjectsChunked](const void* CurrentAddress) -> bool
	{
		//std::cerr << "checking addr: " << CurrentAddress << "\n";
		if (MatchesAnyLayout(FFixedUObjectArrayLayouts, reinterpret_cast<uintptr_t>(CurrentAddress)))
		{
			bIsGObjectsChunked = false;
			return true;
		}
		else if (MatchesAnyLayout(FChunkedFixedUObjectArrayLayouts, reinterpret_cast<uintptr_t>(CurrentAddress)))
		{
			bIsGObjectsChunked = true;
			return true;
		}

		return false;
	};

	void* GObjectsAddress = nullptr;

	if (bScanAllMemory)
	{
		GObjectsAddress = Platform::IterateAllSectionsWithCallback(IsAddressValidGObjects, 0x4, 0x50, ModuleName);
	}
	else
	{
		GObjectsAddress = Platform::IterateSectionWithCallback(Platform::GetSectionInfo(".data"), IsAddressValidGObjects, 0x4, 0x50);
	}


	if (GObjectsAddress)
	{
		if (!bIsGObjectsChunked)
		{
			GObjects = static_cast<uint8*>(GObjectsAddress);
			NumElementsPerChunk = -1;

			Off::InSDK::ObjArray::GObjects = Platform::GetOffset(GObjectsAddress);

			std::cerr << "Found FFixedUObjectArray GObjects at offset 0x" << std::hex << Off::InSDK::ObjArray::GObjects << "\n\n";

			ByIndex = [](void* ObjectsArray, int32 Index, uint32 FUObjectItemSize, uint32 FUObjectItemOffset, uint32 PerChunk) -> void*
			{
				if (Index < 0 || Index > Num())
					return nullptr;

				uint8_t* ChunkPtr = DecryptPtr(*reinterpret_cast<uint8_t**>(ObjectsArray));

				return *reinterpret_cast<void**>(ChunkPtr + FUObjectItemOffset + (Index * FUObjectItemSize));
			};

			uint8_t* FirstItem = DecryptPtr(*reinterpret_cast<uint8_t**>(GObjects + Off::FUObjectArray::GetObjectsOffset()));

			ObjectArray::InitializeFUObjectItem(FirstItem);
		}
		else
		{
			GObjects = static_cast<uint8*>(GObjectsAddress);
			
			NumElementsPerChunk = Max() / MaxChunks();
			Off::InSDK::ObjArray::ChunkSize = NumElementsPerChunk;

			SizeOfFUObjectItem = sizeof(void*) + sizeof(int32) + sizeof(int32);
			FUObjectItemInitialOffset = 0x0;

			Off::InSDK::ObjArray::GObjects = Platform::GetOffset(GObjectsAddress);

			std::cerr << "Found FChunkedFixedUObjectArray GObjects at offset 0x" << std::hex << Off::InSDK::ObjArray::GObjects << "\n\n";

			ByIndex = [](void* ObjectsArray, int32 Index, uint32 FUObjectItemSize, uint32 FUObjectItemOffset, uint32 PerChunk) -> void*
			{
				if (Index < 0 || Index > Num())
					return nullptr;

				const int32 ChunkIndex = Index / PerChunk;
				const int32 InChunkIdx = Index % PerChunk;

				uint8_t* ChunkPtr = DecryptPtr(*reinterpret_cast<uint8_t**>(ObjectsArray));

				uint8_t* Chunk = reinterpret_cast<uint8_t**>(ChunkPtr)[ChunkIndex];
				uint8_t* ItemPtr = Chunk + (InChunkIdx * FUObjectItemSize);

				return *reinterpret_cast<void**>(ItemPtr + FUObjectItemOffset);
			};
			
			uint8_t* ChunksPtr = DecryptPtr(*reinterpret_cast<uint8_t**>(GObjects + Off::FUObjectArray::GetObjectsOffset()));

			ObjectArray::InitializeFUObjectItem(*reinterpret_cast<uint8_t**>(ChunksPtr));
		}

		return;
	}

	if (!bScanAllMemory)
	{
		ObjectArray::Init(true);
		return;
	}

	if (GObjects == nullptr)
	{
		std::cerr << "\nGObjects couldn't be found, please overwrite the offset in Generator.cpp.\n\n\n";
		Sleep(10000);
		exit(1);
	}
}

void ObjectArray::Init(int32 GObjectsOffset, const FFixedUObjectArrayLayout& ObjectArrayLayout, const char* const ModuleName)
{
	GObjects = reinterpret_cast<uint8_t*>(Platform::GetModuleBase(ModuleName) + GObjectsOffset);
	Off::InSDK::ObjArray::GObjects = GObjectsOffset;

	std::cerr << "GObjects: 0x" << (void*)GObjects << "\n" << std::endl;

	Off::FUObjectArray::bIsChunked = false;
	Off::FUObjectArray::FixedLayout = ObjectArrayLayout.IsValid() ? ObjectArrayLayout : FFixedUObjectArrayLayouts[0];

	ByIndex = [](void* ObjectsArray, int32 Index, uint32 FUObjectItemSize, uint32 FUObjectItemOffset, uint32 PerChunk) -> void*
	{
		if (Index < 0 || Index > Num())
			return nullptr;

		uint8_t* ItemPtr = *reinterpret_cast<uint8_t**>(ObjectsArray) + (Index * FUObjectItemSize);

		return *reinterpret_cast<void**>(ItemPtr + FUObjectItemOffset);
	};

	uint8_t* ChunksPtr = DecryptPtr(*reinterpret_cast<uint8_t**>(GObjects + Off::FUObjectArray::GetObjectsOffset()));

	std::cerr << "Overwrote FFixedUObjectArray GObjects to offset 0x" << std::hex << Off::InSDK::ObjArray::GObjects << "\n" << std::endl;

	ObjectArray::InitializeFUObjectItem(*reinterpret_cast<uint8_t**>(ChunksPtr));
}

void ObjectArray::Init(int32 GObjectsOffset, int32 ElementsPerChunk, const FChunkedFixedUObjectArrayLayout& ObjectArrayLayout, const char* const ModuleName)
{
	GObjects = reinterpret_cast<uint8_t*>(Platform::GetModuleBase(ModuleName) + GObjectsOffset);
	Off::InSDK::ObjArray::GObjects = GObjectsOffset;

	Off::FUObjectArray::bIsChunked = true;
	Off::FUObjectArray::ChunkedFixedLayout = ObjectArrayLayout.IsValid() ? ObjectArrayLayout : FChunkedFixedUObjectArrayLayouts[0];

	NumElementsPerChunk = ElementsPerChunk;
	Off::InSDK::ObjArray::ChunkSize = ElementsPerChunk;

	ByIndex = [](void* ObjectsArray, int32 Index, uint32 FUObjectItemSize, uint32 FUObjectItemOffset, uint32 PerChunk) -> void*
	{
		if (Index < 0 || Index > Num())
			return nullptr;

		const int32 ChunkIndex = Index / PerChunk;
		const int32 InChunkIdx = Index % PerChunk;

		uint8_t* Chunk = (*reinterpret_cast<uint8_t***>(ObjectsArray))[ChunkIndex];
		uint8_t* ItemPtr = reinterpret_cast<uint8_t*>(Chunk) + (InChunkIdx * FUObjectItemSize);

		return *reinterpret_cast<void**>(ItemPtr + FUObjectItemOffset);
	};

	uint8_t* ChunksPtr = DecryptPtr(*reinterpret_cast<uint8_t**>(GObjects + Off::FUObjectArray::GetObjectsOffset()));

	std::cerr << "Overwrote FChunkedFixedUObjectArray GObjects to offset 0x" << std::hex << Off::InSDK::ObjArray::GObjects << "\n" << std::endl;

	ObjectArray::InitializeFUObjectItem(*reinterpret_cast<uint8_t**>(ChunksPtr));
}

void ObjectArray::DumpObjects(const fs::path& Path, bool bWithPathname)
{
	std::ofstream DumpStream(Path / "GObjects-Dump.txt");

	DumpStream << "Object dump by Dumper-7\n\n";
	DumpStream << (!Settings::Generator::GameVersion.empty() && !Settings::Generator::GameName.empty() ? (Settings::Generator::GameVersion + '-' + Settings::Generator::GameName) + "\n\n" : "");
	DumpStream << "Count: " << Num() << "\n\n\n";

	for (auto Object : ObjectArray())
	{
		if (!bWithPathname)
		{
			DumpStream << std::format("[{:08X}] {{{}}} {}\n", Object.GetIndex(), Object.GetAddress(), Object.GetFullName());
		}
		else
		{
			DumpStream << std::format("[{:08X}] {{{}}} {}\n", Object.GetIndex(), Object.GetAddress(), Object.GetPathName());
		}
	}

	DumpStream.close();
}

void ObjectArray::DumpObjectsWithProperties(const fs::path& Path, bool bWithPathname)
{
	std::ofstream DumpStream(Path / "GObjects-Dump-WithProperties.txt");

	DumpStream << "Object dump by Dumper-7\n\n";
	DumpStream << (!Settings::Generator::GameVersion.empty() && !Settings::Generator::GameName.empty() ? (Settings::Generator::GameVersion + '-' + Settings::Generator::GameName) + "\n\n" : "");
	DumpStream << "Count: " << Num() << "\n\n\n";

	for (auto Object : ObjectArray())
	{
		if (!bWithPathname)
		{
			DumpStream << std::format("[{:08X}] {{{}}} {}\n", Object.GetIndex(), Object.GetAddress(), Object.GetFullName());
		}
		else
		{
			DumpStream << std::format("[{:08X}] {{{}}} {}\n", Object.GetIndex(), Object.GetAddress(), Object.GetPathName());
		}

		if (Object.IsA(EClassCastFlags::Struct))
		{
			for (UEProperty Prop : Object.Cast<UEStruct>().GetProperties())
			{
				DumpStream << std::format("[{:08X}] {{{}}}     {} {}\n", Prop.GetOffset(), Prop.GetAddress(), Prop.GetPropClassName(), Prop.GetName());
			}
		}
	}

	DumpStream.close();
}


int32 ObjectArray::Num()
{
	if (bUseDiscoveryObjectArray)
		return DiscoveredNum;

	return *reinterpret_cast<int32*>(GObjects + Off::FUObjectArray::GetNumElementsOffset());
}

int32 ObjectArray::Max()
{
	if (bUseDiscoveryObjectArray)
		return NumChunks() * Discovery::ElementsPerChunk;

	return *reinterpret_cast<int32*>(GObjects + Off::FUObjectArray::GetMaxElementsOffset());
}

int32 ObjectArray::NumChunks()
{
	if (bUseDiscoveryObjectArray)
		return static_cast<int32>(DiscoveredChunks.size());

	return *reinterpret_cast<int32*>(GObjects + Off::FUObjectArray::GetNumChunksOffset());
}

int32 ObjectArray::MaxChunks()
{
	if (bUseDiscoveryObjectArray)
		return NumChunks();

	return *reinterpret_cast<int32*>(GObjects + Off::FUObjectArray::GetMaxChunksOffset());
}

uint32 ObjectArray::GetInternalIndexOffset()
{
	return bUseDiscoveredChunks ? DiscoveredInternalIndexOffset : 0x0C;
}

template<typename UEType>
UEType ObjectArray::GetByIndex(int32 Index)
{
	if (bUseDiscoveryObjectArray)
	{
		if (Index < 0 || Index >= Num())
			return UEType();

		const std::uint32_t ChunkIndex = static_cast<std::uint32_t>(Index) / Discovery::ElementsPerChunk;
		const std::uint32_t InChunkIndex = static_cast<std::uint32_t>(Index) % Discovery::ElementsPerChunk;
		if (ChunkIndex >= DiscoveredChunks.size() || !DiscoveredChunks[ChunkIndex])
			return UEType();
		std::uint8_t* Item = DiscoveredChunks[ChunkIndex] + (InChunkIndex * SizeOfFUObjectItem);
		return UEType(*reinterpret_cast<void**>(Item));
	}

	return UEType(ByIndex(GObjects + Off::FUObjectArray::GetObjectsOffset(), Index, SizeOfFUObjectItem, FUObjectItemInitialOffset, NumElementsPerChunk));
}

template<typename UEType>
UEType ObjectArray::FindObject(const std::string& FullName, EClassCastFlags RequiredType)
{
	for (UEObject Object : ObjectArray())
	{
		if (Object.IsA(RequiredType) && Object.GetFullName() == FullName)
		{
			return Object.Cast<UEType>();
		}
	}

	return UEType();
}

template<typename UEType>
UEType ObjectArray::FindObjectFast(const std::string& Name, EClassCastFlags RequiredType)
{
	auto ObjArray = ObjectArray();

	for (UEObject Object : ObjArray)
	{
		if (Object.IsA(RequiredType) && Object.GetName() == Name)
		{
			return Object.Cast<UEType>();
		}
	}

	return UEType();
}

template<typename UEType>
UEType ObjectArray::FindObjectFastInOuter(const std::string& Name, std::string Outer)
{
	auto ObjArray = ObjectArray();

	for (UEObject Object : ObjArray)
	{
		if (Object.GetName() == Name && Object.GetOuter().GetName() == Outer)
		{
			return Object.Cast<UEType>();
		}
	}

	return UEType();
}

UEStruct ObjectArray::FindStruct(const std::string& Name)
{
	return FindObjectFast<UEClass>(Name, EClassCastFlags::Struct);
}

UEStruct ObjectArray::FindStructFast(const std::string& Name)
{
	return FindObjectFast<UEClass>(Name, EClassCastFlags::Struct);
}

UEClass ObjectArray::FindClass(const std::string& FullName)
{
	return FindObject<UEClass>(FullName, EClassCastFlags::Class);
}

UEClass ObjectArray::FindClassFast(const std::string& Name)
{
	return FindObjectFast<UEClass>(Name, EClassCastFlags::Class);
}

ObjectArray::ObjectsIterator ObjectArray::begin()
{
	return ObjectsIterator();
}
ObjectArray::ObjectsIterator ObjectArray::end()
{
	return ObjectsIterator(Num());
}


ObjectArray::ObjectsIterator::ObjectsIterator(int32 StartIndex)
	: CurrentIndex(StartIndex), CurrentObject(ObjectArray::GetByIndex(StartIndex))
{
}

UEObject ObjectArray::ObjectsIterator::operator*() const
{
	return CurrentObject;
}

ObjectArray::ObjectsIterator& ObjectArray::ObjectsIterator::operator++()
{
	CurrentObject = ObjectArray::GetByIndex(++CurrentIndex);

	while (!CurrentObject && CurrentIndex < (ObjectArray::Num() - 1))
	{
		CurrentObject = ObjectArray::GetByIndex(++CurrentIndex);
	}

	if (!CurrentObject && CurrentIndex == (ObjectArray::Num() - 1)) [[unlikely]]
		CurrentIndex++;

	return *this;
}

bool ObjectArray::ObjectsIterator::operator==(const ObjectsIterator& Other) const
{
	return CurrentIndex == Other.CurrentIndex;
}

bool ObjectArray::ObjectsIterator::operator!=(const ObjectsIterator& Other) const
{
	return CurrentIndex != Other.CurrentIndex;
}

int32 ObjectArray::ObjectsIterator::GetIndex() const
{
	return CurrentIndex;
}

bool AllFieldIterator::operator!=(const AllFieldIterator& Other) const
{
	return CurrentObject != Other.CurrentObject || PropertyIndex != Other.PropertyIndex;
}

AllFieldIterator& AllFieldIterator::operator++()
{
	if (CurrenStructHasMoreMembers())
	{
		PropertyIndex++;

		return *this;
	}

	IterateToNextStructWithMembers();

	return *this;
}

UEProperty AllFieldIterator::operator*() const
{
	return Fields[PropertyIndex];
}


void AllFieldIterator::IterateToNextStruct()
{
	if (IsEndIterator())
		return;

	++CurrentObject;

	while (CurrentObject != ObjectEndIterator && !IsCurrentObjectStruct())
		++CurrentObject;
}
void AllFieldIterator::IterateToNextStructWithMembers()
{
	// Loop, in case we meet a struct wihtout any properties
	while (!CurrenStructHasMoreMembers())
	{
		IterateToNextStruct();
		PropertyIndex = 0;

		if (IsEndIterator())
			return;

		Fields = GetCurrentStruct().GetProperties();
	}
}


/*
* The compiler won't generate functions for a specific template type unless it's used in the .cpp file corresponding to the
* header it was declatred in.
*
* See https://stackoverflow.com/questions/456713/why-do-i-get-unresolved-external-symbol-errors-when-using-templates
*/
template UEObject ObjectArray::FindObject<UEObject>(const std::string& FullName, EClassCastFlags RequiredType);
template UEField ObjectArray::FindObject<UEField>(const std::string& FullName, EClassCastFlags RequiredType);
template UEEnum ObjectArray::FindObject<UEEnum>(const std::string& FullName, EClassCastFlags RequiredType);
template UEStruct ObjectArray::FindObject<UEStruct>(const std::string& FullName, EClassCastFlags RequiredType);
template UEClass ObjectArray::FindObject<UEClass>(const std::string& FullName, EClassCastFlags RequiredType);
template UEFunction ObjectArray::FindObject<UEFunction>(const std::string& FullName, EClassCastFlags RequiredType);
template UEProperty ObjectArray::FindObject<UEProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEByteProperty ObjectArray::FindObject<UEByteProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEBoolProperty ObjectArray::FindObject<UEBoolProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEObjectProperty ObjectArray::FindObject<UEObjectProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEClassProperty ObjectArray::FindObject<UEClassProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEStructProperty ObjectArray::FindObject<UEStructProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEArrayProperty ObjectArray::FindObject<UEArrayProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEMapProperty ObjectArray::FindObject<UEMapProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UESetProperty ObjectArray::FindObject<UESetProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEEnumProperty ObjectArray::FindObject<UEEnumProperty>(const std::string& FullName, EClassCastFlags RequiredType);

template UEObject ObjectArray::FindObjectFast<UEObject>(const std::string& FullName, EClassCastFlags RequiredType);
template UEField ObjectArray::FindObjectFast<UEField>(const std::string& FullName, EClassCastFlags RequiredType);
template UEEnum ObjectArray::FindObjectFast<UEEnum>(const std::string& FullName, EClassCastFlags RequiredType);
template UEStruct ObjectArray::FindObjectFast<UEStruct>(const std::string& FullName, EClassCastFlags RequiredType);
template UEClass ObjectArray::FindObjectFast<UEClass>(const std::string& FullName, EClassCastFlags RequiredType);
template UEFunction ObjectArray::FindObjectFast<UEFunction>(const std::string& FullName, EClassCastFlags RequiredType);
template UEProperty ObjectArray::FindObjectFast<UEProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEByteProperty ObjectArray::FindObjectFast<UEByteProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEBoolProperty ObjectArray::FindObjectFast<UEBoolProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEObjectProperty ObjectArray::FindObjectFast<UEObjectProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEClassProperty ObjectArray::FindObjectFast<UEClassProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEStructProperty ObjectArray::FindObjectFast<UEStructProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEArrayProperty ObjectArray::FindObjectFast<UEArrayProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEMapProperty ObjectArray::FindObjectFast<UEMapProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UESetProperty ObjectArray::FindObjectFast<UESetProperty>(const std::string& FullName, EClassCastFlags RequiredType);
template UEEnumProperty ObjectArray::FindObjectFast<UEEnumProperty>(const std::string& FullName, EClassCastFlags RequiredType);

template UEObject ObjectArray::FindObjectFastInOuter<UEObject>(const std::string& FullName, std::string Outer);
template UEField ObjectArray::FindObjectFastInOuter<UEField>(const std::string& FullName, std::string Outer);
template UEEnum ObjectArray::FindObjectFastInOuter<UEEnum>(const std::string& FullName, std::string Outer);
template UEStruct ObjectArray::FindObjectFastInOuter<UEStruct>(const std::string& FullName, std::string Outer);
template UEClass ObjectArray::FindObjectFastInOuter<UEClass>(const std::string& FullName, std::string Outer);
template UEFunction ObjectArray::FindObjectFastInOuter<UEFunction>(const std::string& FullName, std::string Outer);
template UEProperty ObjectArray::FindObjectFastInOuter<UEProperty>(const std::string& FullName, std::string Outer);
template UEByteProperty ObjectArray::FindObjectFastInOuter<UEByteProperty>(const std::string& FullName, std::string Outer);
template UEBoolProperty ObjectArray::FindObjectFastInOuter<UEBoolProperty>(const std::string& FullName, std::string Outer);
template UEObjectProperty ObjectArray::FindObjectFastInOuter<UEObjectProperty>(const std::string& FullName, std::string Outer);
template UEClassProperty ObjectArray::FindObjectFastInOuter<UEClassProperty>(const std::string& FullName, std::string Outer);
template UEStructProperty ObjectArray::FindObjectFastInOuter<UEStructProperty>(const std::string& FullName, std::string Outer);
template UEArrayProperty ObjectArray::FindObjectFastInOuter<UEArrayProperty>(const std::string& FullName, std::string Outer);
template UEMapProperty ObjectArray::FindObjectFastInOuter<UEMapProperty>(const std::string& FullName, std::string Outer);
template UESetProperty ObjectArray::FindObjectFastInOuter<UESetProperty>(const std::string& FullName, std::string Outer);
template UEEnumProperty ObjectArray::FindObjectFastInOuter<UEEnumProperty>(const std::string& FullName, std::string Outer);

template UEObject ObjectArray::GetByIndex<UEObject>(int32 Index);
template UEField ObjectArray::GetByIndex<UEField>(int32 Index);
template UEEnum ObjectArray::GetByIndex<UEEnum>(int32 Index);
template UEStruct ObjectArray::GetByIndex<UEStruct>(int32 Index);
template UEClass ObjectArray::GetByIndex<UEClass>(int32 Index);
template UEFunction ObjectArray::GetByIndex<UEFunction>(int32 Index);
template UEProperty ObjectArray::GetByIndex<UEProperty>(int32 Index);
template UEByteProperty ObjectArray::GetByIndex<UEByteProperty>(int32 Index);
template UEBoolProperty ObjectArray::GetByIndex<UEBoolProperty>(int32 Index);
template UEObjectProperty ObjectArray::GetByIndex<UEObjectProperty>(int32 Index);
template UEClassProperty ObjectArray::GetByIndex<UEClassProperty>(int32 Index);
template UEStructProperty ObjectArray::GetByIndex<UEStructProperty>(int32 Index);
template UEArrayProperty ObjectArray::GetByIndex<UEArrayProperty>(int32 Index);
template UEMapProperty ObjectArray::GetByIndex<UEMapProperty>(int32 Index);
template UESetProperty ObjectArray::GetByIndex<UESetProperty>(int32 Index);
template UEEnumProperty ObjectArray::GetByIndex<UEEnumProperty>(int32 Index);
