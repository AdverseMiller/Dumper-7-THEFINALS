#pragma once

#include <bit>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace Discovery
{
	inline constexpr bool Enabled = true;
	inline constexpr bool ProbeOnly = false;

	inline std::uint32_t ElementsPerChunk = 0;
	inline constexpr std::uint32_t FUObjectItemSize = 0x14;
	inline std::uint32_t ObjectCount = 0;
	inline std::uint64_t GlobalRva = 0;
	inline std::string GlobalModel = "unresolved";
	inline std::uint32_t GlobalRotate = 0;
	inline std::uint32_t GlobalCountOffset = 0;
	inline std::uint32_t GlobalCountXor = 0;
	inline std::uint32_t GlobalChunksOffset = 0;
	inline std::uint64_t GlobalChunksXor = 0;
	inline std::array<std::uint8_t, 16> GlobalMask{};
	inline std::array<std::uint8_t, 16> GlobalShuffle{};
	inline std::uint64_t ProcessEventDispatcherRva = 0;

	inline std::uint32_t FunctionFlagsXorKey = 0;
	inline std::uint32_t PropertyOffsetXorKey = 0;
	inline std::uint64_t PropertyFlagsXorKey = 0;

	inline bool UObjectDecoderReady = false;
	inline bool ProtectedHashReady = false;
	inline std::uint32_t ProtectedAddressOffset = 0;
	inline std::uint32_t ProtectedHashHighShift = 0;
	inline std::uint32_t ProtectedHashRotate1 = 0;
	inline std::uint32_t ProtectedHashRotate2 = 0;
	inline std::uint32_t ProtectedHashRotate3 = 0;
	inline std::uint32_t ProtectedHashFinalShift = 0;
	inline std::uint32_t ProtectedHashFoldShift = 0;
	inline std::uint32_t ProtectedHashMultiplier = 0;
	inline std::uint32_t ProtectedHashAddend = 0;
	inline std::uint32_t ProtectedHashSlotIncrement = 0;
	inline std::uint32_t ProtectedHashSlotMask = 0;
	inline std::uint32_t ProtectedSlotDataOffset = 0;
	inline std::uint32_t ProtectedSlotStride = 0;
	inline std::uint32_t ProtectedSlotRotate = 0;
	inline std::array<std::uint8_t, 16> ProtectedSlotMask{};
	inline std::array<std::uint8_t, 16> ProtectedSlotShuffle{};
	inline std::array<std::uint8_t, 4> ProtectedClassSlots{};
	inline std::array<std::uint8_t, 4> ProtectedOuterSlots{};
	inline std::array<std::uint8_t, 4> ProtectedNameSlots{};

	inline bool FieldNameDecoderReady = false;
	inline std::uint32_t FieldNameOffset = 0;
	inline std::uint32_t FieldNameWordRotate = 0;
	inline std::uint32_t FieldNameResultRotate = 0;
	inline std::uint64_t FieldNameXorKey = 0;
	inline std::array<std::uint8_t, 8> FieldNameShuffle{};

	inline std::uint32_t HashProtectedAddress(const std::uintptr_t Address)
	{
		std::uint32_t Hash = static_cast<std::uint32_t>(Address);
		const std::uint32_t High = static_cast<std::uint32_t>(Address >> ProtectedHashHighShift);

		Hash = std::rotl(Hash, static_cast<int>(ProtectedHashRotate1)) * ProtectedHashMultiplier + ProtectedHashAddend;
		Hash = std::rotl(Hash, static_cast<int>(ProtectedHashRotate2)) * ProtectedHashMultiplier + High + ProtectedHashAddend;
		Hash = std::rotl(Hash, static_cast<int>(ProtectedHashRotate3)) * ProtectedHashMultiplier + ProtectedHashAddend;
		Hash = (Hash >> ProtectedHashFinalShift) * ProtectedHashMultiplier + ProtectedHashAddend;
		return Hash;
	}

	inline std::uint32_t GetProtectedSlot(const void* Object)
	{
		const auto Address = reinterpret_cast<std::uintptr_t>(Object) + ProtectedAddressOffset;
		const std::uint32_t Hash = HashProtectedAddress(Address);
		return (Hash ^ (Hash >> ProtectedHashFoldShift)) & ProtectedHashSlotMask;
	}

	inline std::uint64_t DecodeProtectedSlot(const void* Object, const std::uint32_t Slot)
	{
		std::uint8_t Mixed[16];
		const auto* Encoded = static_cast<const std::uint8_t*>(Object) + ProtectedSlotDataOffset + ((Slot & 0x3) * ProtectedSlotStride);
		for (std::size_t i = 0; i < sizeof(Mixed); ++i)
			Mixed[i] = Encoded[i] ^ ProtectedSlotMask[i];

		std::uint64_t Lanes[2];
		std::memcpy(Lanes, Mixed, sizeof(Lanes));
		for (std::uint64_t& Lane : Lanes)
			Lane = std::rotl(Lane, static_cast<int>(ProtectedSlotRotate));

		std::uint8_t Shuffled[16];
		const auto* Bytes = reinterpret_cast<const std::uint8_t*>(Lanes);
		for (std::size_t i = 0; i < sizeof(Shuffled); ++i)
			Shuffled[i] = (ProtectedSlotShuffle[i] & 0x80) ? 0 : Bytes[ProtectedSlotShuffle[i] & 0x0F];

		std::uint64_t Result;
		std::memcpy(&Result, Shuffled, sizeof(Result));
		return Result;
	}

	inline void* GetClass(const void* Object)
	{
		const std::uint32_t BaseSlot = GetProtectedSlot(Object) & 0x3;
		return reinterpret_cast<void*>(DecodeProtectedSlot(Object, ProtectedClassSlots[BaseSlot]));
	}

	inline void* GetOuter(const void* Object)
	{
		const std::uint32_t BaseSlot = GetProtectedSlot(Object) & 0x3;
		return reinterpret_cast<void*>(DecodeProtectedSlot(Object, ProtectedOuterSlots[BaseSlot]));
	}

	inline std::uint64_t GetName(const void* Object)
	{
		const std::uint32_t BaseSlot = GetProtectedSlot(Object) & 0x3;
		return std::rotl(DecodeProtectedSlot(Object, ProtectedNameSlots[BaseSlot]), 32);
	}

	inline std::uint64_t GetFieldName(const void* Field)
	{
		std::uint8_t Input[16];
		std::memcpy(Input, static_cast<const std::uint8_t*>(Field) + FieldNameOffset, sizeof(Input));

		std::uint8_t Shuffled[8];
		for (std::size_t i = 0; i < sizeof(Shuffled); ++i)
			Shuffled[i] = Input[FieldNameShuffle[i]];

		std::uint16_t Words[4];
		std::memcpy(Words, Shuffled, sizeof(Words));
		for (std::uint16_t& Word : Words)
			Word = std::rotl(Word, static_cast<int>(FieldNameWordRotate));

		std::uint64_t Result;
		std::memcpy(&Result, Words, sizeof(Result));
		return std::rotl(Result ^ FieldNameXorKey, static_cast<int>(FieldNameResultRotate));
	}
}
