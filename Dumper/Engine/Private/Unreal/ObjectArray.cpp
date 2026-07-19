
#include <iostream>
#include <fstream>
#include <format>
#include <filesystem>
#include <array>
#include <stdexcept>
#include <unordered_set>

#include <capstone/capstone.h>
#include <capstone/x86.h>

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
	std::uint8_t** DiscoveredChunkTable = nullptr;

	struct DiscoveryGlobalDecoder
	{
		std::uint8_t* ProtectedGlobal = nullptr;
		std::array<std::uint8_t, 16> Mask{};
		std::array<std::uint8_t, 16> Shuffle{};
		std::uint32_t Rotate = 0;
		std::uint32_t CountOffset = 0;
		std::uint32_t CountXor = 0;
		std::uint32_t ChunksOffset = 0;
		std::uint64_t ChunksXor = 0;
	};

	DiscoveryGlobalDecoder GlobalDecoder;

	struct DiscoveredObjectArray
	{
		std::vector<std::uint8_t*> Chunks;
		std::uint32_t ItemSize = 0;
		std::uint32_t InternalIndexOffset = 0;
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

	bool IsReadableMemoryRegion(const MEMORY_BASIC_INFORMATION& MemoryInfo)
	{
		constexpr DWORD ReadableMask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
		constexpr DWORD InaccessibleMask = PAGE_GUARD | PAGE_NOACCESS;
		return MemoryInfo.State == MEM_COMMIT && (MemoryInfo.Protect & ReadableMask) && !(MemoryInfo.Protect & InaccessibleMask);
	}

	bool IsPlausibleObject(const std::uint8_t* Object, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd)
	{
		const std::uintptr_t ObjectAddress = reinterpret_cast<std::uintptr_t>(Object);
		if (ObjectAddress < 0x10000 || (ObjectAddress & (alignof(void*) - 1)) != 0)
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
		const auto ScanMemory = [&](const bool LikelyChunkRegionsOnly)
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
				std::vector<std::uint8_t> Snapshot(Size);
				if (!TryReadMemory(Region, Snapshot.data(), Snapshot.size()))
					return false;

				for (size_t Offset = 0; Offset + 0x2000 < Size; Offset += sizeof(std::uint32_t))
				{
					auto* Candidate = Region + Offset;
					const std::uint8_t* FirstObject = nullptr;
					std::memcpy(&FirstObject, Snapshot.data() + Offset, sizeof(FirstObject));

					if (!IsPlausibleObject(FirstObject, ModuleBase, ModuleEnd))
						continue;

					for (std::uint32_t IndexOffset = 0x8; IndexOffset <= 0x40; IndexOffset += sizeof(std::uint32_t))
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

		ScanMemory(true);
		if (!bFound)
			ScanMemory(false);

		return bFound;
	}

	bool DiscoverObjectChunks(const char* const ModuleName, DiscoveredObjectArray& Result)
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

	std::uint64_t ByteSwap64(std::uint64_t Value)
	{
		return ((Value & 0x00000000000000FFull) << 56) |
			((Value & 0x000000000000FF00ull) << 40) |
			((Value & 0x0000000000FF0000ull) << 24) |
			((Value & 0x00000000FF000000ull) << 8) |
			((Value & 0x000000FF00000000ull) >> 8) |
			((Value & 0x0000FF0000000000ull) >> 24) |
			((Value & 0x00FF000000000000ull) >> 40) |
			((Value & 0xFF00000000000000ull) >> 56);
	}

	std::uint32_t ByteSwap32(const std::uint32_t Value)
	{
		return ((Value & 0x000000FFu) << 24) |
			((Value & 0x0000FF00u) << 8) |
			((Value & 0x00FF0000u) >> 8) |
			((Value & 0xFF000000u) >> 24);
	}

	struct SemanticGlobalCandidate
	{
		std::uint8_t* Global = nullptr;
		std::uint8_t** Chunks = nullptr;
		std::int32_t Num = 0;
	};

	struct ConcreteScalar
	{
		bool Known = false;
		std::uint64_t Value = 0;
	};

	struct ConcreteVector
	{
		bool Known = false;
		std::array<std::uint8_t, 16> Bytes{};
	};

	struct ConcreteState
	{
		std::array<ConcreteScalar, 16> Gpr{};
		std::array<ConcreteVector, 32> Xmm{};
	};

	int GetGprIndex(const x86_reg Register, bool& Is32Bit)
	{
		Is32Bit = false;
		switch (Register)
		{
		case X86_REG_RAX: return 0;
		case X86_REG_RCX: return 1;
		case X86_REG_RDX: return 2;
		case X86_REG_RBX: return 3;
		case X86_REG_RSP: return 4;
		case X86_REG_RBP: return 5;
		case X86_REG_RSI: return 6;
		case X86_REG_RDI: return 7;
		case X86_REG_R8: return 8;
		case X86_REG_R9: return 9;
		case X86_REG_R10: return 10;
		case X86_REG_R11: return 11;
		case X86_REG_R12: return 12;
		case X86_REG_R13: return 13;
		case X86_REG_R14: return 14;
		case X86_REG_R15: return 15;
		case X86_REG_EAX: Is32Bit = true; return 0;
		case X86_REG_ECX: Is32Bit = true; return 1;
		case X86_REG_EDX: Is32Bit = true; return 2;
		case X86_REG_EBX: Is32Bit = true; return 3;
		case X86_REG_ESP: Is32Bit = true; return 4;
		case X86_REG_EBP: Is32Bit = true; return 5;
		case X86_REG_ESI: Is32Bit = true; return 6;
		case X86_REG_EDI: Is32Bit = true; return 7;
		case X86_REG_R8D: Is32Bit = true; return 8;
		case X86_REG_R9D: Is32Bit = true; return 9;
		case X86_REG_R10D: Is32Bit = true; return 10;
		case X86_REG_R11D: Is32Bit = true; return 11;
		case X86_REG_R12D: Is32Bit = true; return 12;
		case X86_REG_R13D: Is32Bit = true; return 13;
		case X86_REG_R14D: Is32Bit = true; return 14;
		case X86_REG_R15D: Is32Bit = true; return 15;
		default: return -1;
		}
	}

	int GetXmmIndex(const x86_reg Register)
	{
		return Register >= X86_REG_XMM0 && Register <= X86_REG_XMM31 ? static_cast<int>(Register - X86_REG_XMM0) : -1;
	}

	bool GetConcreteAddress(const cs_insn& Instruction, const x86_op_mem& Memory, const ConcreteState& State, std::uintptr_t& Address)
	{
		std::uint64_t Result = static_cast<std::uint64_t>(Memory.disp);
		if (Memory.base == X86_REG_RIP)
		{
			Result += Instruction.address + Instruction.size;
		}
		else if (Memory.base != X86_REG_INVALID)
		{
			bool Is32Bit = false;
			const int Index = GetGprIndex(Memory.base, Is32Bit);
			if (Index < 0 || !State.Gpr[Index].Known)
				return false;
			Result += State.Gpr[Index].Value;
		}

		if (Memory.index != X86_REG_INVALID)
		{
			bool Is32Bit = false;
			const int Index = GetGprIndex(Memory.index, Is32Bit);
			if (Index < 0 || !State.Gpr[Index].Known)
				return false;
			Result += State.Gpr[Index].Value * Memory.scale;
		}

		Address = static_cast<std::uintptr_t>(Result);
		return true;
	}

	bool ReadConcreteScalar(const cs_insn& Instruction, const cs_x86_op& Operand, const ConcreteState& State, std::uint64_t& Value)
	{
		if (Operand.type == X86_OP_IMM)
		{
			Value = static_cast<std::uint64_t>(Operand.imm);
			return true;
		}
		if (Operand.type == X86_OP_REG)
		{
			bool Is32Bit = false;
			const int Index = GetGprIndex(Operand.reg, Is32Bit);
			if (Index < 0 || !State.Gpr[Index].Known)
				return false;
			Value = Is32Bit ? static_cast<std::uint32_t>(State.Gpr[Index].Value) : State.Gpr[Index].Value;
			return true;
		}
		if (Operand.type == X86_OP_MEM)
		{
			std::uintptr_t Address = 0;
			if (!GetConcreteAddress(Instruction, Operand.mem, State, Address) || Operand.size == 0 || Operand.size > sizeof(Value))
				return false;
			Value = 0;
			return TryReadMemory(reinterpret_cast<const void*>(Address), &Value, Operand.size);
		}
		return false;
	}

	void WriteConcreteScalar(const cs_x86_op& Operand, ConcreteState& State, const bool Known, std::uint64_t Value)
	{
		if (Operand.type != X86_OP_REG)
			return;
		bool Is32Bit = false;
		const int Index = GetGprIndex(Operand.reg, Is32Bit);
		if (Index < 0)
			return;
		State.Gpr[Index].Known = Known;
		State.Gpr[Index].Value = Is32Bit ? static_cast<std::uint32_t>(Value) : Value;
	}

	bool ReadConcreteVector(const cs_insn& Instruction, const cs_x86_op& Operand, const ConcreteState& State, ConcreteVector& Value)
	{
		if (Operand.type == X86_OP_REG)
		{
			const int Index = GetXmmIndex(Operand.reg);
			if (Index < 0 || !State.Xmm[Index].Known)
				return false;
			Value = State.Xmm[Index];
			return true;
		}
		if (Operand.type == X86_OP_MEM && Operand.size == 16)
		{
			std::uintptr_t Address = 0;
			if (!GetConcreteAddress(Instruction, Operand.mem, State, Address))
				return false;
			Value.Known = TryReadMemory(reinterpret_cast<const void*>(Address), Value.Bytes.data(), Value.Bytes.size());
			return Value.Known;
		}
		return false;
	}

	void WriteConcreteVector(const cs_x86_op& Operand, ConcreteState& State, const ConcreteVector& Value)
	{
		if (Operand.type != X86_OP_REG)
			return;
		const int Index = GetXmmIndex(Operand.reg);
		if (Index >= 0)
			State.Xmm[Index] = Value;
	}

	void InvalidateWrittenOperands(const cs_x86& X86, ConcreteState& State)
	{
		for (std::uint8_t OperandIndex = 0; OperandIndex < X86.op_count; ++OperandIndex)
		{
			const cs_x86_op& Operand = X86.operands[OperandIndex];
			if (Operand.type != X86_OP_REG || (Operand.access & CS_AC_WRITE) == 0)
				continue;

			bool Is32Bit = false;
			const int GprIndex = GetGprIndex(Operand.reg, Is32Bit);
			if (GprIndex >= 0)
				State.Gpr[GprIndex] = {};

			const int XmmIndex = GetXmmIndex(Operand.reg);
			if (XmmIndex >= 0)
				State.Xmm[XmmIndex] = {};
		}
	}

	bool IsVectorMoveInstruction(const unsigned int InstructionId)
	{
		return InstructionId == X86_INS_MOVDQA || InstructionId == X86_INS_MOVDQU || InstructionId == X86_INS_MOVAPS || InstructionId == X86_INS_MOVUPS ||
			InstructionId == X86_INS_VMOVDQA || InstructionId == X86_INS_VMOVDQA32 || InstructionId == X86_INS_VMOVDQA64 || InstructionId == X86_INS_VMOVDQU ||
			InstructionId == X86_INS_VMOVDQU8 || InstructionId == X86_INS_VMOVDQU16 || InstructionId == X86_INS_VMOVDQU32 || InstructionId == X86_INS_VMOVDQU64 ||
			InstructionId == X86_INS_VMOVAPS || InstructionId == X86_INS_VMOVUPS;
	}

	bool IsVectorXorInstruction(const unsigned int InstructionId)
	{
		return InstructionId == X86_INS_PXOR || InstructionId == X86_INS_VPXOR || InstructionId == X86_INS_VPXORD || InstructionId == X86_INS_VPXORQ;
	}

	bool IsVectorOrInstruction(const unsigned int InstructionId)
	{
		return InstructionId == X86_INS_POR || InstructionId == X86_INS_VPOR || InstructionId == X86_INS_VPORD || InstructionId == X86_INS_VPORQ;
	}

	bool IsVectorShuffleInstruction(const unsigned int InstructionId)
	{
		return InstructionId == X86_INS_PSHUFB || InstructionId == X86_INS_VPSHUFB;
	}

	bool IsVectorShiftInstruction(const unsigned int InstructionId)
	{
		return InstructionId == X86_INS_PSLLD || InstructionId == X86_INS_PSRLD || InstructionId == X86_INS_PSLLQ || InstructionId == X86_INS_PSRLQ ||
			InstructionId == X86_INS_VPSLLD || InstructionId == X86_INS_VPSRLD || InstructionId == X86_INS_VPSLLQ || InstructionId == X86_INS_VPSRLQ;
	}

	template<typename LaneType, typename Operation>
	void TransformVectorLanes(ConcreteVector& Value, Operation&& Transform)
	{
		for (std::size_t Offset = 0; Offset < Value.Bytes.size(); Offset += sizeof(LaneType))
		{
			LaneType Lane = 0;
			std::memcpy(&Lane, Value.Bytes.data() + Offset, sizeof(Lane));
			Lane = Transform(Lane);
			std::memcpy(Value.Bytes.data() + Offset, &Lane, sizeof(Lane));
		}
	}

	void ObserveConcreteValue(const std::uint64_t Value, const std::uint8_t Width, std::uint8_t* ExpectedFirstChunk, std::unordered_set<std::int32_t>& Counts, std::unordered_set<std::uint8_t**>& ChunkTables)
	{
		if (Width == 4)
		{
			const std::int32_t Count = static_cast<std::int32_t>(Value);
			if (Count >= 0x1000 && Count < 0x800000)
				Counts.insert(Count);
		}
		if (Width != 8 || Value < 0x10000 || (Value & (alignof(void*) - 1)) != 0)
			return;

		auto** Candidate = reinterpret_cast<std::uint8_t**>(Value);
		std::uint8_t* FirstChunk = nullptr;
		if (TryReadValue(Candidate, FirstChunk) && FirstChunk == ExpectedFirstChunk)
			ChunkTables.insert(Candidate);
	}

	std::vector<SemanticGlobalCandidate> EvaluateObjectAccessor(const csh Handle, const std::uint8_t* Begin, const std::size_t Size, const std::uint64_t Address, std::uint8_t* ExpectedFirstChunk, std::uint8_t* Global)
	{
		ConcreteState State;
		std::unordered_set<std::int32_t> Counts;
		std::unordered_set<std::uint8_t**> ChunkTables;
		const std::uint8_t* Code = Begin;
		std::size_t Remaining = Size;
		std::uint64_t CurrentAddress = Address;
		cs_insn* Instruction = cs_malloc(Handle);
		if (!Instruction)
			return {};

		for (int InstructionCount = 0; InstructionCount < 80 && Remaining > 0 && cs_disasm_iter(Handle, &Code, &Remaining, &CurrentAddress, Instruction); ++InstructionCount)
		{
			if (!Instruction->detail)
				break;

			const cs_x86& X86 = Instruction->detail->x86;
			const auto& Operands = X86.operands;
			const std::uint8_t OperandCount = X86.op_count;
			bool Handled = true;
			if (OperandCount >= 2 && IsVectorMoveInstruction(Instruction->id))
			{
				ConcreteVector Value;
				Value.Known = ReadConcreteVector(*Instruction, Operands[1], State, Value);
				WriteConcreteVector(Operands[0], State, Value);
			}
			else if (OperandCount >= 2 && (IsVectorXorInstruction(Instruction->id) || IsVectorOrInstruction(Instruction->id)))
			{
				ConcreteVector Left;
				ConcreteVector Right;
				const cs_x86_op& LeftOperand = OperandCount >= 3 ? Operands[1] : Operands[0];
				const cs_x86_op& RightOperand = OperandCount >= 3 ? Operands[2] : Operands[1];
				const bool Known = ReadConcreteVector(*Instruction, LeftOperand, State, Left) && ReadConcreteVector(*Instruction, RightOperand, State, Right);
				if (Known)
				{
					for (std::size_t Index = 0; Index < Left.Bytes.size(); ++Index)
						Left.Bytes[Index] = IsVectorXorInstruction(Instruction->id) ? Left.Bytes[Index] ^ Right.Bytes[Index] : Left.Bytes[Index] | Right.Bytes[Index];
				}
				Left.Known = Known;
				WriteConcreteVector(Operands[0], State, Left);
			}
			else if (OperandCount >= 2 && IsVectorShuffleInstruction(Instruction->id))
			{
				ConcreteVector Input;
				ConcreteVector Control;
				const cs_x86_op& InputOperand = OperandCount >= 3 ? Operands[1] : Operands[0];
				const cs_x86_op& ControlOperand = OperandCount >= 3 ? Operands[2] : Operands[1];
				const bool Known = ReadConcreteVector(*Instruction, InputOperand, State, Input) && ReadConcreteVector(*Instruction, ControlOperand, State, Control);
				ConcreteVector Output;
				Output.Known = Known;
				if (Known)
				{
					for (std::size_t Index = 0; Index < Output.Bytes.size(); ++Index)
						Output.Bytes[Index] = (Control.Bytes[Index] & 0x80) ? 0 : Input.Bytes[Control.Bytes[Index] & 0x0F];
				}
				WriteConcreteVector(Operands[0], State, Output);
			}
			else if (OperandCount >= 2 && IsVectorShiftInstruction(Instruction->id))
			{
				ConcreteVector Value;
				std::uint64_t Shift = 0;
				const cs_x86_op& InputOperand = OperandCount >= 3 ? Operands[1] : Operands[0];
				const cs_x86_op& ShiftOperand = OperandCount >= 3 ? Operands[2] : Operands[1];
				const bool Known = ReadConcreteVector(*Instruction, InputOperand, State, Value) && ReadConcreteScalar(*Instruction, ShiftOperand, State, Shift);
				if (Known)
				{
					if (Instruction->id == X86_INS_PSLLD || Instruction->id == X86_INS_VPSLLD) TransformVectorLanes<std::uint32_t>(Value, [&](const std::uint32_t Lane) { return Shift < 32 ? Lane << Shift : 0u; });
					if (Instruction->id == X86_INS_PSRLD || Instruction->id == X86_INS_VPSRLD) TransformVectorLanes<std::uint32_t>(Value, [&](const std::uint32_t Lane) { return Shift < 32 ? Lane >> Shift : 0u; });
					if (Instruction->id == X86_INS_PSLLQ || Instruction->id == X86_INS_VPSLLQ) TransformVectorLanes<std::uint64_t>(Value, [&](const std::uint64_t Lane) { return Shift < 64 ? Lane << Shift : 0ull; });
					if (Instruction->id == X86_INS_PSRLQ || Instruction->id == X86_INS_VPSRLQ) TransformVectorLanes<std::uint64_t>(Value, [&](const std::uint64_t Lane) { return Shift < 64 ? Lane >> Shift : 0ull; });
				}
				Value.Known = Known;
				WriteConcreteVector(Operands[0], State, Value);
			}
			else if (OperandCount >= 2 && (Instruction->id == X86_INS_MOVQ || Instruction->id == X86_INS_VMOVQ))
			{
				const int DestinationXmm = Operands[0].type == X86_OP_REG ? GetXmmIndex(Operands[0].reg) : -1;
				const int SourceXmm = Operands[1].type == X86_OP_REG ? GetXmmIndex(Operands[1].reg) : -1;
				if (DestinationXmm >= 0)
				{
					std::uint64_t Scalar = 0;
					ConcreteVector Value;
					Value.Known = ReadConcreteScalar(*Instruction, Operands[1], State, Scalar);
					if (Value.Known)
						std::memcpy(Value.Bytes.data(), &Scalar, sizeof(Scalar));
					WriteConcreteVector(Operands[0], State, Value);
				}
				else if (SourceXmm >= 0)
				{
					std::uint64_t Scalar = 0;
					const bool Known = State.Xmm[SourceXmm].Known;
					if (Known)
						std::memcpy(&Scalar, State.Xmm[SourceXmm].Bytes.data(), sizeof(Scalar));
					WriteConcreteScalar(Operands[0], State, Known, Scalar);
					if (Known)
						ObserveConcreteValue(Scalar, Operands[0].size, ExpectedFirstChunk, Counts, ChunkTables);
				}
			}
			else if (OperandCount >= 2 && (Instruction->id == X86_INS_MOV || Instruction->id == X86_INS_MOVABS || Instruction->id == X86_INS_LEA))
			{
				std::uint64_t Value = 0;
				bool Known = false;
				if (Instruction->id == X86_INS_LEA && Operands[1].type == X86_OP_MEM)
				{
					std::uintptr_t Address = 0;
					Known = GetConcreteAddress(*Instruction, Operands[1].mem, State, Address);
					Value = Address;
				}
				else
				{
					Known = ReadConcreteScalar(*Instruction, Operands[1], State, Value);
				}
				WriteConcreteScalar(Operands[0], State, Known, Value);
				if (Known)
					ObserveConcreteValue(Value, Operands[0].size, ExpectedFirstChunk, Counts, ChunkTables);
			}
			else if (OperandCount >= 2 && (Instruction->id == X86_INS_XOR || Instruction->id == X86_INS_OR || Instruction->id == X86_INS_AND || Instruction->id == X86_INS_ADD || Instruction->id == X86_INS_SUB || Instruction->id == X86_INS_IMUL))
			{
				std::uint64_t Left = 0;
				std::uint64_t Right = 0;
				const cs_x86_op& LeftOperand = Operands[0];
				const cs_x86_op& RightOperand = OperandCount >= 3 && Instruction->id == X86_INS_IMUL ? Operands[2] : Operands[1];
				const cs_x86_op& SourceOperand = OperandCount >= 3 && Instruction->id == X86_INS_IMUL ? Operands[1] : Operands[0];
				const bool Known = ReadConcreteScalar(*Instruction, SourceOperand, State, Left) && ReadConcreteScalar(*Instruction, RightOperand, State, Right);
				if (Known)
				{
					if (Instruction->id == X86_INS_XOR) Left ^= Right;
					if (Instruction->id == X86_INS_OR) Left |= Right;
					if (Instruction->id == X86_INS_AND) Left &= Right;
					if (Instruction->id == X86_INS_ADD) Left += Right;
					if (Instruction->id == X86_INS_SUB) Left -= Right;
					if (Instruction->id == X86_INS_IMUL) Left *= Right;
				}
				WriteConcreteScalar(LeftOperand, State, Known, Left);
				if (Known)
					ObserveConcreteValue(Left, LeftOperand.size, ExpectedFirstChunk, Counts, ChunkTables);
			}
			else if (OperandCount >= 2 && (Instruction->id == X86_INS_ROL || Instruction->id == X86_INS_ROR || Instruction->id == X86_INS_SHL || Instruction->id == X86_INS_SHR))
			{
				std::uint64_t Value = 0;
				std::uint64_t Shift = 0;
				const bool Known = ReadConcreteScalar(*Instruction, Operands[0], State, Value) && ReadConcreteScalar(*Instruction, Operands[1], State, Shift);
				if (Known)
				{
					if (Operands[0].size == 4)
					{
						std::uint32_t Narrow = static_cast<std::uint32_t>(Value);
						const std::uint32_t MaskedShift = static_cast<std::uint32_t>(Shift) & 31u;
						if (Instruction->id == X86_INS_ROL) Narrow = std::rotl(Narrow, static_cast<int>(MaskedShift));
						if (Instruction->id == X86_INS_ROR) Narrow = std::rotr(Narrow, static_cast<int>(MaskedShift));
						if (Instruction->id == X86_INS_SHL) Narrow <<= MaskedShift;
						if (Instruction->id == X86_INS_SHR) Narrow >>= MaskedShift;
						Value = Narrow;
					}
					else
					{
						const std::uint32_t MaskedShift = static_cast<std::uint32_t>(Shift) & 63u;
						if (Instruction->id == X86_INS_ROL) Value = std::rotl(Value, static_cast<int>(MaskedShift));
						if (Instruction->id == X86_INS_ROR) Value = std::rotr(Value, static_cast<int>(MaskedShift));
						if (Instruction->id == X86_INS_SHL) Value <<= MaskedShift;
						if (Instruction->id == X86_INS_SHR) Value >>= MaskedShift;
					}
				}
				WriteConcreteScalar(Operands[0], State, Known, Value);
				if (Known)
					ObserveConcreteValue(Value, Operands[0].size, ExpectedFirstChunk, Counts, ChunkTables);
			}
			else if (OperandCount >= 1 && Instruction->id == X86_INS_BSWAP)
			{
				std::uint64_t Value = 0;
				const bool Known = ReadConcreteScalar(*Instruction, Operands[0], State, Value);
				if (Known)
					Value = Operands[0].size == 4 ? ByteSwap32(static_cast<std::uint32_t>(Value)) : ByteSwap64(Value);
				WriteConcreteScalar(Operands[0], State, Known, Value);
				if (Known)
					ObserveConcreteValue(Value, Operands[0].size, ExpectedFirstChunk, Counts, ChunkTables);
			}
			else if (Instruction->id == X86_INS_RET || Instruction->id == X86_INS_RETF || Instruction->id == X86_INS_RETFQ || Instruction->id == X86_INS_JMP)
			{
				break;
			}
			else
			{
				Handled = false;
			}

			if (!Handled)
				InvalidateWrittenOperands(X86, State);
		}

		cs_free(Instruction, 1);
		std::vector<SemanticGlobalCandidate> Results;
		for (std::uint8_t** Chunks : ChunkTables)
		{
			for (const std::int32_t Count : Counts)
				Results.push_back({ Global, Chunks, Count });
		}
		return Results;
	}

	std::vector<SemanticGlobalCandidate> FindSemanticDiscoveryGlobals(const char* const ModuleName, std::uint8_t* ExpectedFirstChunk)
	{
		const std::uintptr_t ModuleBase = Platform::GetModuleBase(ModuleName);
		const auto* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(ModuleBase);
		if (!ModuleBase || Platform::IsBadReadPtr(DosHeader) || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return {};
		const auto* NtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(ModuleBase + DosHeader->e_lfanew);
		if (Platform::IsBadReadPtr(NtHeaders) || NtHeaders->Signature != IMAGE_NT_SIGNATURE)
			return {};

		csh Handle = 0;
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
			return {};
		cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);

		std::vector<SemanticGlobalCandidate> Results;
		const auto* Section = IMAGE_FIRST_SECTION(NtHeaders);
		for (std::uint16_t SectionIndex = 0; SectionIndex < NtHeaders->FileHeader.NumberOfSections; ++SectionIndex)
		{
			if ((Section[SectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
				continue;
			if (Section[SectionIndex].VirtualAddress >= NtHeaders->OptionalHeader.SizeOfImage)
				continue;
			const auto* SectionBegin = reinterpret_cast<const std::uint8_t*>(ModuleBase + Section[SectionIndex].VirtualAddress);
			const auto* SectionEnd = SectionBegin + std::min<std::size_t>(Section[SectionIndex].Misc.VirtualSize, NtHeaders->OptionalHeader.SizeOfImage - Section[SectionIndex].VirtualAddress);
			for (const std::uint8_t* RegionCursor = SectionBegin; RegionCursor < SectionEnd;)
			{
				MEMORY_BASIC_INFORMATION MemoryInfo{};
				if (!VirtualQuery(RegionCursor, &MemoryInfo, sizeof(MemoryInfo)))
					break;
				const auto* RegionEnd = std::min(SectionEnd, reinterpret_cast<const std::uint8_t*>(MemoryInfo.BaseAddress) + MemoryInfo.RegionSize);
				if (RegionEnd <= RegionCursor)
					break;
				if (!IsReadableMemoryRegion(MemoryInfo))
				{
					RegionCursor = RegionEnd;
					continue;
				}

				const std::uint8_t* Cursor = RegionCursor;
				std::size_t Remaining = static_cast<std::size_t>(RegionEnd - RegionCursor);
				std::uint64_t Address = reinterpret_cast<std::uint64_t>(RegionCursor);
				cs_insn* Instruction = cs_malloc(Handle);
				if (!Instruction)
				{
					RegionCursor = RegionEnd;
					continue;
				}

				while (Remaining > 0)
				{
					const std::uint8_t* InstructionBegin = Cursor;
					const std::size_t RemainingBefore = Remaining;
					const std::uint64_t InstructionAddress = Address;
					if (!cs_disasm_iter(Handle, &Cursor, &Remaining, &Address, Instruction))
					{
						Cursor = InstructionBegin + 1;
						Remaining = RemainingBefore - 1;
						Address = InstructionAddress + 1;
						continue;
					}

					if (!Instruction->detail)
						continue;
					const cs_x86& X86 = Instruction->detail->x86;
					if (X86.op_count < 2 || X86.operands[0].type != X86_OP_REG || GetXmmIndex(X86.operands[0].reg) < 0 || X86.operands[1].type != X86_OP_MEM || X86.operands[1].mem.base != X86_REG_RIP || X86.operands[1].size != 16)
						continue;
					if (!IsVectorMoveInstruction(Instruction->id))
						continue;

					std::uintptr_t GlobalAddress = 0;
					ConcreteState EmptyState;
					if (!GetConcreteAddress(*Instruction, X86.operands[1].mem, EmptyState, GlobalAddress))
						continue;
					auto Candidates = EvaluateObjectAccessor(Handle, InstructionBegin, std::min<std::size_t>(RemainingBefore, 0x180), InstructionAddress, ExpectedFirstChunk, reinterpret_cast<std::uint8_t*>(GlobalAddress));
					Results.insert(Results.end(), Candidates.begin(), Candidates.end());
				}

				cs_free(Instruction, 1);
				RegionCursor = RegionEnd;
			}
		}
		cs_close(&Handle);

		std::vector<SemanticGlobalCandidate> Unique;
		for (const SemanticGlobalCandidate& Candidate : Results)
		{
			if (std::find_if(Unique.begin(), Unique.end(), [&](const SemanticGlobalCandidate& Existing) { return Existing.Chunks == Candidate.Chunks && Existing.Num == Candidate.Num; }) == Unique.end())
				Unique.push_back(Candidate);
		}
		return Unique;
	}

	std::uint8_t* GetDiscoveryObjectArrayOwner(std::uint8_t* ProtectedGlobal, const DiscoveryGlobalDecoder& Decoder)
	{
		std::uint8_t Mixed[16];
		for (std::size_t i = 0; i < sizeof(Mixed); ++i)
			Mixed[i] = ProtectedGlobal[i] ^ Decoder.Mask[i];

		std::uint64_t Lanes[2];
		std::memcpy(Lanes, Mixed, sizeof(Lanes));
		for (std::uint64_t& Lane : Lanes)
			Lane = std::rotl(Lane, static_cast<int>(Decoder.Rotate));

		std::uint8_t Output[16];
		const auto* Input = reinterpret_cast<const std::uint8_t*>(Lanes);
		for (std::size_t i = 0; i < sizeof(Output); ++i)
			Output[i] = (Decoder.Shuffle[i] & 0x80) ? 0 : Input[Decoder.Shuffle[i] & 0x0F];

		std::uint64_t Owner;
		std::memcpy(&Owner, Output, sizeof(Owner));
		return reinterpret_cast<std::uint8_t*>(Owner);
	}

	std::uint8_t** GetDiscoveryChunks(std::uint8_t* ProtectedGlobal, const DiscoveryGlobalDecoder& Decoder = GlobalDecoder)
	{
		std::uint8_t* Owner = GetDiscoveryObjectArrayOwner(ProtectedGlobal, Decoder);
		return reinterpret_cast<std::uint8_t**>(ByteSwap64(*reinterpret_cast<std::uint64_t*>(Owner + Decoder.ChunksOffset) ^ Decoder.ChunksXor));
	}

	std::int32_t GetDiscoveryNum(std::uint8_t* ProtectedGlobal, const DiscoveryGlobalDecoder& Decoder = GlobalDecoder)
	{
		std::uint8_t* Owner = GetDiscoveryObjectArrayOwner(ProtectedGlobal, Decoder);
		return static_cast<std::int32_t>(ByteSwap32(*reinterpret_cast<std::uint32_t*>(Owner + Decoder.CountOffset) ^ Decoder.CountXor));
	}

	bool ValidateDiscoveryGlobal(const DiscoveryGlobalDecoder& Decoder, std::uint8_t* ExpectedFirstChunk, std::int32_t& Num)
	{
		std::uint8_t* ProtectedGlobal = Decoder.ProtectedGlobal;
		if (Platform::IsBadReadPtr(ProtectedGlobal) || Platform::IsBadReadPtr(ProtectedGlobal + 0xF))
			return false;

		if (std::memcmp(ProtectedGlobal, ProtectedGlobal + sizeof(std::uint64_t), sizeof(std::uint64_t)) != 0)
			return false;

		std::uint8_t* Owner = GetDiscoveryObjectArrayOwner(ProtectedGlobal, Decoder);
		const std::uint32_t LastOwnerOffset = std::max(Decoder.CountOffset + static_cast<std::uint32_t>(sizeof(std::uint32_t)), Decoder.ChunksOffset + static_cast<std::uint32_t>(sizeof(std::uint64_t)));
		if (Platform::IsBadReadPtr(Owner) || Platform::IsBadReadPtr(Owner + LastOwnerOffset - 1))
			return false;

		const std::int32_t CandidateNum = GetDiscoveryNum(ProtectedGlobal, Decoder);
		if (CandidateNum < 0x1000 || CandidateNum >= 0x800000)
			return false;

		std::uint8_t** Chunks = GetDiscoveryChunks(ProtectedGlobal, Decoder);
		if (Platform::IsBadReadPtr(Chunks) || Platform::IsBadReadPtr(Chunks + 1))
			return false;

		if (Chunks[0] != ExpectedFirstChunk)
			return false;

		Num = CandidateNum;
		return true;
	}

	bool ParseOwnerMemberXor32(const std::uint8_t* Begin, const std::uint8_t* End, std::uint32_t& Offset, std::uint32_t& Key)
	{
		for (const std::uint8_t* Cursor = Begin; Cursor + 10 <= End; ++Cursor)
		{
			if (Cursor[0] < 0xB8 || Cursor[0] > 0xBF)
				continue;

			const std::uint8_t Register = Cursor[0] - 0xB8;
			std::uint32_t Immediate;
			std::memcpy(&Immediate, Cursor + 1, sizeof(Immediate));
			const std::uint8_t* Xor = Cursor + 5;
			if (Xor[0] != 0x33 || ((Xor[1] >> 3) & 0x7) != Register || (Xor[1] & 0x7) != 1)
				continue;

			const std::uint8_t Mode = Xor[1] >> 6;
			std::size_t XorSize = 0;
			std::int32_t Displacement = 0;
			if (Mode == 1)
			{
				Displacement = static_cast<std::int8_t>(Xor[2]);
				XorSize = 3;
			}
			else if (Mode == 2)
			{
				std::memcpy(&Displacement, Xor + 2, sizeof(Displacement));
				XorSize = 6;
			}
			else
			{
				continue;
			}

			const std::uint8_t* ByteSwap = Xor + XorSize;
			if (ByteSwap + 2 > End || ByteSwap[0] != 0x0F || ByteSwap[1] != 0xC8 + Register || Displacement < 0 || Displacement > 0x400)
				continue;

			Offset = static_cast<std::uint32_t>(Displacement);
			Key = Immediate;
			return true;
		}

		return false;
	}

	bool ParseOwnerMemberXor64(const std::uint8_t* Begin, const std::uint8_t* End, std::uint32_t& Offset, std::uint64_t& Key)
	{
		for (const std::uint8_t* Cursor = Begin; Cursor + 16 <= End; ++Cursor)
		{
			if (Cursor[0] != 0x48 || Cursor[1] < 0xB8 || Cursor[1] > 0xBF)
				continue;

			const std::uint8_t Register = Cursor[1] - 0xB8;
			std::uint64_t Immediate;
			std::memcpy(&Immediate, Cursor + 2, sizeof(Immediate));
			const std::uint8_t* Xor = Cursor + 10;
			if (Xor[0] != 0x48 || Xor[1] != 0x33 || ((Xor[2] >> 3) & 0x7) != Register || (Xor[2] & 0x7) != 1)
				continue;

			const std::uint8_t Mode = Xor[2] >> 6;
			std::size_t XorSize = 0;
			std::int32_t Displacement = 0;
			if (Mode == 1)
			{
				Displacement = static_cast<std::int8_t>(Xor[3]);
				XorSize = 4;
			}
			else if (Mode == 2)
			{
				std::memcpy(&Displacement, Xor + 3, sizeof(Displacement));
				XorSize = 7;
			}
			else
			{
				continue;
			}

			const std::uint8_t* ByteSwap = nullptr;
			for (const std::uint8_t* Candidate = Xor + XorSize; Candidate + 3 <= End && Candidate < Xor + XorSize + 8; ++Candidate)
			{
				if (Candidate[0] == 0x48 && Candidate[1] == 0x0F && Candidate[2] == 0xC8 + Register)
				{
					ByteSwap = Candidate;
					break;
				}
			}
			if (!ByteSwap || Displacement < 0 || Displacement > 0x400)
				continue;

			Offset = static_cast<std::uint32_t>(Displacement);
			Key = Immediate;
			return true;
		}

		return false;
	}

	bool SameGlobalDecoder(const DiscoveryGlobalDecoder& Left, const DiscoveryGlobalDecoder& Right)
	{
		return Left.ProtectedGlobal == Right.ProtectedGlobal && Left.Mask == Right.Mask && Left.Shuffle == Right.Shuffle && Left.Rotate == Right.Rotate && Left.CountOffset == Right.CountOffset && Left.CountXor == Right.CountXor && Left.ChunksOffset == Right.ChunksOffset && Left.ChunksXor == Right.ChunksXor;
	}

	std::uint8_t* FindDiscoveryGlobal(const char* const ModuleName, std::uint8_t* ExpectedFirstChunk, std::int32_t& Num)
	{
		const std::uintptr_t ModuleBase = Platform::GetModuleBase(ModuleName);
		const auto* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(ModuleBase);
		if (!ModuleBase || Platform::IsBadReadPtr(DosHeader) || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		const auto* NtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(ModuleBase + DosHeader->e_lfanew);
		if (Platform::IsBadReadPtr(NtHeaders) || NtHeaders->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		const std::uintptr_t ModuleEnd = ModuleBase + NtHeaders->OptionalHeader.SizeOfImage;
		std::vector<DiscoveryGlobalDecoder> Decoders;
		const auto* Section = IMAGE_FIRST_SECTION(NtHeaders);
		for (std::uint16_t SectionIndex = 0; SectionIndex < NtHeaders->FileHeader.NumberOfSections; ++SectionIndex)
		{
			if ((Section[SectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
				continue;

			const auto* SectionBegin = reinterpret_cast<const std::uint8_t*>(ModuleBase + Section[SectionIndex].VirtualAddress);
			const auto* SectionEnd = SectionBegin + std::min<std::size_t>(Section[SectionIndex].Misc.VirtualSize, ModuleEnd - reinterpret_cast<std::uintptr_t>(SectionBegin));
			if (SectionEnd <= SectionBegin)
				continue;

			for (const std::uint8_t* RegionCursor = SectionBegin; RegionCursor < SectionEnd;)
			{
				MEMORY_BASIC_INFORMATION MemoryInfo{};
				if (!VirtualQuery(RegionCursor, &MemoryInfo, sizeof(MemoryInfo)))
					break;
				const auto* RegionEnd = std::min(SectionEnd, reinterpret_cast<const std::uint8_t*>(MemoryInfo.BaseAddress) + MemoryInfo.RegionSize);
				if (RegionEnd <= RegionCursor)
					break;
				if (!IsReadableMemoryRegion(MemoryInfo))
				{
					RegionCursor = RegionEnd;
					continue;
				}

				for (const std::uint8_t* Cursor = RegionCursor; Cursor + 0x80 <= RegionEnd; ++Cursor)
				{
				if (Cursor[0] != 0x66 || Cursor[1] != 0x0F || Cursor[2] != 0x6F || Cursor[3] != 0x05 || Cursor[8] != 0x66 || Cursor[9] != 0x0F || Cursor[10] != 0xEF || Cursor[11] != 0x05)
					continue;
				if (std::memcmp(Cursor + 16, "\x66\x0F\x6F\xC8\x66\x0F\x73\xD1", 8) != 0 || std::memcmp(Cursor + 25, "\x66\x0F\x73\xF0", 4) != 0 || std::memcmp(Cursor + 30, "\x66\x0F\xEB\xC1\x66\x0F\x38\x00\x05", 9) != 0 || std::memcmp(Cursor + 43, "\x66\x48\x0F\x7E\xC1", 5) != 0)
					continue;

				const std::uint32_t RightRotate = Cursor[24];
				const std::uint32_t LeftRotate = Cursor[29];
				if (RightRotate + LeftRotate != 64 || LeftRotate == 0 || LeftRotate >= 64)
					continue;

				std::int32_t GlobalDisplacement;
				std::int32_t MaskDisplacement;
				std::int32_t ShuffleDisplacement;
				std::memcpy(&GlobalDisplacement, Cursor + 4, sizeof(GlobalDisplacement));
				std::memcpy(&MaskDisplacement, Cursor + 12, sizeof(MaskDisplacement));
				std::memcpy(&ShuffleDisplacement, Cursor + 39, sizeof(ShuffleDisplacement));

				DiscoveryGlobalDecoder Candidate;
				Candidate.ProtectedGlobal = const_cast<std::uint8_t*>(Cursor + 8 + GlobalDisplacement);
				const auto* Mask = Cursor + 16 + MaskDisplacement;
				const auto* Shuffle = Cursor + 43 + ShuffleDisplacement;
				const auto IsModuleRange = [&](const std::uint8_t* Address, const std::size_t Length) { return reinterpret_cast<std::uintptr_t>(Address) >= ModuleBase && reinterpret_cast<std::uintptr_t>(Address + Length) <= ModuleEnd && !Platform::IsBadReadPtr(Address + Length - 1); };
				if (!IsModuleRange(Candidate.ProtectedGlobal, 16) || !IsModuleRange(Mask, 16) || !IsModuleRange(Shuffle, 16))
					continue;

				std::memcpy(Candidate.Mask.data(), Mask, Candidate.Mask.size());
				std::memcpy(Candidate.Shuffle.data(), Shuffle, Candidate.Shuffle.size());
				Candidate.Rotate = LeftRotate;
				if (!ParseOwnerMemberXor32(Cursor + 48, Cursor + 0x80, Candidate.CountOffset, Candidate.CountXor) || !ParseOwnerMemberXor64(Cursor + 48, Cursor + 0x80, Candidate.ChunksOffset, Candidate.ChunksXor))
					continue;

				if (std::find_if(Decoders.begin(), Decoders.end(), [&](const DiscoveryGlobalDecoder& Existing) { return SameGlobalDecoder(Existing, Candidate); }) == Decoders.end())
					Decoders.push_back(Candidate);
				}

				RegionCursor = RegionEnd;
			}
		}

		std::vector<DiscoveryGlobalDecoder> Validated;
		for (const DiscoveryGlobalDecoder& Decoder : Decoders)
		{
			std::int32_t CandidateNum = 0;
			if (ValidateDiscoveryGlobal(Decoder, ExpectedFirstChunk, CandidateNum))
			{
				Validated.push_back(Decoder);
				Num = CandidateNum;
			}
		}

		if (Validated.size() != 1)
			throw std::runtime_error(std::format("Discovery protected GObjects accessor produced {} validated decoder candidates from {} unique instruction-derived candidates", Validated.size(), Decoders.size()));

		GlobalDecoder = Validated[0];
		Discovery::GlobalRva = reinterpret_cast<std::uintptr_t>(GlobalDecoder.ProtectedGlobal) - ModuleBase;
		Discovery::GlobalRotate = GlobalDecoder.Rotate;
		Discovery::GlobalCountOffset = GlobalDecoder.CountOffset;
		Discovery::GlobalCountXor = GlobalDecoder.CountXor;
		Discovery::GlobalChunksOffset = GlobalDecoder.ChunksOffset;
		Discovery::GlobalChunksXor = GlobalDecoder.ChunksXor;
		Discovery::GlobalMask = GlobalDecoder.Mask;
		Discovery::GlobalShuffle = GlobalDecoder.Shuffle;
		return GlobalDecoder.ProtectedGlobal;
	}

	std::uint32_t DiscoverElementsPerChunk(std::uint8_t** Chunks, const std::int32_t Num, const std::uint32_t ItemSize, const std::uint32_t InternalIndexOffset, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd)
	{
		constexpr std::array<std::uint32_t, 5> Candidates = { 0x8000, 0x10000, 0x20000, 0x40000, 0x80000 };
		std::vector<std::uint32_t> Validated;
		for (const std::uint32_t Candidate : Candidates)
		{
			const std::uint32_t NumChunks = (static_cast<std::uint32_t>(Num) + Candidate - 1) / Candidate;
			if (NumChunks < 2 || NumChunks > 0x80 || Platform::IsBadReadPtr(Chunks + NumChunks - 1))
				continue;

			bool bValid = true;
			for (std::uint32_t ChunkIndex = 0; ChunkIndex < NumChunks; ++ChunkIndex)
			{
				if (ScoreObjectChunk(Chunks[ChunkIndex], ChunkIndex, ItemSize, InternalIndexOffset, Candidate, ModuleBase, ModuleEnd) < 0)
				{
					bValid = false;
					break;
				}
			}

			if (bValid)
				Validated.push_back(Candidate);
		}

		if (Validated.size() != 1)
			throw std::runtime_error(std::format("Discovery object chunk geometry matched {} candidate element counts", Validated.size()));

		return Validated[0];
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
	DiscoveredChunkTable = nullptr;
	Discovery::GlobalModel = "unresolved";

	DiscoveredObjectArray DiscoveredArray;
	if (DiscoverObjectChunks(ModuleName, DiscoveredArray))
	{
		std::cerr << std::format("Discovery bootstrap: first chunk found; item size 0x{:X}, index +0x{:X}\n", DiscoveredArray.ItemSize, DiscoveredArray.InternalIndexOffset);
		bUseDiscoveredChunks = true;
		DiscoveredChunks = std::move(DiscoveredArray.Chunks);
		DiscoveredInternalIndexOffset = DiscoveredArray.InternalIndexOffset;
		SizeOfFUObjectItem = DiscoveredArray.ItemSize;
		const std::uintptr_t ModuleBase = Platform::GetModuleBase(ModuleName);
		const std::uintptr_t ModuleEnd = ModuleBase + GetModuleSize(ModuleBase);
		std::cerr << "Discovery bootstrap: evaluating protected GObjects accessors by instruction semantics\n";

		struct ValidatedSemanticCandidate
		{
			SemanticGlobalCandidate Candidate;
			std::uint32_t ElementsPerChunk = 0;
		};

		std::vector<ValidatedSemanticCandidate> ValidatedSemanticCandidates;
		for (const SemanticGlobalCandidate& Candidate : FindSemanticDiscoveryGlobals(ModuleName, DiscoveredChunks[0]))
		{
			try
			{
				const std::uint32_t ElementsPerChunk = DiscoverElementsPerChunk(Candidate.Chunks, Candidate.Num, SizeOfFUObjectItem, DiscoveredInternalIndexOffset, ModuleBase, ModuleEnd);
				ValidatedSemanticCandidates.push_back({ Candidate, ElementsPerChunk });
			}
			catch (const std::exception&)
			{
			}
		}

		if (ValidatedSemanticCandidates.size() == 1)
		{
			const ValidatedSemanticCandidate& Validated = ValidatedSemanticCandidates[0];
			GObjects = Validated.Candidate.Global;
			DiscoveredChunkTable = Validated.Candidate.Chunks;
			DiscoveredNum = Validated.Candidate.Num;
			Discovery::ElementsPerChunk = Validated.ElementsPerChunk;
			Discovery::GlobalRva = reinterpret_cast<std::uintptr_t>(GObjects) - ModuleBase;
			Discovery::GlobalModel = "semantic-x86-concrete-dataflow";
			std::cerr << "Discovery bootstrap: semantic GObjects decoder validated\n";
		}
		else
		{
			std::cerr << std::format("Discovery bootstrap: semantic evaluation produced {} structurally valid candidates; trying the compatibility template\n", ValidatedSemanticCandidates.size());
			GObjects = FindDiscoveryGlobal(ModuleName, DiscoveredChunks[0], DiscoveredNum);
			if (!GObjects)
				throw std::runtime_error("Object chunks were discovered, but the protected object-count owner could not be validated");
			DiscoveredChunkTable = GetDiscoveryChunks(GObjects);
			Discovery::ElementsPerChunk = DiscoverElementsPerChunk(DiscoveredChunkTable, DiscoveredNum, SizeOfFUObjectItem, DiscoveredInternalIndexOffset, ModuleBase, ModuleEnd);
			Discovery::GlobalModel = "current-template-fallback";
		}

		std::uint8_t** ChunkTable = DiscoveredChunkTable;
		std::cerr << "Discovery bootstrap: deriving object chunk geometry\n";
		const std::uint32_t NumChunks = (static_cast<std::uint32_t>(DiscoveredNum) + Discovery::ElementsPerChunk - 1) / Discovery::ElementsPerChunk;
		DiscoveredChunks.clear();
		DiscoveredChunks.reserve(NumChunks);

		for (std::uint32_t ChunkIndex = 0; ChunkIndex < NumChunks; ++ChunkIndex)
		{
			std::uint8_t* Chunk = ChunkTable[ChunkIndex];
			if (ScoreObjectChunk(Chunk, ChunkIndex, SizeOfFUObjectItem, DiscoveredInternalIndexOffset, Discovery::ElementsPerChunk, ModuleBase, ModuleEnd) < 0)
				throw std::runtime_error(std::format("Protected object metadata referenced an invalid chunk at index {}", ChunkIndex));

			DiscoveredChunks.push_back(Chunk);
		}
	}
	else
	{
		throw std::runtime_error("Structural object-array discovery failed; refusing to trust a build-specific GObjects RVA");
	}

	NumElementsPerChunk = Discovery::ElementsPerChunk;
	Discovery::ObjectCount = static_cast<std::uint32_t>(DiscoveredNum);
	FUObjectItemInitialOffset = 0x0;

	Off::FUObjectArray::bIsChunked = true;
	Off::FUObjectArray::ChunkedFixedLayout = FChunkedFixedUObjectArrayLayouts[0];
	Off::InSDK::ObjArray::GObjects = static_cast<int32>(Platform::GetOffset(GObjects, ModuleName));
	Off::InSDK::ObjArray::ChunkSize = Discovery::ElementsPerChunk;
	Off::InSDK::ObjArray::FUObjectItemSize = SizeOfFUObjectItem;
	Off::InSDK::ObjArray::FUObjectItemInitialOffset = 0x0;

	if (bUseDiscoveredChunks)
	{
		std::cerr << "Discovery object chunks located structurally; no fixed GObjects RVA was used\n";
		std::cerr << std::format("Discovery chunks: {}, FUObjectItem size: 0x{:X}, UObject index offset: 0x{:X}\n", DiscoveredChunks.size(), SizeOfFUObjectItem, DiscoveredInternalIndexOffset);
		std::cerr << std::format("Protected count metadata located and validated at RVA 0x{:X}\n", Off::InSDK::ObjArray::GObjects);
		std::cerr << std::format("Protected global decoder model: {}\n", Discovery::GlobalModel);
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
	{
		if (bUseDiscoveredChunks)
			return DiscoveredNum;

		return GetDiscoveryNum(GObjects);
	}

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
	{
		if (bUseDiscoveredChunks)
			return static_cast<int32>(DiscoveredChunks.size());

		return (Num() + Discovery::ElementsPerChunk - 1) / Discovery::ElementsPerChunk;
	}

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
		std::uint8_t** Chunks = bUseDiscoveredChunks ? DiscoveredChunks.data() : GetDiscoveryChunks(GObjects);
		std::uint8_t* Item = Chunks[ChunkIndex] + (InChunkIndex * SizeOfFUObjectItem);
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
