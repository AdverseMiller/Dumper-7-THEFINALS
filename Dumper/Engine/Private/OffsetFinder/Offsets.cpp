#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <stdexcept>
#include <unordered_set>
#include <vector>

#include "Utils.h"

#include "OffsetFinder/Offsets.h"
#include "OffsetFinder/OffsetFinder.h"

#include "Unreal/ObjectArray.h"
#include "Unreal/NameArray.h"
#include "Unreal/Discovery.h"

#include "Platform.h"
#include "Architecture.h"

namespace
{
	std::size_t GetReadableSpan(const std::uint8_t* Address, const std::size_t MaximumSize)
	{
		MEMORY_BASIC_INFORMATION MemoryInfo;
		if (!VirtualQuery(Address, &MemoryInfo, sizeof(MemoryInfo)))
			return 0;

		constexpr DWORD ReadableMask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
		constexpr DWORD InaccessibleMask = PAGE_GUARD | PAGE_NOACCESS;
		if (MemoryInfo.State != MEM_COMMIT || !(MemoryInfo.Protect & ReadableMask) || (MemoryInfo.Protect & InaccessibleMask))
			return 0;

		const std::uintptr_t RegionEnd = reinterpret_cast<std::uintptr_t>(MemoryInfo.BaseAddress) + MemoryInfo.RegionSize;
		const std::uintptr_t Current = reinterpret_cast<std::uintptr_t>(Address);
		if (Current >= RegionEnd)
			return 0;

		return std::min(MaximumSize, static_cast<std::size_t>(RegionEnd - Current));
	}

	const std::uint8_t* ResolveDirectJump(const std::uint8_t* Address, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd)
	{
		for (int Depth = 0; Depth < 4; ++Depth)
		{
			if (GetReadableSpan(Address, 5) < 5 || Address[0] != 0xE9)
				break;

			std::int32_t Relative = 0;
			std::memcpy(&Relative, Address + 1, sizeof(Relative));
			const auto* Target = Address + 5 + Relative;
			const std::uintptr_t TargetAddress = reinterpret_cast<std::uintptr_t>(Target);
			if (TargetAddress < ModuleBase || TargetAddress >= ModuleEnd)
				return nullptr;

			Address = Target;
		}

		return Address;
	}

	std::uint8_t FindDiscoveryProtectedObjectBaseRegister(const std::uint8_t* Address, const std::size_t Span)
	{
		std::vector<std::uint8_t> Registers;
		for (std::size_t Offset = 0; Offset + 14 <= Span; ++Offset)
		{
			const std::uint8_t* Code = Address + Offset;
			if (Code[0] != 0x48 || Code[1] != 0x8D || (Code[2] >> 6) != 1 || std::memcmp(Code + 4, "\x49\x89\xC8\x49\xC1\xE8", 6) != 0 || std::memcmp(Code + 11, "\xC1\xC1", 2) != 0)
				continue;

			const std::uint8_t BaseRegister = Code[2] & 0x7;
			if (std::find(Registers.begin(), Registers.end(), BaseRegister) == Registers.end())
				Registers.push_back(BaseRegister);
		}

		return Registers.size() == 1 ? Registers[0] : 0xFF;
	}

	bool IsDiscoveryProcessEventDispatcher(const std::uint8_t* Address, int32& FunctionFlagsOffset)
	{
		const std::size_t Span = GetReadableSpan(Address, 0x800);
		if (Span < 0x100)
			return false;
		const std::uint8_t ProtectedObjectBaseRegister = FindDiscoveryProtectedObjectBaseRegister(Address, Span);
		if (ProtectedObjectBaseRegister == 0xFF)
			return false;

		struct FlagRead
		{
			std::uint8_t BaseRegister;
			std::uint8_t DestinationRegister;
			int32 Displacement;
			int Count;
		};

		std::vector<FlagRead> FlagReads;
		std::array<bool, 16> NativeFlagTests{};

		for (std::size_t Offset = 0; Offset + 8 < Span; ++Offset)
		{
			std::size_t OpcodeOffset = Offset;
			std::uint8_t Rex = 0;
			if ((Address[OpcodeOffset] & 0xF0) == 0x40)
			{
				Rex = Address[OpcodeOffset];
				++OpcodeOffset;
			}

			if (OpcodeOffset + 7 >= Span || Address[OpcodeOffset] != 0x8B)
				continue;

			const std::uint8_t ModRm = Address[OpcodeOffset + 1];
			if ((ModRm >> 6) != 0x2)
				continue;

			std::size_t DisplacementOffset = OpcodeOffset + 2;
			std::uint8_t BaseRegister = ModRm & 0x7;
			if (BaseRegister == 0x4)
			{
				const std::uint8_t Sib = Address[DisplacementOffset++];
				BaseRegister = Sib & 0x7;
			}

			BaseRegister |= (Rex & 0x1) ? 0x8 : 0x0;
			const std::uint8_t DestinationRegister = ((ModRm >> 3) & 0x7) | ((Rex & 0x4) ? 0x8 : 0x0);
			std::int32_t Displacement = 0;
			std::memcpy(&Displacement, Address + DisplacementOffset, sizeof(Displacement));
			if (BaseRegister == 4 || Displacement < 0x40 || Displacement > 0x300 || (Displacement & 0x3))
				continue;

			auto Existing = std::find_if(FlagReads.begin(), FlagReads.end(), [&](const FlagRead& Read)
			{
				return Read.BaseRegister == BaseRegister && Read.DestinationRegister == DestinationRegister && Read.Displacement == Displacement;
			});
			if (Existing == FlagReads.end())
				FlagReads.push_back({ BaseRegister, DestinationRegister, Displacement, 1 });
			else
				++Existing->Count;
		}

		for (std::size_t Offset = 0; Offset + 3 <= Span; ++Offset)
		{
			std::size_t OpcodeOffset = Offset;
			std::uint8_t Rex = 0;
			if ((Address[OpcodeOffset] & 0xF0) == 0x40)
				Rex = Address[OpcodeOffset++];

			if (OpcodeOffset + 3 > Span || Address[OpcodeOffset] != 0xF6)
				continue;

			const std::uint8_t ModRm = Address[OpcodeOffset + 1];
			if ((ModRm & 0xF8) != 0xC0 || Address[OpcodeOffset + 2] != 0x10)
				continue;

			NativeFlagTests[(ModRm & 0x7) | ((Rex & 0x1) ? 0x8 : 0x0)] = true;
		}

		std::vector<int32> Candidates;
		for (const FlagRead& Read : FlagReads)
		{
			if (Read.BaseRegister == ProtectedObjectBaseRegister && Read.Count >= 3 && NativeFlagTests[Read.DestinationRegister])
				Candidates.push_back(Read.Displacement);
		}

		std::sort(Candidates.begin(), Candidates.end());
		Candidates.erase(std::unique(Candidates.begin(), Candidates.end()), Candidates.end());
		if (Candidates.size() != 1)
			return false;

		FunctionFlagsOffset = Candidates[0];
		return true;
	}

	const std::uint8_t* FindDiscoveryProcessEventDispatcher(const std::uint8_t* Wrapper, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd, int32& FunctionFlagsOffset)
	{
		const std::size_t Span = GetReadableSpan(Wrapper, 0x400);
		for (std::size_t Offset = 0; Offset + 5 <= Span; ++Offset)
		{
			if (Wrapper[Offset] != 0xE8)
				continue;

			std::int32_t Relative = 0;
			std::memcpy(&Relative, Wrapper + Offset + 1, sizeof(Relative));
			const std::uint8_t* Target = ResolveDirectJump(Wrapper + Offset + 5 + Relative, ModuleBase, ModuleEnd);
			const std::uintptr_t TargetAddress = reinterpret_cast<std::uintptr_t>(Target);
			if (!Target || TargetAddress < ModuleBase || TargetAddress >= ModuleEnd)
				continue;

			if (IsDiscoveryProcessEventDispatcher(Target, FunctionFlagsOffset))
				return Target;
		}

		return nullptr;
	}

	struct DiscoveryVectorProgram
	{
		std::uint32_t AddressOffset = 0;
		std::uint32_t DataOffset = 0;
		std::uint32_t Stride = 0;
		std::uint8_t InputRegister = 0;
		std::vector<Discovery::ProtectedScalarInstruction> HashInstructions;
		std::vector<Discovery::ProtectedVectorInstruction> Instructions;
	};

	bool ParseDiscoveryScalarHashProgram(const std::uint8_t* Dispatcher, const std::size_t StartOffset, const std::size_t EndOffset, const std::uint8_t ObjectRegister, std::uint32_t& AddressOffset, std::vector<Discovery::ProtectedScalarInstruction>& Instructions)
	{
		const std::uint8_t* Cursor = Dispatcher + StartOffset;
		const std::uint8_t* End = Dispatcher + EndOffset;
		int MultiplyCount = 0;
		while (Cursor < End && Instructions.size() < Discovery::ProtectedHashProgram.size())
		{
			std::uint8_t Rex = 0;
			if ((*Cursor & 0xF0) == 0x40)
				Rex = *Cursor++;
			if (Cursor >= End)
				return false;

			const bool Is64Bit = (Rex & 0x8) != 0;
			const std::uint8_t Opcode = *Cursor++;
			if (Cursor >= End)
				return false;
			const std::uint8_t ModRm = *Cursor++;
			const std::uint8_t Mode = ModRm >> 6;
			const std::uint8_t Register = ((ModRm >> 3) & 0x7) | ((Rex & 0x4) ? 0x8 : 0x0);
			const std::uint8_t Rm = (ModRm & 0x7) | ((Rex & 0x1) ? 0x8 : 0x0);

			Discovery::ProtectedScalarInstruction Instruction{};
			Instruction.Destination = Rm;
			Instruction.Source = Register;
			Instruction.Is64Bit = Is64Bit;

			if (Opcode == 0x8D && (Mode == 1 || Mode == 2) && (ModRm & 0x7) != 4)
			{
				std::int32_t Displacement = 0;
				if (Mode == 1)
					Displacement = static_cast<std::int8_t>(*Cursor++);
				else
				{
					if (End - Cursor < 4)
						return false;
					std::memcpy(&Displacement, Cursor, sizeof(Displacement));
					Cursor += 4;
				}
				Instruction.Destination = Register;
				Instruction.Source = Rm;
				Instruction.Immediate = static_cast<std::uint32_t>(Displacement);
				if (Instructions.empty())
				{
					if (Rm != ObjectRegister || Displacement <= 0 || Displacement > 0x100)
						return false;
					Instruction.Opcode = Discovery::ProtectedScalarOpcode::LoadAddress;
					AddressOffset = static_cast<std::uint32_t>(Displacement);
				}
				else
					Instruction.Opcode = Discovery::ProtectedScalarOpcode::LeaAddImmediate;
				Instructions.push_back(Instruction);
				continue;
			}

			if (Instructions.empty())
				return false;

			if (Opcode == 0x89 && Mode == 3)
			{
				Instruction.Opcode = Discovery::ProtectedScalarOpcode::Move;
				Instruction.Destination = Rm;
				Instruction.Source = Register;
			}
			else if (Opcode == 0xC1 && Mode == 3)
			{
				if (Cursor >= End)
					return false;
				Instruction.Destination = Rm;
				Instruction.Source = Rm;
				Instruction.Immediate = *Cursor++;
				const std::uint8_t Group = (ModRm >> 3) & 0x7;
				if (Group == 0)
					Instruction.Opcode = Discovery::ProtectedScalarOpcode::RotateLeft;
				else if (Group == 5)
					Instruction.Opcode = Discovery::ProtectedScalarOpcode::ShiftRight;
				else
					return false;
			}
			else if (Opcode == 0x69 && Mode == 3)
			{
				if (End - Cursor < 4)
					return false;
				Instruction.Opcode = Discovery::ProtectedScalarOpcode::Multiply;
				Instruction.Destination = Register;
				Instruction.Source = Rm;
				std::memcpy(&Instruction.Immediate, Cursor, sizeof(Instruction.Immediate));
				Cursor += 4;
				++MultiplyCount;
			}
			else if (Opcode == 0x01 && Mode == 3)
			{
				Instruction.Opcode = Discovery::ProtectedScalarOpcode::Add;
				Instruction.Destination = Rm;
				Instruction.Source = Register;
			}
			else if (Opcode == 0x31 && Mode == 3)
			{
				Instruction.Opcode = Discovery::ProtectedScalarOpcode::Xor;
				Instruction.Destination = Rm;
				Instruction.Source = Register;
			}
			else if ((Opcode == 0x81 || Opcode == 0x83) && Mode == 3)
			{
				const std::uint8_t Group = (ModRm >> 3) & 0x7;
				std::uint32_t Immediate = 0;
				if (Opcode == 0x81)
				{
					if (End - Cursor < 4)
						return false;
					std::memcpy(&Immediate, Cursor, sizeof(Immediate));
					Cursor += 4;
				}
				else
					Immediate = static_cast<std::uint32_t>(static_cast<std::int8_t>(*Cursor++));
				Instruction.Destination = Rm;
				Instruction.Source = Rm;
				Instruction.Immediate = Immediate;
				if (Group == 0)
					Instruction.Opcode = Discovery::ProtectedScalarOpcode::AddImmediate;
				else if (Group == 4)
				{
					Instruction.Opcode = Discovery::ProtectedScalarOpcode::AndImmediate;
					Instructions.push_back(Instruction);
					if (Immediate > 0xF || MultiplyCount < 3)
						return false;
					Instructions.push_back({
						.Opcode = Discovery::ProtectedScalarOpcode::Return,
						.Source = Rm,
					});
					return true;
				}
				else
					return false;
			}
			else if (Opcode == 0xFF && Mode == 3 && ((ModRm >> 3) & 0x7) == 0)
			{
				Instruction.Opcode = Discovery::ProtectedScalarOpcode::Increment;
				Instruction.Destination = Rm;
				Instruction.Source = Rm;
			}
			else
				return false;

			Instructions.push_back(Instruction);
		}

		return false;
	}

	bool SameDiscoveryVectorInstruction(const Discovery::ProtectedVectorInstruction& Left, const Discovery::ProtectedVectorInstruction& Right)
	{
		return Left.Opcode == Right.Opcode && Left.Destination == Right.Destination && Left.Source == Right.Source && Left.Immediate == Right.Immediate && Left.SourceIsConstant == Right.SourceIsConstant && Left.Constant == Right.Constant;
	}

	bool SameDiscoveryVectorProgram(const DiscoveryVectorProgram& Left, const DiscoveryVectorProgram& Right)
	{
		if (Left.AddressOffset != Right.AddressOffset || Left.DataOffset != Right.DataOffset || Left.Stride != Right.Stride || Left.InputRegister != Right.InputRegister || Left.Instructions.size() != Right.Instructions.size())
			return false;

		for (std::size_t Index = 0; Index < Left.Instructions.size(); ++Index)
		{
			if (!SameDiscoveryVectorInstruction(Left.Instructions[Index], Right.Instructions[Index]))
				return false;
		}

		return true;
	}

	bool ReadDiscoveryVectorConstant(const std::uint8_t* InstructionEnd, const std::int32_t Relative, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd, std::array<std::uint8_t, 16>& Constant)
	{
		const auto* Address = InstructionEnd + Relative;
		const std::uintptr_t Value = reinterpret_cast<std::uintptr_t>(Address);
		if (Value < ModuleBase || Value + Constant.size() > ModuleEnd || GetReadableSpan(Address, Constant.size()) < Constant.size())
			return false;

		std::memcpy(Constant.data(), Address, Constant.size());
		return true;
	}

	bool ParseDiscoveryVectorProgram(const std::uint8_t* Dispatcher, const std::size_t Span, const std::size_t LoadOffset, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd, DiscoveryVectorProgram& Result)
	{
		const std::uint8_t* End = Dispatcher + Span;
		const std::uint8_t* Cursor = Dispatcher + LoadOffset;
		if (Cursor >= End || (*Cursor != 0x66 && *Cursor != 0xF2))
			return false;

		const std::uint8_t LoadPrefix = *Cursor++;
		std::uint8_t LoadRex = 0;
		if (Cursor < End && (*Cursor & 0xF0) == 0x40)
			LoadRex = *Cursor++;
		if (End - Cursor < 5 || Cursor[0] != 0x0F || (Cursor[1] != 0x6F && Cursor[1] != 0x70))
			return false;
		const bool LoadAndShuffleLowWords = LoadPrefix == 0xF2 && Cursor[1] == 0x70;
		if (!LoadAndShuffleLowWords && !(LoadPrefix == 0x66 && Cursor[1] == 0x6F))
			return false;

		const std::uint8_t LoadModRm = Cursor[2];
		const std::uint8_t LoadMode = LoadModRm >> 6;
		if ((LoadMode != 1 && LoadMode != 2) || (LoadModRm & 0x7) != 4)
			return false;
		const std::uint8_t LoadSib = Cursor[3];
		const std::uint8_t IndexRegister = ((LoadSib >> 3) & 0x7) | ((LoadRex & 0x2) ? 0x8 : 0x0);
		const std::uint8_t BaseRegister = (LoadSib & 0x7) | ((LoadRex & 0x1) ? 0x8 : 0x0);
		const std::uint8_t InputRegister = ((LoadModRm >> 3) & 0x7) | ((LoadRex & 0x4) ? 0x8 : 0x0);
		std::int32_t DataOffset = 0;
		std::size_t LoadLength = static_cast<std::size_t>(Cursor - (Dispatcher + LoadOffset)) + 4;
		if (LoadMode == 1)
		{
			DataOffset = static_cast<std::int8_t>(Cursor[4]);
			++LoadLength;
		}
		else
		{
			if (End - Cursor < 8)
				return false;
			std::memcpy(&DataOffset, Cursor + 4, sizeof(DataOffset));
			LoadLength += 4;
		}
		if (DataOffset <= 0 || DataOffset > 0x400)
			return false;

		std::uint8_t ShuffleLowImmediate = 0;
		if (LoadAndShuffleLowWords)
		{
			if (Dispatcher + LoadOffset + LoadLength >= End)
				return false;
			ShuffleLowImmediate = Dispatcher[LoadOffset + LoadLength++];
		}

		std::uint32_t Stride = 1u << (LoadSib >> 6);
		const std::size_t SearchStart = LoadOffset > 64 ? LoadOffset - 64 : 0;
		bool FoundIndexShift = false;
		for (std::size_t ShiftOffset = SearchStart; ShiftOffset + 3 <= LoadOffset; ++ShiftOffset)
		{
			const std::uint8_t* Shift = Dispatcher + ShiftOffset;
			std::uint8_t Rex = 0;
			if ((*Shift & 0xF0) == 0x40)
				Rex = *Shift++;
			if (Shift + 3 > Dispatcher + LoadOffset || Shift[0] != 0xC1)
				continue;
			const std::uint8_t ModRm = Shift[1];
			const std::uint8_t Register = (ModRm & 0x7) | ((Rex & 0x1) ? 0x8 : 0x0);
			if ((ModRm & 0xF8) == 0xE0 && Register == IndexRegister && Shift[2] < 8)
			{
				Stride <<= Shift[2];
				FoundIndexShift = true;
			}
		}
		if (!FoundIndexShift || Stride < 16 || Stride > 0x100)
			return false;

		std::uint32_t AddressOffset = 0;
		const std::size_t HashStart = LoadOffset > 176 ? LoadOffset - 176 : 0;
		std::vector<Discovery::ProtectedScalarInstruction> HashInstructions;
		for (std::size_t CandidateOffset = HashStart; CandidateOffset + 4 <= LoadOffset; ++CandidateOffset)
		{
			std::uint32_t CandidateAddressOffset = 0;
			std::vector<Discovery::ProtectedScalarInstruction> CandidateInstructions;
			if (!ParseDiscoveryScalarHashProgram(Dispatcher, CandidateOffset, LoadOffset, BaseRegister, CandidateAddressOffset, CandidateInstructions))
				continue;
			AddressOffset = CandidateAddressOffset;
			HashInstructions = std::move(CandidateInstructions);
			break;
		}
		if (!AddressOffset || HashInstructions.empty())
			return false;

		Result = {};
		Result.AddressOffset = AddressOffset;
		Result.DataOffset = static_cast<std::uint32_t>(DataOffset);
		Result.Stride = Stride;
		Result.InputRegister = InputRegister;
		Result.HashInstructions = std::move(HashInstructions);
		if (LoadAndShuffleLowWords)
		{
			Result.Instructions.push_back({
				.Opcode = Discovery::ProtectedVectorOpcode::ShuffleLowWords,
				.Destination = InputRegister,
				.Source = InputRegister,
				.Immediate = ShuffleLowImmediate,
			});
		}

		Cursor = Dispatcher + LoadOffset + LoadLength;
		while (Cursor < End && Result.Instructions.size() < Discovery::ProtectedSlotProgram.size())
		{
			if (*Cursor != 0x66)
				return false;
			++Cursor;
			std::uint8_t Rex = 0;
			if (Cursor < End && (*Cursor & 0xF0) == 0x40)
				Rex = *Cursor++;
			if (Cursor >= End || *Cursor++ != 0x0F || Cursor >= End)
				return false;

			bool ThreeByteOpcode = false;
			std::uint8_t Opcode = *Cursor++;
			if (Opcode == 0x38)
			{
				if (Cursor >= End)
					return false;
				ThreeByteOpcode = true;
				Opcode = *Cursor++;
			}
			if (Cursor >= End)
				return false;

			const std::uint8_t ModRm = *Cursor++;
			const std::uint8_t Mode = ModRm >> 6;
			const std::uint8_t Register = ((ModRm >> 3) & 0x7) | ((Rex & 0x4) ? 0x8 : 0x0);
			const std::uint8_t Rm = (ModRm & 0x7) | ((Rex & 0x1) ? 0x8 : 0x0);

			Discovery::ProtectedVectorInstruction Decoded{};
			Decoded.Destination = Register;
			Decoded.Source = Rm;

			if (!ThreeByteOpcode && Opcode == 0x7E && (Rex & 0x8) && Mode == 3)
			{
				Decoded.Opcode = Discovery::ProtectedVectorOpcode::ReturnLowQword;
				Decoded.Source = Register;
				if (End - Cursor >= 4 && (Cursor[0] & 0xF8) == 0x48 && Cursor[1] == 0xC1 && (Cursor[2] >> 6) == 3 && ((Cursor[2] >> 3) & 0x7) == 0)
				{
					const std::uint8_t ScalarRegister = (Cursor[2] & 0x7) | ((Cursor[0] & 0x1) ? 0x8 : 0x0);
					if (ScalarRegister == Rm && Cursor[3] < 64)
						Decoded.Immediate = Cursor[3];
				}
				Result.Instructions.push_back(Decoded);
				return true;
			}

			if (!ThreeByteOpcode && (Opcode == 0x71 || Opcode == 0x72 || Opcode == 0x73) && Mode == 3)
			{
				if (Cursor >= End)
					return false;
				Decoded.Destination = Rm;
				Decoded.Source = Rm;
				Decoded.Immediate = *Cursor++;
				const std::uint8_t Group = (ModRm >> 3) & 0x7;
				if (Opcode == 0x71 && Group == 2)
					Decoded.Opcode = Discovery::ProtectedVectorOpcode::ShiftRightWords;
				else if (Opcode == 0x71 && Group == 6)
					Decoded.Opcode = Discovery::ProtectedVectorOpcode::ShiftLeftWords;
				else if (Opcode == 0x72 && Group == 2)
					Decoded.Opcode = Discovery::ProtectedVectorOpcode::ShiftRightDwords;
				else if (Opcode == 0x72 && Group == 6)
					Decoded.Opcode = Discovery::ProtectedVectorOpcode::ShiftLeftDwords;
				else if (Opcode == 0x73 && Group == 2)
					Decoded.Opcode = Discovery::ProtectedVectorOpcode::ShiftRightQwords;
				else if (Opcode == 0x73 && Group == 6)
					Decoded.Opcode = Discovery::ProtectedVectorOpcode::ShiftLeftQwords;
				else
					return false;
				Result.Instructions.push_back(Decoded);
				continue;
			}

			if (Mode == 3)
			{
				if (!ThreeByteOpcode && Opcode == 0x6F)
					Decoded.Opcode = Discovery::ProtectedVectorOpcode::Move;
				else if (!ThreeByteOpcode && Opcode == 0xEF)
					Decoded.Opcode = Discovery::ProtectedVectorOpcode::Xor;
				else if (!ThreeByteOpcode && Opcode == 0xFD)
					Decoded.Opcode = Discovery::ProtectedVectorOpcode::AddWords;
				else if (!ThreeByteOpcode && Opcode == 0xEB)
					Decoded.Opcode = Discovery::ProtectedVectorOpcode::Or;
				else if (ThreeByteOpcode && Opcode == 0x00)
					Decoded.Opcode = Discovery::ProtectedVectorOpcode::ShuffleBytes;
				else
					return false;
				Result.Instructions.push_back(Decoded);
				continue;
			}

			if (Mode != 0 || (ModRm & 0x7) != 5 || (Opcode != 0xEF && !(ThreeByteOpcode && Opcode == 0x00)) || End - Cursor < 4)
				return false;
			std::int32_t Relative = 0;
			std::memcpy(&Relative, Cursor, sizeof(Relative));
			Cursor += 4;
			Decoded.Opcode = Opcode == 0xEF ? Discovery::ProtectedVectorOpcode::Xor : Discovery::ProtectedVectorOpcode::ShuffleBytes;
			Decoded.SourceIsConstant = true;
			if (!ReadDiscoveryVectorConstant(Cursor, Relative, ModuleBase, ModuleEnd, Decoded.Constant))
				return false;
			Result.Instructions.push_back(Decoded);
		}

		return false;
	}

	bool FindDiscoveryVectorProgram(const std::uint8_t* Dispatcher, const std::size_t Span, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd, DiscoveryVectorProgram& Result)
	{
		std::vector<DiscoveryVectorProgram> Programs;
		for (std::size_t Offset = 0; Offset + 16 < Span; ++Offset)
		{
			DiscoveryVectorProgram Candidate;
			if (!ParseDiscoveryVectorProgram(Dispatcher, Span, Offset, ModuleBase, ModuleEnd, Candidate))
				continue;
			if (std::find_if(Programs.begin(), Programs.end(), [&](const DiscoveryVectorProgram& Existing) { return SameDiscoveryVectorProgram(Existing, Candidate); }) == Programs.end())
				Programs.push_back(std::move(Candidate));
		}

		if (Programs.size() != 1)
		{
			std::cerr << std::format("Discovery vector extractor found {} distinct candidate programs\n", Programs.size());
			for (const DiscoveryVectorProgram& Program : Programs)
				std::cerr << std::format("  candidate: address +0x{:X}, data +0x{:X}, stride 0x{:X}, input xmm{}, {} instructions\n", Program.AddressOffset, Program.DataOffset, Program.Stride, Program.InputRegister, Program.Instructions.size());
			return false;
		}

		Result = std::move(Programs[0]);
		return true;
	}

	bool InitializeDiscoveryUObjectDecoder(const std::uint8_t* Dispatcher, const std::uintptr_t ModuleBase, const std::uintptr_t ModuleEnd)
	{
		const std::size_t Span = GetReadableSpan(Dispatcher, 0x800);
		DiscoveryVectorProgram Program;
		if (!FindDiscoveryVectorProgram(Dispatcher, Span, ModuleBase, ModuleEnd, Program))
			return false;
		if (Program.HashInstructions.empty() || Program.HashInstructions.size() > Discovery::ProtectedHashProgram.size() || Program.Instructions.empty() || Program.Instructions.size() > Discovery::ProtectedSlotProgram.size())
		{
			std::cerr << std::format("Discovery instruction program failed structural validation: {} scalar and {} vector instructions\n", Program.HashInstructions.size(), Program.Instructions.size());
			return false;
		}
		std::cerr << std::format("Discovery instruction programs extracted: {} scalar instructions, input xmm{}, {} vector instructions\n", Program.HashInstructions.size(), Program.InputRegister, Program.Instructions.size());

		Discovery::ProtectedAddressOffset = Program.AddressOffset;
		Discovery::ProtectedHashProgramSize = static_cast<std::uint32_t>(Program.HashInstructions.size());
		std::copy(Program.HashInstructions.begin(), Program.HashInstructions.end(), Discovery::ProtectedHashProgram.begin());
		Discovery::ProtectedHashReady = true;
		Discovery::ProtectedSlotDataOffset = Program.DataOffset;
		Discovery::ProtectedSlotStride = Program.Stride;
		Discovery::ProtectedSlotInputRegister = Program.InputRegister;
		Discovery::ProtectedSlotProgramSize = static_cast<std::uint32_t>(Program.Instructions.size());
		std::copy(Program.Instructions.begin(), Program.Instructions.end(), Discovery::ProtectedSlotProgram.begin());

		struct SelectorScores
		{
			int Samples = 0;
			std::array<int, 4> PlausibleNames{};
			std::array<int, 4> KnownObjects{};
			std::array<int, 4> KnownObjectsOrNull{};
			std::array<int, 4> NullValues{};
			std::array<std::unordered_set<std::uintptr_t>, 4> UniqueObjects{};
		};

		auto IsKnownObject = [](const std::uint64_t Value)
		{
			const auto* Object = reinterpret_cast<const std::uint8_t*>(Value);
			if (!Object || (Value & 0x7) || Platform::IsBadReadPtr(Object + ObjectArray::GetInternalIndexOffset()))
				return false;

			const int32 Index = *reinterpret_cast<const int32*>(Object + ObjectArray::GetInternalIndexOffset());
			return Index >= 0 && Index < ObjectArray::Num() && ObjectArray::GetByIndex(Index).GetAddress() == Object;
		};

		std::array<SelectorScores, 4> Scores{};
		const int32 NumObjects = ObjectArray::Num();
		constexpr int32 DesiredSamples = 0x2000;
		for (int32 Sample = 0; Sample < DesiredSamples && Sample < NumObjects; ++Sample)
		{
			const int32 Index = static_cast<int32>((static_cast<std::int64_t>(Sample) * NumObjects) / std::min(DesiredSamples, NumObjects));
			const UEObject Object = ObjectArray::GetByIndex(Index);
			if (!Object)
				continue;

			const std::uint32_t BaseSlot = Discovery::GetProtectedSlot(Object.GetAddress()) & 0x3;
			SelectorScores& BaseScores = Scores[BaseSlot];
			++BaseScores.Samples;
			for (std::uint32_t Slot = 0; Slot < 4; ++Slot)
			{
				const std::uint64_t Decoded = Discovery::DecodeProtectedSlot(Object.GetAddress(), Slot);
				const std::uint64_t NameValue = std::rotl(Decoded, 32);
				const std::uint32_t ComparisonIndex = static_cast<std::uint32_t>(NameValue);
				const std::uint32_t Number = static_cast<std::uint32_t>(NameValue >> 32);
				if (ComparisonIndex > 0 && ComparisonIndex < 0x04000000 && Number < 0x00100000)
					++BaseScores.PlausibleNames[Slot];

				if (!Decoded)
				{
					++BaseScores.KnownObjectsOrNull[Slot];
					++BaseScores.NullValues[Slot];
				}
				else if (IsKnownObject(Decoded))
				{
					++BaseScores.KnownObjects[Slot];
					++BaseScores.KnownObjectsOrNull[Slot];
					BaseScores.UniqueObjects[Slot].insert(static_cast<std::uintptr_t>(Decoded));
				}
			}
		}

		for (std::uint32_t BaseSlot = 0; BaseSlot < 4; ++BaseSlot)
		{
			const SelectorScores& BaseScores = Scores[BaseSlot];
			if (BaseScores.Samples < 0x100)
			{
				std::cerr << std::format("Discovery selector validation had only {} samples for hash bucket {}\n", BaseScores.Samples, BaseSlot);
				return false;
			}

			std::vector<std::uint8_t> ClassCandidates;
			for (std::uint8_t Slot = 0; Slot < 4; ++Slot)
			{
				if (BaseScores.KnownObjects[Slot] * 10 >= BaseScores.Samples * 9 && BaseScores.NullValues[Slot] == 0)
					ClassCandidates.push_back(Slot);
			}

			if (ClassCandidates.empty())
			{
				std::cerr << std::format("Discovery selector validation found no class candidate in hash bucket {}\n", BaseSlot);
				return false;
			}

			std::sort(ClassCandidates.begin(), ClassCandidates.end(), [&](const std::uint8_t Left, const std::uint8_t Right)
			{
				return BaseScores.UniqueObjects[Left].size() < BaseScores.UniqueObjects[Right].size();
			});
			if (ClassCandidates.size() > 1 && BaseScores.UniqueObjects[ClassCandidates[0]].size() == BaseScores.UniqueObjects[ClassCandidates[1]].size())
			{
				std::cerr << std::format("Discovery selector validation found ambiguous class slots in hash bucket {}\n", BaseSlot);
				return false;
			}
			const std::uint8_t ClassSlot = ClassCandidates[0];

			std::vector<std::uint8_t> OuterCandidates;
			for (std::uint8_t Slot = 0; Slot < 4; ++Slot)
			{
				if (Slot != ClassSlot && BaseScores.KnownObjectsOrNull[Slot] * 10 >= BaseScores.Samples * 9 && BaseScores.KnownObjects[Slot] * 10 >= BaseScores.Samples)
					OuterCandidates.push_back(Slot);
			}
			if (OuterCandidates.size() != 1)
			{
				std::cerr << std::format("Discovery selector validation failed in hash bucket {}: {} outer candidates\n", BaseSlot, OuterCandidates.size());
				return false;
			}
			const std::uint8_t OuterSlot = OuterCandidates[0];

			std::vector<std::uint8_t> NameCandidates;
			for (std::uint8_t Slot = 0; Slot < 4; ++Slot)
			{
				if (Slot != ClassSlot && Slot != OuterSlot)
					NameCandidates.push_back(Slot);
			}
			std::sort(NameCandidates.begin(), NameCandidates.end(), [&](const std::uint8_t Left, const std::uint8_t Right)
			{
				return BaseScores.PlausibleNames[Left] > BaseScores.PlausibleNames[Right];
			});
			if (NameCandidates.size() != 2 || BaseScores.PlausibleNames[NameCandidates[0]] <= BaseScores.PlausibleNames[NameCandidates[1]] || BaseScores.PlausibleNames[NameCandidates[0]] * 4 < BaseScores.Samples)
			{
				std::cerr << std::format("Discovery selector validation could not separate the remaining name slot in hash bucket {}: scores [{},{},{},{}] across {} samples\n", BaseSlot, BaseScores.PlausibleNames[0], BaseScores.PlausibleNames[1], BaseScores.PlausibleNames[2], BaseScores.PlausibleNames[3], BaseScores.Samples);
				return false;
			}
			const std::uint8_t NameSlot = NameCandidates[0];

			Discovery::ProtectedNameSlots[BaseSlot] = NameSlot;
			Discovery::ProtectedClassSlots[BaseSlot] = ClassSlot;
			Discovery::ProtectedOuterSlots[BaseSlot] = OuterSlot;
		}

		Discovery::UObjectDecoderReady = true;
		std::cerr << std::format("Discovery UObject selectors recovered: class [{},{},{},{}], outer [{},{},{},{}], name [{},{},{},{}]\n", Discovery::ProtectedClassSlots[0], Discovery::ProtectedClassSlots[1], Discovery::ProtectedClassSlots[2], Discovery::ProtectedClassSlots[3], Discovery::ProtectedOuterSlots[0], Discovery::ProtectedOuterSlots[1], Discovery::ProtectedOuterSlots[2], Discovery::ProtectedOuterSlots[3], Discovery::ProtectedNameSlots[0], Discovery::ProtectedNameSlots[1], Discovery::ProtectedNameSlots[2], Discovery::ProtectedNameSlots[3]);
		return true;
	}
}


void Off::InSDK::ProcessEvent::InitPE_Windows()
{
#ifdef PLATFORM_WINDOWS

	void** Vft = *(void***)ObjectArray::GetByIndex(0).GetAddress();

#if defined(_WIN64)
	/* Primary, and more reliable, check for ProcessEvent */
	auto IsProcessEvent = [](const uint8_t* FuncAddress, [[maybe_unused]] int32_t Index) -> bool
	{
		return Platform::FindPatternInRange({ 0xF7, -0x1, Off::UFunction::FunctionFlags, 0x0, 0x0, 0x0, 0x0, 0x04, 0x0, 0x0 }, FuncAddress, 0x400)
			&& Platform::FindPatternInRange({ 0xF7, -0x1, Off::UFunction::FunctionFlags, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x0 }, FuncAddress, 0xF00);
	};
#elif defined(_WIN32)
	/* Primary, and more reliable, check for ProcessEvent */
	auto IsProcessEvent = [](const uint8_t* FuncAddress, [[maybe_unused]] int32_t Index) -> bool
	{
		return Platform::FindPatternInRange({ 0xF7, -0x1, Off::UFunction::FunctionFlags, 0x0, 0x4, 0x0, 0x0 }, FuncAddress, 0x400)
			&& Platform::FindPatternInRange({ 0xF7, -0x1, Off::UFunction::FunctionFlags, 0x0, 0x0, 0x40, 0x0 }, FuncAddress, 0xF00);
	};
#endif

	const void* ProcessEventAddr = nullptr;
	int32_t ProcessEventIdx = 0;

	const auto [FuncPtr, FuncIdx] = Platform::IterateVTableFunctions(Vft, IsProcessEvent);

	ProcessEventAddr = FuncPtr;
	ProcessEventIdx = FuncIdx;

	if (!FuncPtr)
	{
		const void* StringRefAddr = Platform::FindByStringInAllSections(L"Accessed None", 0x0, 0x0, Settings::General::bSearchOnlyExecutableSectionsForStrings);
		/* ProcessEvent is sometimes located right after a func with the string L"Accessed None. Might as well check for it, because else we're going to crash anyways. */
		const void* PossiblePEAddr = reinterpret_cast<void*>(Architecture_x86_64::FindNextFunctionStart(StringRefAddr));

		auto IsSameAddr = [PossiblePEAddr](const uint8_t* FuncAddress, [[maybe_unused]] int32_t Index) -> bool
		{
			return FuncAddress == PossiblePEAddr;
		};

		const auto [FuncPtr2, FuncIdx2] = Platform::IterateVTableFunctions(Vft, IsSameAddr);
		ProcessEventAddr = FuncPtr2;
		ProcessEventIdx = FuncIdx2;
	}

	if (ProcessEventAddr)
	{
		Off::InSDK::ProcessEvent::PEIndex = ProcessEventIdx;
		Off::InSDK::ProcessEvent::PEOffset = Platform::GetOffset(ProcessEventAddr);

		std::cerr << std::format("PE-Offset: 0x{:X}\n", Off::InSDK::ProcessEvent::PEOffset);
		std::cerr << std::format("PE-Index: 0x{:X}\n\n", ProcessEventIdx);
		return;
	}

	std::cerr << "\nCouldn't find ProcessEvent!\n\n" << std::endl;

#endif // PLATFORM_WINDOWS
}

void Off::InSDK::ProcessEvent::InitDiscoveryPE_Windows()
{
#ifdef PLATFORM_WINDOWS
	const std::uintptr_t ModuleBase = Platform::GetModuleBase(Settings::General::DefaultModuleName);
	if (!ModuleBase)
		throw std::runtime_error("Discovery ProcessEvent scan could not locate the main module");

	const auto* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(ModuleBase);
	if (Platform::IsBadReadPtr(DosHeader) || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		throw std::runtime_error("Discovery ProcessEvent scan found an invalid DOS header");

	const auto* NtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(ModuleBase + DosHeader->e_lfanew);
	if (Platform::IsBadReadPtr(NtHeaders) || NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("Discovery ProcessEvent scan found an invalid NT header");

	const std::uintptr_t ModuleEnd = ModuleBase + NtHeaders->OptionalHeader.SizeOfImage;
	UEObject FirstObject = ObjectArray::GetByIndex(0);
	if (!FirstObject || Platform::IsBadReadPtr(FirstObject.GetAddress()))
		throw std::runtime_error("Discovery ProcessEvent scan could not read object zero");

	void** Vft = *reinterpret_cast<void***>(FirstObject.GetAddress());
	if (Platform::IsBadReadPtr(Vft))
		throw std::runtime_error("Discovery ProcessEvent scan could not read the UObject vtable");

	struct Match
	{
		const std::uint8_t* Wrapper;
		const std::uint8_t* Dispatcher;
		int32 Index;
		int32 FunctionFlagsOffset;
	};
	std::vector<Match> Matches;

	Platform::IterateVTableFunctions<false>(Vft, [&](const std::uint8_t* Wrapper, const int32 Index) -> bool
	{
		int32 FunctionFlagsOffset = 0;
		if (const std::uint8_t* Dispatcher = FindDiscoveryProcessEventDispatcher(Wrapper, ModuleBase, ModuleEnd, FunctionFlagsOffset))
			Matches.push_back({ Wrapper, Dispatcher, Index, FunctionFlagsOffset });
		return false;
	});

	if (Matches.empty())
		throw std::runtime_error("Discovery ProcessEvent semantic dispatcher was not found in the UObject vtable");
	if (Matches.size() != 1)
		throw std::runtime_error(std::format("Discovery ProcessEvent semantic dispatcher matched {} UObject vtable entries", Matches.size()));
	std::cerr << std::format("Discovery ProcessEvent candidate: wrapper RVA 0x{:X}, vtable index 0x{:X}, dispatcher RVA 0x{:X}, FunctionFlags +0x{:X}\n", Platform::GetOffset(Matches[0].Wrapper), Matches[0].Index, Platform::GetOffset(Matches[0].Dispatcher), Matches[0].FunctionFlagsOffset);
	bool DecoderReady = false;
	constexpr int32 DecoderAttempts = 20;
	for (int32 Attempt = 0; Attempt < DecoderAttempts && !DecoderReady; ++Attempt)
	{
		DecoderReady = InitializeDiscoveryUObjectDecoder(Matches[0].Dispatcher, ModuleBase, ModuleEnd);
		if (!DecoderReady && Attempt + 1 < DecoderAttempts)
		{
			std::cerr << std::format("Discovery UObject selector validation retry {}/{}\n", Attempt + 2, DecoderAttempts);
			::Sleep(250);
		}
	}
	if (!DecoderReady)
		throw std::runtime_error("Discovery ProcessEvent dispatcher did not yield one consistent UObject protected-slot decoder after bounded retries");

	PEIndex = Matches[0].Index;
	PEOffset = static_cast<int32>(Platform::GetOffset(Matches[0].Wrapper));
	Off::UFunction::FunctionFlags = Matches[0].FunctionFlagsOffset;
	const std::uintptr_t DispatcherOffset = Platform::GetOffset(Matches[0].Dispatcher);
	Discovery::ProcessEventDispatcherRva = DispatcherOffset;

	std::cerr << std::format("PE-Offset: 0x{:X}\n", PEOffset);
	std::cerr << std::format("PE-Index: 0x{:X}\n", PEIndex);
	std::cerr << std::format("Discovery UFunction::FunctionFlags recovered at +0x{:X}\n", Off::UFunction::FunctionFlags);
	std::cerr << std::format("Discovery UObject decoder recovered: address +0x{:X}, slots +0x{:X}/0x{:X}, {} extracted vector instructions\n", Discovery::ProtectedAddressOffset, Discovery::ProtectedSlotDataOffset, Discovery::ProtectedSlotStride, Discovery::ProtectedSlotProgramSize);
	std::cerr << std::format("Discovery ProcessEvent dispatcher validated at RVA 0x{:X}\n\n", DispatcherOffset);
#endif // PLATFORM_WINDOWS
}

void Off::InSDK::ProcessEvent::InitPE(const int32 Index, const char* const ModuleName)
{
	Off::InSDK::ProcessEvent::PEIndex = Index;

	void** VFT = *reinterpret_cast<void***>(ObjectArray::GetByIndex(0).GetAddress());

	Off::InSDK::ProcessEvent::PEOffset = Platform::GetOffset(VFT[Off::InSDK::ProcessEvent::PEIndex], ModuleName);

	std::cerr << std::format("PE-Offset: 0x{:X}\n", Off::InSDK::ProcessEvent::PEOffset);
}

/* UWorld */
void Off::InSDK::World::InitGWorld()
{
	UEClass UWorld = ObjectArray::FindClassFast("World");

	for (UEObject Obj : ObjectArray())
	{
		if (Obj.HasAnyFlags(EObjectFlags::ClassDefaultObject) || !Obj.IsA(UWorld))
			continue;

		/* Try to find a pointer to the word, aka UWorld** GWorld */
		auto Results = Platform::FindAllAlignedValuesInProcess(Obj.GetAddress());

		void* Result = nullptr;
		if (Results.size())
		{
			if (Results.size() == 1)
			{
				Result = Results[0];
			}
			else if (Results.size() == 2)
			{
				auto ObjAddress = reinterpret_cast<uintptr_t>(Obj.GetAddress());
				auto PossibleGWorld = reinterpret_cast<volatile uintptr_t*>(Results[0]);
				auto CurrentValue = *PossibleGWorld;

				for (int i = 0; CurrentValue == ObjAddress && i < 50; ++i)
				{
					::Sleep(1);
					CurrentValue = *PossibleGWorld;
				}
				if (CurrentValue == ObjAddress)
				{
					Result = Results[0];
				}
				else
				{
					Result = Results[1];
					std::cerr << std::format("Filter GActiveLogWorld at 0x{:X}\n\n", reinterpret_cast<uintptr_t>(PossibleGWorld));
				}
			}
			else
			{
				std::cerr << std::format("Detected {} GWorld \n\n", Results.size());
			}
		}

		/* Pointer to UWorld* couldn't be found */
		if (Result)
		{
			Off::InSDK::World::GWorld = Platform::GetOffset(Result);
			std::cerr << std::format("GWorld-Offset: 0x{:X}\n\n", Off::InSDK::World::GWorld);
			break;
		}
	}

	if (Off::InSDK::World::GWorld == 0x0)
		std::cerr << std::format("\nGWorld WAS NOT FOUND!!!!!!!!!\n\n");
}

/* FText */
void Off::InSDK::Text::InitTextOffsets()
{
	if (!Off::InSDK::ProcessEvent::PEIndex)
	{
		std::cerr << std::format("\nDumper-7: Error, 'InitInSDKTextOffsets' was called before ProcessEvent was initialized!\n") << std::endl;
		return;
	}

	auto IsValidPtr = [](void* a) -> bool
	{
		return !Platform::IsBadReadPtr(a) /* && (uintptr_t(a) & 0x1) == 0*/; // realistically, there wont be any pointers to unaligned memory
	};


	const UEFunction Conv_StringToText = ObjectArray::FindObjectFast<UEFunction>("Conv_StringToText", EClassCastFlags::Function);

	UEProperty InStringProp = nullptr;
	UEProperty ReturnProp = nullptr;

	if (!Conv_StringToText)
	{
		std::cerr << "Conv_StringToText is invalid!\n";
		return;
	}

	for (UEProperty Prop : Conv_StringToText.GetProperties())
	{
		/* Func has 2 params, if the param is the return value assign to ReturnProp, else InStringProp*/
		if (Prop.HasPropertyFlags(EPropertyFlags::ReturnParm))
		{
			ReturnProp = Prop;
		}
		else
		{
			InStringProp = Prop;
		}
	}

	const int32 ParamSize = Conv_StringToText.GetStructSize();
	const int32 FTextSize = ReturnProp.GetSize();

	const int32 StringOffset = InStringProp.GetOffset();
	const int32 ReturnValueOffset = ReturnProp.GetOffset();

	Off::InSDK::Text::TextSize = FTextSize;


	/* Allocate and zero-initialize ParamStruct */
#pragma warning(disable: 6255)
	uint8_t* ParamPtr = static_cast<uint8_t*>(alloca(ParamSize));
	memset(ParamPtr, 0, ParamSize);

	/* Choose a, fairly random, string to later search for in FTextData */
	constexpr const wchar_t* StringText = L"ThisIsAGoodString!";
	constexpr int32 StringLength = (sizeof(L"ThisIsAGoodString!") / sizeof(wchar_t));
	constexpr int32 StringLengthBytes = (sizeof(L"ThisIsAGoodString!"));

	/* Initialize 'InString' in the ParamStruct */
	*reinterpret_cast<FString*>(ParamPtr + StringOffset) = StringText;

	/* This function is 'static' so the object on which we call it doesn't matter */
	ObjectArray::GetByIndex(0).ProcessEvent(Conv_StringToText, ParamPtr);

	uint8_t* FTextDataPtr = nullptr;

	/* Search for the first valid pointer inside of the FText and make the offset our 'TextDatOffset' */
	for (int32 i = 0; i < (FTextSize - sizeof(void*)); i += sizeof(void*))
	{
		void* PossibleTextDataPtr = *reinterpret_cast<void**>(ParamPtr + ReturnValueOffset + i);

		if (IsValidPtr(PossibleTextDataPtr))
		{
			FTextDataPtr = static_cast<uint8_t*>(PossibleTextDataPtr);
			Off::InSDK::Text::TextDatOffset = i;
			break;
		}
	}

	if (!FTextDataPtr)
	{
		std::cerr << std::format("\nDumper-7: Error, 'FTextDataPtr' could not be found!\n") << std::endl;
		return;
	}

	constexpr int32 MaxOffset = 0x50;
	constexpr int32 StartOffset = sizeof(void*); // FString::NumElements offset

	/* Search for a pointer pointing to a int32 Value (FString::NumElements) equal to StringLength */
	for (int32 i = StartOffset; i < MaxOffset; i += sizeof(int32))
	{
		wchar_t* PosibleStringPtr = *reinterpret_cast<wchar_t**>((FTextDataPtr + i) - sizeof(void*));
		const int32 PossibleLength = *reinterpret_cast<int32*>(FTextDataPtr + i);

		if (PossibleLength == StringLength && PosibleStringPtr && IsValidPtr(PosibleStringPtr) && memcmp(StringText, PosibleStringPtr, StringLengthBytes) == 0)
		{
			Off::InSDK::Text::InTextDataStringOffset = (i - sizeof(void*));
			break;
		}
	}

	std::cerr << std::format("Off::InSDK::Text::TextSize: 0x{:X}\n", Off::InSDK::Text::TextSize);
	std::cerr << std::format("Off::InSDK::Text::TextDatOffset: 0x{:X}\n", Off::InSDK::Text::TextDatOffset);
	std::cerr << std::format("Off::InSDK::Text::InTextDataStringOffset: 0x{:X}\n\n", Off::InSDK::Text::InTextDataStringOffset);
}

void Off::Init()
{
	auto OverwriteIfInvalidOffset = [](int32& Offset, int32 DefaultValue)
	{
		if (Offset == OffsetFinder::OffsetNotFound)
		{
			std::cerr << std::format("Defaulting to offset: 0x{:X}\n", DefaultValue);
			Offset = DefaultValue;
		}
	};
	auto RequireDiscoveryOffset = [](const int32 Offset, const char* const Name)
	{
		if (Discovery::Enabled && Offset == OffsetFinder::OffsetNotFound)
			throw std::runtime_error(std::string("Discovery offset validation failed: ") + Name);
	};

	if (Discovery::Enabled)
	{
		Off::UObject::Flags = OffsetFinder::FindUObjectFlagsOffset();
		RequireDiscoveryOffset(Off::UObject::Flags, "UObject::Flags");
		Off::UObject::Index = ObjectArray::GetInternalIndexOffset();
		Off::UObject::Class = 0x10;
		Off::UObject::Name = 0x80;
		Off::UObject::Outer = 0x88;

		Off::FName::CompIdx = 0x0;
		Off::FName::Number = 0x4;
		Off::InSDK::Name::FNameSize = 0x8;
		Settings::Internal::bUseCasePreservingName = false;
		Settings::Internal::bUseOutlineNumberName = false;

		std::cerr << "Discovery protected UObject layout enabled\n";
		std::cerr << std::format("Off::UObject::Flags: 0x{:X}\n", Off::UObject::Flags);
		std::cerr << std::format("Off::UObject::Index: 0x{:X}\n", Off::UObject::Index);
		std::cerr << "UObject Class/Outer/Name are decoded from protected slots\n\n";
	}
	else
	{

	Off::UObject::Flags = OffsetFinder::FindUObjectFlagsOffset();
	OverwriteIfInvalidOffset(Off::UObject::Flags, sizeof(void*)); // Default to right after VTable
	std::cerr << std::format("Off::UObject::Flags: 0x{:X}\n", Off::UObject::Flags);

	Off::UObject::Index = OffsetFinder::FindUObjectIndexOffset();
	OverwriteIfInvalidOffset(Off::UObject::Index, (Off::UObject::Flags + sizeof(int32))); // Default to right after Flags
	std::cerr << std::format("Off::UObject::Index: 0x{:X}\n", Off::UObject::Index);

	Off::UObject::Class = OffsetFinder::FindUObjectClassOffset();
	OverwriteIfInvalidOffset(Off::UObject::Class, (Off::UObject::Index + sizeof(int32))); // Default to right after Index
	std::cerr << std::format("Off::UObject::Class: 0x{:X}\n", Off::UObject::Class);

	Off::UObject::Outer = OffsetFinder::FindUObjectOuterOffset();
	std::cerr << std::format("Off::UObject::Outer: 0x{:X}\n", Off::UObject::Outer);

	Off::UObject::Name = OffsetFinder::FindUObjectNameOffset();
	OverwriteIfInvalidOffset(Off::UObject::Name, (Off::UObject::Class + sizeof(void*))); // Default to right after Class
	std::cerr << std::format("Off::UObject::Name: 0x{:X}\n\n", Off::UObject::Name);

	OverwriteIfInvalidOffset(Off::UObject::Outer, (Off::UObject::Name + sizeof(int32) + sizeof(int32)));  // Default to right after Name

	OffsetFinder::InitFNameSettings();

	::NameArray::PostInit();
	}

	// Castflags needs to stay here since the FindChildOffset() uses CastFlags
	Off::UClass::CastFlags = OffsetFinder::FindCastFlagsOffset();
	std::cerr << std::format("Off::UClass::CastFlags: 0x{:X}\n", Off::UClass::CastFlags);
	RequireDiscoveryOffset(Off::UClass::CastFlags, "UClass::CastFlags");

	Off::UStruct::Children = OffsetFinder::FindChildOffset();
	std::cerr << std::format("Off::UStruct::Children: 0x{:X}\n", Off::UStruct::Children);
	RequireDiscoveryOffset(Off::UStruct::Children, "UStruct::Children");

	Off::UField::Next = OffsetFinder::FindUFieldNextOffset();
	std::cerr << std::format("Off::UField::Next: 0x{:X}\n", Off::UField::Next);
	RequireDiscoveryOffset(Off::UField::Next, "UField::Next");

	Off::UStruct::SuperStruct = OffsetFinder::FindSuperOffset();
	std::cerr << std::format("Off::UStruct::SuperStruct: 0x{:X}\n", Off::UStruct::SuperStruct);
	RequireDiscoveryOffset(Off::UStruct::SuperStruct, "UStruct::SuperStruct");

	Off::UStruct::Size = OffsetFinder::FindStructSizeOffset();
	std::cerr << std::format("Off::UStruct::Size: 0x{:X}\n", Off::UStruct::Size);
	RequireDiscoveryOffset(Off::UStruct::Size, "UStruct::Size");

	Off::UStruct::MinAlignment = OffsetFinder::FindMinAlignmentOffset();
	std::cerr << std::format("Off::UStruct::MinAlignment: 0x{:X}\n", Off::UStruct::MinAlignment);
	RequireDiscoveryOffset(Off::UStruct::MinAlignment, "UStruct::MinAlignment");

	Off::UClass::CastFlags = OffsetFinder::FindCastFlagsOffset();
	std::cerr << std::format("Off::UClass::CastFlags: 0x{:X}\n", Off::UClass::CastFlags);

	// Castflags become available for use

	if (Settings::Internal::bUseFProperty)
	{
		std::cerr << std::format("\nGame uses FProperty system\n\n");

		if (Discovery::Enabled)
		{
			Settings::Internal::bUseMaskForFieldOwner = true;
		}

		Off::UStruct::ChildProperties = OffsetFinder::FindChildPropertiesOffset();
		std::cerr << std::format("Off::UStruct::ChildProperties: 0x{:X}\n", Off::UStruct::ChildProperties);
		RequireDiscoveryOffset(Off::UStruct::ChildProperties, "UStruct::ChildProperties");
		if (Discovery::Enabled)
			OffsetFinder::InitDiscoveryFFieldLayout();

		if (!Discovery::Enabled)
			OffsetFinder::FixupHardcodedOffsets(); // must be called after FindChildPropertiesOffset

		if (!Discovery::Enabled)
			Off::FField::Next = OffsetFinder::FindFFieldNextOffset();
		std::cerr << std::format("Off::FField::Next: 0x{:X}\n", Off::FField::Next);
		RequireDiscoveryOffset(Off::FField::Next, "FField::Next");

		if (!Discovery::Enabled)
			Off::FField::Class = OffsetFinder::FindFFieldClassOffset();
		std::cerr << std::format("Off::FField::Class: 0x{:X}\n", Off::FField::Class);
		RequireDiscoveryOffset(Off::FField::Class, "FField::Class");

		// Comment out this line if you're crashing here and see if the NewFindFFieldNameOffset might work!
		if (!Discovery::Enabled)
			Off::FField::Name = OffsetFinder::FindFFieldNameOffset();
		//Off::FField::Name = OffsetFinder::NewFindFFieldNameOffset();

		if (Off::FField::Name == OffsetFinder::OffsetNotFound)
			Off::FField::Name = OffsetFinder::NewFindFFieldNameOffset();

		std::cerr << std::format("Off::FField::Name: 0x{:X}\n", Off::FField::Name);
		RequireDiscoveryOffset(Off::FField::Name, "FField::Name");

		/*
		* FNameSize might be wrong at this point of execution.
		* FField::Flags is not critical so a fix is only applied later in OffsetFinder::PostInitFNameSettings().
		*/
		if (!Discovery::Enabled)
			Off::FField::Flags = Off::FField::Name + Off::InSDK::Name::FNameSize;
		std::cerr << std::format("Off::FField::Flags: 0x{:X}\n", Off::FField::Flags);

		Off::FField::EditorOnlyMetadata = Discovery::Enabled ? OffsetFinder::OffsetNotFound : OffsetFinder::FindFFieldEditorOnlyMetaDataOffset();
		if (Off::FField::EditorOnlyMetadata != OffsetFinder::OffsetNotFound)
			std::cerr << std::format("Off::FField::EditorOnlyMetadata: 0x{:X}\n", Off::FField::EditorOnlyMetadata);

		if (!Discovery::Enabled)
			Off::FFieldClass::CastFlags = OffsetFinder::FindFieldClassCastFlagsOffset();
		std::cerr << std::format("Off::FFieldClass::CastFlags: 0x{:X}\n\n", Off::FFieldClass::CastFlags);
		RequireDiscoveryOffset(Off::FFieldClass::CastFlags, "FFieldClass::CastFlags");
	}

	std::cerr << "Discovery stage: resolving UStruct::StructBaseChain\n";
	Off::UStruct::StructBaseChain = OffsetFinder::FindStructBaseChainOffset();
	if (Off::UStruct::StructBaseChain != OffsetFinder::OffsetNotFound)
		std::cerr << std::format("Off::UStruct::StructBaseChain: 0x{:X}\n", Off::UStruct::StructBaseChain);

	std::cerr << "Discovery stage: resolving UClass::ClassDefaultObject\n";
	Off::UClass::ClassDefaultObject = OffsetFinder::FindDefaultObjectOffset();
	std::cerr << std::format("Off::UClass::ClassDefaultObject: 0x{:X}\n", Off::UClass::ClassDefaultObject);
	RequireDiscoveryOffset(Off::UClass::ClassDefaultObject, "UClass::ClassDefaultObject");

	std::cerr << "Discovery stage: resolving UClass::ImplementedInterfaces\n";
	Off::UClass::ImplementedInterfaces = OffsetFinder::FindImplementedInterfacesOffset();
	std::cerr << std::format("Off::UClass::ImplementedInterfaces: 0x{:X}\n", Off::UClass::ImplementedInterfaces);
	RequireDiscoveryOffset(Off::UClass::ImplementedInterfaces, "UClass::ImplementedInterfaces");

	std::cerr << "Discovery stage: resolving UEnum::Names\n";
	Off::UEnum::Names = OffsetFinder::FindEnumNamesOffset();
	std::cerr << std::format("Off::UEnum::Names: 0x{:X}\n", Off::UEnum::Names) << std::endl;
	RequireDiscoveryOffset(Off::UEnum::Names, "UEnum::Names");

	Off::UEnum::UnderlyingType = OffsetFinder::FindEnumUnderlayingTypeOffset();

	if (Settings::Internal::bHasUnderlayingTypeInUEnum)
		std::cerr << std::format("Off::UEnum::UnderlyingType: 0x{:X}\n", Off::UEnum::UnderlyingType) << std::endl;

	std::cerr << "Discovery stage: resolving UFunction layout\n";
	const int32 FoundFunctionFlags = OffsetFinder::FindFunctionFlagsOffset();
	if (Discovery::Enabled && FoundFunctionFlags != Off::UFunction::FunctionFlags)
		throw std::runtime_error(std::format("Discovery ProcessEvent UFunction::FunctionFlags offset 0x{:X} disagrees with reflection validation 0x{:X}", Off::UFunction::FunctionFlags, FoundFunctionFlags));
	Off::UFunction::FunctionFlags = FoundFunctionFlags;
	std::cerr << std::format("Off::UFunction::FunctionFlags: 0x{:X}\n", Off::UFunction::FunctionFlags);
	RequireDiscoveryOffset(Off::UFunction::FunctionFlags, "UFunction::FunctionFlags");

	Off::UFunction::ExecFunction = OffsetFinder::FindFunctionNativeFuncOffset();
	std::cerr << std::format("Off::UFunction::ExecFunction: 0x{:X}\n", Off::UFunction::ExecFunction) << std::endl;
	RequireDiscoveryOffset(Off::UFunction::ExecFunction, "UFunction::ExecFunction");

	std::cerr << "Discovery stage: resolving FProperty base layout\n";
	Off::Property::ElementSize = OffsetFinder::FindElementSizeOffset();
	std::cerr << std::format("Off::Property::ElementSize: 0x{:X}\n", Off::Property::ElementSize);
	RequireDiscoveryOffset(Off::Property::ElementSize, "Property::ElementSize");

	Off::Property::ArrayDim = OffsetFinder::FindArrayDimOffset();
	std::cerr << std::format("Off::Property::ArrayDim: 0x{:X}\n", Off::Property::ArrayDim);
	RequireDiscoveryOffset(Off::Property::ArrayDim, "Property::ArrayDim");

	Off::Property::Offset_Internal = OffsetFinder::FindOffsetInternalOffset();
	std::cerr << std::format("Off::Property::Offset_Internal: 0x{:X}\n", Off::Property::Offset_Internal);
	RequireDiscoveryOffset(Off::Property::Offset_Internal, "Property::Offset_Internal");

	Off::Property::PropertyFlags = OffsetFinder::FindPropertyFlagsOffset();
	std::cerr << std::format("Off::Property::PropertyFlags: 0x{:X}\n", Off::Property::PropertyFlags);
	RequireDiscoveryOffset(Off::Property::PropertyFlags, "Property::PropertyFlags");

	if (Discovery::Enabled)
	{
		Off::ObjectProperty::PropertyClass = OffsetFinder::FindObjectPropertyClassOffset();
		RequireDiscoveryOffset(Off::ObjectProperty::PropertyClass, "ObjectProperty::PropertyClass");
	}

	Off::BoolProperty::Base = OffsetFinder::FindBoolPropertyBaseOffset();
	std::cerr << std::format("UBoolProperty::Base: 0x{:X}\n", Off::BoolProperty::Base) << std::endl;
	RequireDiscoveryOffset(Off::BoolProperty::Base, "BoolProperty::Base");

	Off::EnumProperty::Base = OffsetFinder::FindEnumPropertyBaseOffset();
	std::cerr << std::format("Off::EnumProperty::Base: 0x{:X}\n", Off::EnumProperty::Base) << std::endl;


	if (Off::EnumProperty::Base == OffsetFinder::OffsetNotFound)
	{
		Off::InSDK::Properties::PropertySize = Off::BoolProperty::Base;
		Off::EnumProperty::Base = Off::BoolProperty::Base;
	}
	else
	{
		Off::InSDK::Properties::PropertySize = Off::EnumProperty::Base;
	}

	std::cerr << std::format("UPropertySize: 0x{:X}\n", Off::InSDK::Properties::PropertySize) << std::endl;

	Off::ObjectProperty::PropertyClass = OffsetFinder::FindObjectPropertyClassOffset();
	std::cerr << std::format("Off::ObjectProperty::PropertyClass: 0x{:X}", Off::ObjectProperty::PropertyClass) << std::endl;
	if (Discovery::Enabled)
		RequireDiscoveryOffset(Off::ObjectProperty::PropertyClass, "ObjectProperty::PropertyClass");
	else
		OverwriteIfInvalidOffset(Off::ObjectProperty::PropertyClass, Off::InSDK::Properties::PropertySize);

	Off::ByteProperty::Enum = OffsetFinder::FindBytePropertyEnumOffset();
	if (Discovery::Enabled)
		RequireDiscoveryOffset(Off::ByteProperty::Enum, "ByteProperty::Enum");
	else
		OverwriteIfInvalidOffset(Off::ByteProperty::Enum, Off::InSDK::Properties::PropertySize);
	std::cerr << std::format("Off::ByteProperty::Enum: 0x{:X}", Off::ByteProperty::Enum) << std::endl;

	Off::StructProperty::Struct = OffsetFinder::FindStructPropertyStructOffset();
	if (Discovery::Enabled)
		RequireDiscoveryOffset(Off::StructProperty::Struct, "StructProperty::Struct");
	else
		OverwriteIfInvalidOffset(Off::StructProperty::Struct, Off::InSDK::Properties::PropertySize);
	std::cerr << std::format("Off::StructProperty::Struct: 0x{:X}\n", Off::StructProperty::Struct) << std::endl;

	Off::DelegateProperty::SignatureFunction = OffsetFinder::FindDelegatePropertySignatureFunctionOffset();
	if (Discovery::Enabled)
		RequireDiscoveryOffset(Off::DelegateProperty::SignatureFunction, "DelegateProperty::SignatureFunction");
	else
		OverwriteIfInvalidOffset(Off::DelegateProperty::SignatureFunction, Off::InSDK::Properties::PropertySize);
	std::cerr << std::format("Off::DelegateProperty::SignatureFunction: 0x{:X}\n", Off::DelegateProperty::SignatureFunction) << std::endl;

	Off::ArrayProperty::Inner = OffsetFinder::FindInnerTypeOffset(Off::InSDK::Properties::PropertySize);
	std::cerr << std::format("Off::ArrayProperty::Inner: 0x{:X}\n", Off::ArrayProperty::Inner);

	Off::SetProperty::ElementProp = OffsetFinder::FindSetPropertyBaseOffset(Off::InSDK::Properties::PropertySize);
	std::cerr << std::format("Off::SetProperty::ElementProp: 0x{:X}\n", Off::SetProperty::ElementProp);

	Off::MapProperty::Base = OffsetFinder::FindMapPropertyBaseOffset(Off::InSDK::Properties::PropertySize);
	std::cerr << std::format("Off::MapProperty::Base: 0x{:X}\n", Off::MapProperty::Base) << std::endl;

	if (Discovery::Enabled)
	{
		const int32 PropertySize = Off::InSDK::Properties::PropertySize;
		auto RequireBaseMember = [PropertySize](const int32 Offset, const int32 Size, const char* const Name)
		{
			if (Offset < 0 || Size <= 0 || Offset + Size > PropertySize)
				throw std::runtime_error(std::format("Discovery {} +0x{:X} size 0x{:X} is outside FProperty size 0x{:X}", Name, Offset, Size, PropertySize));
		};
		auto RequireDerivedMember = [PropertySize](const int32 Offset, const char* const Name)
		{
			if (Offset < PropertySize || Offset > PropertySize + 0x40 || (Offset % alignof(void*)) != 0)
				throw std::runtime_error(std::format("Discovery {} +0x{:X} is inconsistent with FProperty size 0x{:X}", Name, Offset, PropertySize));
		};

		if (PropertySize <= 0 || PropertySize > 0x400 || Off::BoolProperty::Base != PropertySize || Off::EnumProperty::Base != PropertySize)
			throw std::runtime_error(std::format("Discovery property bases are inconsistent: FProperty=0x{:X}, Bool=0x{:X}, Enum=0x{:X}", PropertySize, Off::BoolProperty::Base, Off::EnumProperty::Base));
		RequireBaseMember(Off::Property::PropertyFlags, sizeof(uint64), "FProperty::PropertyFlags");
		RequireBaseMember(Off::Property::ArrayDim, sizeof(int32), "FProperty::ArrayDim");
		RequireBaseMember(Off::Property::ElementSize, sizeof(int32), "FProperty::ElementSize");
		RequireBaseMember(Off::Property::Offset_Internal, sizeof(int32), "FProperty::Offset_Internal");
		RequireDerivedMember(Off::ObjectProperty::PropertyClass, "FObjectPropertyBase::PropertyClass");
		RequireDerivedMember(Off::ByteProperty::Enum, "FByteProperty::Enum");
		RequireDerivedMember(Off::StructProperty::Struct, "FStructProperty::Struct");
		RequireDerivedMember(Off::DelegateProperty::SignatureFunction, "FDelegateProperty::SignatureFunction");
		RequireDerivedMember(Off::ArrayProperty::Inner, "FArrayProperty::Inner");
		RequireDerivedMember(Off::SetProperty::ElementProp, "FSetProperty::ElementProp");
		RequireDerivedMember(Off::MapProperty::Base, "FMapProperty::Base");
		std::cerr << "Discovery property-layout invariants validated\n";
	}

	Off::InSDK::ULevel::Actors = OffsetFinder::FindLevelActorsOffset();
	std::cerr << std::format("Off::InSDK::ULevel::Actors: 0x{:X}\n", Off::InSDK::ULevel::Actors) << std::endl;

	Off::InSDK::UDataTable::RowMap = OffsetFinder::FindDatatableRowMapOffset();
	std::cerr << std::format("Off::InSDK::UDataTable::RowMap: 0x{:X}\n", Off::InSDK::UDataTable::RowMap) << std::endl;

	OffsetFinder::PostInitFNameSettings();

	std::cerr << std::endl;

	Off::FieldPathProperty::FieldClass = Off::InSDK::Properties::PropertySize;
	Off::OptionalProperty::ValueProperty = Off::InSDK::Properties::PropertySize;

	Off::ClassProperty::MetaClass = Off::ObjectProperty::PropertyClass + sizeof(void*); //0x8 inheritance from ObjectProperty

	Off::FInstancedStruct::ScriptStruct = 0x00;
	Off::FInstancedStruct::StructMemory = Off::FInstancedStruct::ScriptStruct + sizeof(void*);
}

void PropertySizes::Init()
{
	InitTDelegateSize();
	InitFFieldPathSize();
	InitTMulticastInlineDelegateSize();
}

void PropertySizes::InitTDelegateSize()
{
	/* If the AudioComponent class or the OnQueueSubtitles member weren't found, fallback to looping GObjects and looking for a Delegate. */
	auto OnPropertyNotFound = [&]() -> void
	{
		for (UEObject Obj : ObjectArray())
		{
			if (!Obj.IsA(EClassCastFlags::Struct))
				continue;

			for (UEProperty Prop : Obj.Cast<UEClass>().GetProperties())
			{
				if (Prop.IsA(EClassCastFlags::DelegateProperty))
				{
					PropertySizes::DelegateProperty = Prop.GetSize();
					return;
				}
			}
		}
	};

	const UEClass AudioComponentClass = ObjectArray::FindClassFast("AudioComponent");

	if (!AudioComponentClass)
		return OnPropertyNotFound();

	const UEProperty OnQueueSubtitlesProp = AudioComponentClass.FindMember("OnQueueSubtitles", EClassCastFlags::DelegateProperty);

	if (!OnQueueSubtitlesProp)
		return OnPropertyNotFound();

	PropertySizes::DelegateProperty = OnQueueSubtitlesProp.GetSize();
}

void PropertySizes::InitFFieldPathSize()
{
	if (!Settings::Internal::bUseFProperty)
		return;

	/* If the SetFieldPathPropertyByName function or the Value parameter weren't found, fallback to looping GObjects and looking for a Delegate. */
	auto OnPropertyNotFound = [&]() -> void
	{
		for (UEObject Obj : ObjectArray())
		{
			if (!Obj.IsA(EClassCastFlags::Struct))
				continue;

			for (UEProperty Prop : Obj.Cast<UEClass>().GetProperties())
			{
				if (Prop.IsA(EClassCastFlags::FieldPathProperty))
				{
					PropertySizes::FieldPathProperty = Prop.GetSize();
					return;
				}
			}
		}
	};

	const UEFunction SetFieldPathPropertyByNameFunc = ObjectArray::FindObjectFast<UEFunction>("SetFieldPathPropertyByName", EClassCastFlags::Function);

	if (!SetFieldPathPropertyByNameFunc)
		return OnPropertyNotFound();

	const UEProperty ValueParamProp = SetFieldPathPropertyByNameFunc.FindMember("Value", EClassCastFlags::FieldPathProperty);

	if (!ValueParamProp)
		return OnPropertyNotFound();

	PropertySizes::FieldPathProperty = ValueParamProp.GetSize();
}

void PropertySizes::InitTMulticastInlineDelegateSize()
{
	/* If the AudioComponent class or the OnQueueSubtitles member weren't found, fallback to looping GObjects and looking for a Delegate. */
	auto OnPropertyNotFound = [&]() -> void
		{
			for (UEObject Obj : ObjectArray())
			{
				if (!Obj.IsA(EClassCastFlags::Struct))
					continue;

				for (UEProperty Prop : Obj.Cast<UEClass>().GetProperties())
				{
					if (Prop.IsA(EClassCastFlags::MulticastInlineDelegateProperty))
					{
						PropertySizes::DelegateProperty = Prop.GetSize();
						return;
					}
				}
			}
		};

	const UEClass EmitterClass = ObjectArray::FindClassFast("Emitter");

	if (!EmitterClass)
		return OnPropertyNotFound();

	const UEProperty OnParticleSpawn = EmitterClass.FindMember("OnParticleSpawn", EClassCastFlags::MulticastDelegateProperty);

	if (!OnParticleSpawn)
		return OnPropertyNotFound();

	PropertySizes::MulticastInlineDelegateProperty = OnParticleSpawn.GetSize();
}
