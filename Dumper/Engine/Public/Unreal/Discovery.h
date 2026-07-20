#pragma once

#include <bit>
#include <array>
#include <cstdint>
#include <cstring>

namespace Discovery
{
	inline constexpr bool Enabled = true;
	inline constexpr bool ProbeOnly = false;

	inline std::uint32_t ElementsPerChunk = 0;
	inline constexpr std::uint32_t FUObjectItemSize = 0x14;
	inline std::uint32_t ObjectCount = 0;
	inline std::uintptr_t ChunkTableAddress = 0;
	inline std::uint32_t ChunkCount = 0;
	inline std::uint64_t ProcessEventDispatcherRva = 0;

	inline std::uint32_t FunctionFlagsXorKey = 0;
	inline std::uint64_t ClassCastFlagsXorKey = 0;
	inline std::uint32_t PropertyOffsetXorKey = 0;
	inline std::uint64_t PropertyFlagsXorKey = 0;

	inline bool UObjectDecoderReady = false;
	inline bool ProtectedHashReady = false;
	inline std::uint32_t ProtectedAddressOffset = 0;

	enum class ProtectedScalarOpcode : std::uint8_t
	{
		LoadAddress,
		Move,
		ShiftRight,
		RotateLeft,
		Multiply,
		Add,
		AddImmediate,
		LeaAddImmediate,
		Xor,
		Increment,
		AndImmediate,
		Return,
	};

	struct ProtectedScalarInstruction
	{
		ProtectedScalarOpcode Opcode{};
		std::uint8_t Destination = 0;
		std::uint8_t Source = 0;
		bool Is64Bit = false;
		std::uint32_t Immediate = 0;
	};

	inline std::array<ProtectedScalarInstruction, 32> ProtectedHashProgram{};
	inline std::uint32_t ProtectedHashProgramSize = 0;
	inline std::uint32_t ProtectedSlotDataOffset = 0;
	inline std::uint32_t ProtectedSlotStride = 0;

	enum class ProtectedVectorOpcode : std::uint8_t
	{
		Move,
		Xor,
		ShiftRightWords,
		ShiftLeftWords,
		ShiftRightQwords,
		ShiftLeftQwords,
		AddWords,
		Or,
		ShuffleLowWords,
		ShuffleBytes,
		ReturnLowQword,
		And,
		AndNot,
		ShiftRightDwords,
		ShiftLeftDwords,
	};

	struct ProtectedVectorInstruction
	{
		ProtectedVectorOpcode Opcode{};
		std::uint8_t Destination = 0;
		std::uint8_t Source = 0;
		std::uint8_t Immediate = 0;
		bool SourceIsConstant = false;
		std::array<std::uint8_t, 16> Constant{};
	};

	inline std::uint8_t ProtectedSlotInputRegister = 0;
	inline std::array<ProtectedVectorInstruction, 32> ProtectedSlotProgram{};
	inline std::uint32_t ProtectedSlotProgramSize = 0;
	inline std::array<std::uint8_t, 4> ProtectedClassSlots{};
	inline std::array<std::uint8_t, 4> ProtectedOuterSlots{};
	inline std::array<std::uint8_t, 4> ProtectedNameSlots{};

	inline bool FieldNameDecoderReady = false;
	inline std::uint32_t FieldNameOffset = 0;
	inline std::uint8_t FieldNameInputRegister = 0;
	inline std::array<ProtectedVectorInstruction, 32> FieldNameProgram{};
	inline std::uint32_t FieldNameProgramSize = 0;
	inline std::uint64_t FieldNameScalarXor = 0;
	inline std::uint8_t FieldNameScalarRotate = 0;

	inline std::uint32_t GetProtectedSlot(const void* Object)
	{
		std::array<std::uint64_t, 16> Registers{};
		for (std::uint32_t Index = 0; Index < ProtectedHashProgramSize; ++Index)
		{
			const ProtectedScalarInstruction& Instruction = ProtectedHashProgram[Index];
			auto Write = [&](const std::uint64_t Value)
			{
				Registers[Instruction.Destination] = Instruction.Is64Bit ? Value : static_cast<std::uint32_t>(Value);
			};

			switch (Instruction.Opcode)
			{
			case ProtectedScalarOpcode::LoadAddress:
				Write(reinterpret_cast<std::uintptr_t>(Object) + static_cast<std::int32_t>(Instruction.Immediate));
				break;
			case ProtectedScalarOpcode::Move:
				Write(Registers[Instruction.Source]);
				break;
			case ProtectedScalarOpcode::ShiftRight:
				Write(Registers[Instruction.Source] >> Instruction.Immediate);
				break;
			case ProtectedScalarOpcode::RotateLeft:
				if (Instruction.Is64Bit)
					Write(std::rotl(Registers[Instruction.Source], static_cast<int>(Instruction.Immediate)));
				else
					Write(std::rotl(static_cast<std::uint32_t>(Registers[Instruction.Source]), static_cast<int>(Instruction.Immediate)));
				break;
			case ProtectedScalarOpcode::Multiply:
				Write(static_cast<std::uint32_t>(Registers[Instruction.Source]) * Instruction.Immediate);
				break;
			case ProtectedScalarOpcode::Add:
				Write(Registers[Instruction.Destination] + Registers[Instruction.Source]);
				break;
			case ProtectedScalarOpcode::AddImmediate:
			case ProtectedScalarOpcode::LeaAddImmediate:
				Write(Registers[Instruction.Source] + static_cast<std::int32_t>(Instruction.Immediate));
				break;
			case ProtectedScalarOpcode::Xor:
				Write(Registers[Instruction.Destination] ^ Registers[Instruction.Source]);
				break;
			case ProtectedScalarOpcode::Increment:
				Write(Registers[Instruction.Source] + 1);
				break;
			case ProtectedScalarOpcode::AndImmediate:
				Write(Registers[Instruction.Source] & Instruction.Immediate);
				break;
			case ProtectedScalarOpcode::Return:
				return static_cast<std::uint32_t>(Registers[Instruction.Source]);
			}
		}

		return 0;
	}

	inline std::uint64_t DecodeProtectedSlot(const void* Object, const std::uint32_t Slot)
	{
		std::array<std::array<std::uint8_t, 16>, 16> Registers{};
		const auto* Encoded = static_cast<const std::uint8_t*>(Object) + ProtectedSlotDataOffset + ((Slot & 0x3) * ProtectedSlotStride);
		std::memcpy(Registers[ProtectedSlotInputRegister].data(), Encoded, 16);

		for (std::uint32_t Index = 0; Index < ProtectedSlotProgramSize; ++Index)
		{
			const ProtectedVectorInstruction& Instruction = ProtectedSlotProgram[Index];
			auto& Destination = Registers[Instruction.Destination];
			const auto& Source = Instruction.SourceIsConstant ? Instruction.Constant : Registers[Instruction.Source];

			switch (Instruction.Opcode)
			{
			case ProtectedVectorOpcode::Move:
				Destination = Source;
				break;
			case ProtectedVectorOpcode::Xor:
				for (std::size_t Byte = 0; Byte < Destination.size(); ++Byte)
					Destination[Byte] ^= Source[Byte];
				break;
			case ProtectedVectorOpcode::ShiftRightWords:
			case ProtectedVectorOpcode::ShiftLeftWords:
			case ProtectedVectorOpcode::AddWords:
			{
				std::array<std::uint16_t, 8> DestinationWords{};
				std::array<std::uint16_t, 8> SourceWords{};
				std::memcpy(DestinationWords.data(), Destination.data(), Destination.size());
				std::memcpy(SourceWords.data(), Source.data(), Source.size());
				for (std::size_t Word = 0; Word < DestinationWords.size(); ++Word)
				{
					if (Instruction.Opcode == ProtectedVectorOpcode::ShiftRightWords)
						DestinationWords[Word] >>= Instruction.Immediate;
					else if (Instruction.Opcode == ProtectedVectorOpcode::ShiftLeftWords)
						DestinationWords[Word] <<= Instruction.Immediate;
					else
						DestinationWords[Word] += SourceWords[Word];
				}
				std::memcpy(Destination.data(), DestinationWords.data(), Destination.size());
				break;
			}
			case ProtectedVectorOpcode::ShiftRightQwords:
			case ProtectedVectorOpcode::ShiftLeftQwords:
			{
				std::array<std::uint64_t, 2> Qwords{};
				std::memcpy(Qwords.data(), Destination.data(), Destination.size());
				for (std::uint64_t& Qword : Qwords)
				{
					if (Instruction.Opcode == ProtectedVectorOpcode::ShiftRightQwords)
						Qword >>= Instruction.Immediate;
					else
						Qword <<= Instruction.Immediate;
				}
				std::memcpy(Destination.data(), Qwords.data(), Destination.size());
				break;
			}
			case ProtectedVectorOpcode::ShiftRightDwords:
			case ProtectedVectorOpcode::ShiftLeftDwords:
			{
				std::array<std::uint32_t, 4> Dwords{};
				std::memcpy(Dwords.data(), Destination.data(), Destination.size());
				for (std::uint32_t& Dword : Dwords)
				{
					if (Instruction.Opcode == ProtectedVectorOpcode::ShiftRightDwords)
						Dword >>= Instruction.Immediate;
					else
						Dword <<= Instruction.Immediate;
				}
				std::memcpy(Destination.data(), Dwords.data(), Destination.size());
				break;
			}
			case ProtectedVectorOpcode::Or:
				for (std::size_t Byte = 0; Byte < Destination.size(); ++Byte)
					Destination[Byte] |= Source[Byte];
				break;
			case ProtectedVectorOpcode::And:
				for (std::size_t Byte = 0; Byte < Destination.size(); ++Byte)
					Destination[Byte] &= Source[Byte];
				break;
			case ProtectedVectorOpcode::AndNot:
				for (std::size_t Byte = 0; Byte < Destination.size(); ++Byte)
					Destination[Byte] = static_cast<std::uint8_t>(~Destination[Byte]) & Source[Byte];
				break;
			case ProtectedVectorOpcode::ShuffleLowWords:
			{
				const auto Input = Source;
				Destination = Input;
				for (std::size_t Word = 0; Word < 4; ++Word)
				{
					const std::size_t SourceWord = (Instruction.Immediate >> (Word * 2)) & 0x3;
					Destination[Word * 2] = Input[SourceWord * 2];
					Destination[Word * 2 + 1] = Input[SourceWord * 2 + 1];
				}
				break;
			}
			case ProtectedVectorOpcode::ShuffleBytes:
			{
				const auto Input = Destination;
				for (std::size_t Byte = 0; Byte < Destination.size(); ++Byte)
					Destination[Byte] = (Source[Byte] & 0x80) ? 0 : Input[Source[Byte] & 0x0F];
				break;
			}
			case ProtectedVectorOpcode::ReturnLowQword:
			{
				std::uint64_t Result = 0;
				std::memcpy(&Result, Source.data(), sizeof(Result));
				return std::rotl(Result, static_cast<int>(Instruction.Immediate));
			}
			}
		}

		return 0;
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
		std::array<std::array<std::uint8_t, 16>, 16> Registers{};
		std::memcpy(Registers[FieldNameInputRegister].data(), static_cast<const std::uint8_t*>(Field) + FieldNameOffset, 16);
		for (std::uint32_t Index = 0; Index < FieldNameProgramSize; ++Index)
		{
			const ProtectedVectorInstruction& Instruction = FieldNameProgram[Index];
			auto& Destination = Registers[Instruction.Destination];
			const auto& Source = Instruction.SourceIsConstant ? Instruction.Constant : Registers[Instruction.Source];
			switch (Instruction.Opcode)
			{
			case ProtectedVectorOpcode::Move:
				Destination = Source;
				break;
			case ProtectedVectorOpcode::Xor:
			case ProtectedVectorOpcode::Or:
			case ProtectedVectorOpcode::And:
			case ProtectedVectorOpcode::AndNot:
				for (std::size_t Byte = 0; Byte < Destination.size(); ++Byte)
				{
					if (Instruction.Opcode == ProtectedVectorOpcode::Xor)
						Destination[Byte] ^= Source[Byte];
					else if (Instruction.Opcode == ProtectedVectorOpcode::Or)
						Destination[Byte] |= Source[Byte];
					else if (Instruction.Opcode == ProtectedVectorOpcode::And)
						Destination[Byte] &= Source[Byte];
					else
						Destination[Byte] = static_cast<std::uint8_t>(~Destination[Byte]) & Source[Byte];
				}
				break;
			case ProtectedVectorOpcode::ShiftRightWords:
			case ProtectedVectorOpcode::ShiftLeftWords:
			case ProtectedVectorOpcode::AddWords:
			{
				std::array<std::uint16_t, 8> DestinationWords{};
				std::array<std::uint16_t, 8> SourceWords{};
				std::memcpy(DestinationWords.data(), Destination.data(), Destination.size());
				std::memcpy(SourceWords.data(), Source.data(), Source.size());
				for (std::size_t Word = 0; Word < DestinationWords.size(); ++Word)
				{
					if (Instruction.Opcode == ProtectedVectorOpcode::ShiftRightWords)
						DestinationWords[Word] >>= Instruction.Immediate;
					else if (Instruction.Opcode == ProtectedVectorOpcode::ShiftLeftWords)
						DestinationWords[Word] <<= Instruction.Immediate;
					else
						DestinationWords[Word] += SourceWords[Word];
				}
				std::memcpy(Destination.data(), DestinationWords.data(), Destination.size());
				break;
			}
			case ProtectedVectorOpcode::ShiftRightQwords:
			case ProtectedVectorOpcode::ShiftLeftQwords:
			{
				std::array<std::uint64_t, 2> Qwords{};
				std::memcpy(Qwords.data(), Destination.data(), Destination.size());
				for (std::uint64_t& Qword : Qwords)
				{
					if (Instruction.Opcode == ProtectedVectorOpcode::ShiftRightQwords)
						Qword >>= Instruction.Immediate;
					else
						Qword <<= Instruction.Immediate;
				}
				std::memcpy(Destination.data(), Qwords.data(), Destination.size());
				break;
			}
			case ProtectedVectorOpcode::ShiftRightDwords:
			case ProtectedVectorOpcode::ShiftLeftDwords:
			{
				std::array<std::uint32_t, 4> Dwords{};
				std::memcpy(Dwords.data(), Destination.data(), Destination.size());
				for (std::uint32_t& Dword : Dwords)
				{
					if (Instruction.Opcode == ProtectedVectorOpcode::ShiftRightDwords)
						Dword >>= Instruction.Immediate;
					else
						Dword <<= Instruction.Immediate;
				}
				std::memcpy(Destination.data(), Dwords.data(), Destination.size());
				break;
			}
			case ProtectedVectorOpcode::ShuffleLowWords:
			{
				const auto Input = Source;
				Destination = Input;
				for (std::size_t Word = 0; Word < 4; ++Word)
				{
					const std::size_t SourceWord = (Instruction.Immediate >> (Word * 2)) & 0x3;
					Destination[Word * 2] = Input[SourceWord * 2];
					Destination[Word * 2 + 1] = Input[SourceWord * 2 + 1];
				}
				break;
			}
			case ProtectedVectorOpcode::ShuffleBytes:
			{
				const auto Input = Destination;
				for (std::size_t Byte = 0; Byte < Destination.size(); ++Byte)
					Destination[Byte] = (Source[Byte] & 0x80) ? 0 : Input[Source[Byte] & 0x0F];
				break;
			}
			case ProtectedVectorOpcode::ReturnLowQword:
			{
				std::uint64_t Result = 0;
				std::memcpy(&Result, Source.data(), sizeof(Result));
				Result = std::rotl(Result, static_cast<int>(Instruction.Immediate));
				return std::rotl(Result ^ FieldNameScalarXor, static_cast<int>(FieldNameScalarRotate));
			}
			}
		}
		return 0;
	}
}
