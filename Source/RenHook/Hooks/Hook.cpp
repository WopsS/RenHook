#include <RenHook/RenHook.hpp>
#include <RenHook/Hooks/Hook.hpp>
#include <RenHook/Memory/Protection.hpp>
#include <RenHook/Threads/Threads.hpp>

RenHook::Hook::Hook(const uintptr_t Address, const uintptr_t Detour)
    : m_address(Address)
    , m_size(GetMinimumSize(Address))
    , m_memoryBlock(nullptr)
{
    if (m_size >= 5)
    {
        // Create our memory block with hook size + necessary size for conditional jumps.
        m_memoryBlock = std::make_unique<RenHook::Memory::Block>(Address, m_size + (CountConditionalJumps(Address) * 16));

        RenHook::Managers::Threads Threads;
        Threads.Suspend();

        // Backup the original bytes.
        m_memoryBlock->CopyFrom(Address, m_size);

        Memory::Protection Protection(Address, m_size);
        Protection.Change(PAGE_EXECUTE_READWRITE);

        // Relocate RIP addresses with our address.
        RelocateRIP(Address, m_memoryBlock->GetAddress());

        auto HookSize = WriteJump(Address, Detour, m_size);

        // Jump back to the original code (16 bytes).
        WriteJump(m_memoryBlock->GetAddress() + m_size, Address + m_size, 16);

        // Set unused bytes as NOP.
        if (HookSize < m_size)
        {
            std::memset(reinterpret_cast<uintptr_t*>(Address + HookSize), 0x90, m_size - HookSize);
        }

        Protection.Restore();
        Threads.Resume();
    }
    else
    {
        throw std::invalid_argument("Size is lower than 5 bytes");
    }
}

RenHook::Hook::~Hook()
{
    if (m_memoryBlock != nullptr)
    {
        RenHook::Managers::Threads Threads;
        Threads.Suspend();

        Memory::Protection Protection(m_address, m_size);
        Protection.Change(PAGE_EXECUTE_READWRITE);

        // Restore the original bytes.
        m_memoryBlock->CopyTo(m_address, m_size);

        // Relocate RIP addresses back to their original value.
        RelocateRIP(m_memoryBlock->GetAddress(), m_address);

        Protection.Restore();
        Threads.Resume();
    }
}

std::shared_ptr<RenHook::Hook> RenHook::Hook::Get(const uintptr_t Address)
{
    return RenHook::Managers::Hooks::Get(Address);
}

std::shared_ptr<RenHook::Hook> RenHook::Hook::Get(const std::string& Key)
{
    return RenHook::Managers::Hooks::Get(Key);
}

std::shared_ptr<RenHook::Hook> RenHook::Hook::Get(const std::string& Module, const std::string& Function)
{
    return RenHook::Managers::Hooks::Get(Module, Function);
}

void RenHook::Hook::Remove(const uintptr_t Address)
{
    return RenHook::Managers::Hooks::Remove(Address);
}

void RenHook::Hook::Remove(const std::string& Key)
{
    return RenHook::Managers::Hooks::Remove(Key);
}

void RenHook::Hook::Remove(const std::string& Module, const std::string& Function)
{
    return RenHook::Managers::Hooks::Remove(Module, Function);
}

void RenHook::Hook::RemoveAll()
{
    RenHook::Managers::Hooks::RemoveAll();
}

void RenHook::Hook::SetImageBase(const uintptr_t Value)
{
    RenHook::Managers::Hooks::Private::ImageBase = Value;
}

const bool RenHook::Hook::IsValid() const
{
    return m_size >= 5 && m_memoryBlock != nullptr && m_memoryBlock->GetAddress() > 0;
}

const size_t RenHook::Hook::CheckSize(const RenHook::Capstone& Capstone, const size_t MinimumSize) const
{
    size_t Size = 0;

    for (size_t i = 0; i < Capstone.GetTotalNumberOfInstructions(); i++)
    {
        Size += Capstone.GetInstructionSize(i);

        if (Size >= MinimumSize)
        {
            return Size;
        }
    }

    return 0;
}

const size_t RenHook::Hook::CountConditionalJumps(const uintptr_t Address) const
{
    size_t Result = 0;

    RenHook::Capstone Capstone;
    Capstone.Disassemble(Address, m_size);

    for (size_t i = 0; i < Capstone.GetTotalNumberOfInstructions(); i++)
    {
        auto Instruction = Capstone.GetInstructionAt(i);
        auto& Structure = Instruction->detail->x86;

        // Check all operands.
        for (size_t j = 0; j < Structure.op_count; j++)
        {
            auto& Operand = Structure.operands[j];

            if (Operand.type == X86_OP_IMM && IsConditionalJump(Instruction->bytes, Instruction->size) == true)
            {
                Result++;
            }
        }
    }

    return Result;
}

const size_t RenHook::Hook::GetMinimumSize(const uintptr_t Address) const
{
    size_t Size = 0;

    RenHook::Capstone Capstone;
    Capstone.Disassemble(Address, 128);

    // Check if we can do a 16 byte jump.
    Size = CheckSize(Capstone, 16);

    // Check if we can do a 6 byte jump if we can't do a 16 byte jump.
    if (Size == 0)
    {
        Size = CheckSize(Capstone, 6);

        // Check if we can do a 5 byte jump if we can't do a 6 byte jump.
        if (Size == 0)
        {
            Size = CheckSize(Capstone, 5);
        }
    }

    return Size;
}

const bool RenHook::Hook::IsConditionalJump(const uint8_t* Bytes, const size_t Size) const
{
    if (Size > 0)
    {
        // See https://software.intel.com/sites/default/files/managed/a4/60/325383-sdm-vol-2abcd.pdf (Jcc - Jump if Condition Is Met).

        if (Bytes[0] == 0xE3)
        {
            return true;
        }
        else if (Bytes[0] >= 0x70 && Bytes[0] <= 0x7F)
        {
            return true;
        }
        else if ((Bytes[0] == 0x0F && Size > 1) && (Bytes[1] >= 0x80 && Bytes[1] <= 0x8F))
        {
            return true;
        }
    }


    return false;
}

const void RenHook::Hook::RelocateRIP(const uintptr_t From, const uintptr_t To) const
{
    RenHook::Capstone Capstone;

    auto Instructions = Capstone.Disassemble(From, m_size);
    size_t NumberOfConditionalJumps = 0;

    for (size_t i = 0; i < Instructions; i++)
    {
        auto Instruction = Capstone.GetInstructionAt(i);
        auto& Structure = Instruction->detail->x86;

        // Check all operands.
        for (size_t j = 0; j < Structure.op_count; j++)
        {
            auto& Operand = Structure.operands[j];

            uintptr_t DisplacementAddress = 0;

            if (Operand.type == X86_OP_MEM && Operand.mem.base == X86_REG_RIP)
            {
                // Calculate the displacement address.
                DisplacementAddress = Instruction->address + Instruction->size + Structure.disp;
            }
            else if (Operand.type == X86_OP_IMM)
            {
                // Skip instructions like "sub something, something".
                if (Structure.op_count > 1)
                {
                    continue;
                }

                // Calculate the displacement address.
                DisplacementAddress = Structure.operands[0].imm;
            }

            if (DisplacementAddress > 0)
            {
                size_t UsedBytes = 0;

                if (Structure.rex > 0)
                {
                    UsedBytes++;
                }

                for (int i = 0; i < sizeof(Structure.opcode); i++)
                {
                    if (Structure.opcode[i] == 0)
                    {
                        break;
                    }

                    UsedBytes++;
                }

                if (Structure.modrm > 0)
                {
                    UsedBytes++;
                }

                auto DisplacementSize = Instruction->size - UsedBytes;
                auto InstructionAddress = To + Instruction->address - From;

                if (IsConditionalJump(Instruction->bytes, Instruction->size) == true)
                {
                    NumberOfConditionalJumps++;

                    // block_base_address + size_of_the_hook + (size_of_trampoline * total_number_of_conditional_jumps_until_now)
                    auto JumpAddress = m_memoryBlock->GetAddress() + m_size + (16 * NumberOfConditionalJumps);
                    WriteJump(JumpAddress, DisplacementAddress, 16);

                    DisplacementAddress = JumpAddress;
                }

                switch (DisplacementSize)
                {
                    case 1:
                    {
                        *reinterpret_cast<int8_t*>(InstructionAddress + UsedBytes) = CalculateDisplacement<int8_t>(InstructionAddress, DisplacementAddress, UsedBytes + sizeof(int8_t));
                        break;
                    }
                    case 2:
                    {
                        *reinterpret_cast<int16_t*>(InstructionAddress + UsedBytes) = CalculateDisplacement<int16_t>(InstructionAddress, DisplacementAddress, UsedBytes + sizeof(int16_t));
                        break;
                    }
                    case 4:
                    {
                        *reinterpret_cast<int32_t*>(InstructionAddress + UsedBytes) = CalculateDisplacement<int32_t>(InstructionAddress, DisplacementAddress, UsedBytes + sizeof(int32_t));
                        break;
                    }
                    case 8:
                    {
                        *reinterpret_cast<int64_t*>(InstructionAddress + UsedBytes) = CalculateDisplacement<int64_t>(InstructionAddress, DisplacementAddress, UsedBytes + sizeof(int64_t));
                        break;
                    }
                    default:
                    {
                        throw std::runtime_error("Invalid displacement size");
                        break;
                    }
                }
            }
        }
    }
}

const size_t RenHook::Hook::WriteJump(const uintptr_t From, const uintptr_t To, const size_t Size) const
{
    std::vector<uint8_t> Bytes;

    // Should we do a x64 or x86 jump?
    if (Size >= 16)
    {
        /*
        * push rax
        * mov rax, 0xCCCCCCCCCCCCCCCC
        * xchg rax, [rsp]
        * ret
        */
        Bytes = { 0x50, 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x87, 0x04, 0x24, 0xC3 };

        // Set our detour function.
        *reinterpret_cast<uintptr_t*>(Bytes.data() + 3) = To;
    }
    else
    {
        // If the displacement is less than 2048 MB do a near jump or if the hook size is equal with 5, otherwise do a far jump.
        if (std::abs(reinterpret_cast<uintptr_t*>(From) - reinterpret_cast<uintptr_t*>(To)) <= 0x7fff0000 || Size == 5)
        {
            /*
            * jmp 0xCCCCCCCC
            */
            Bytes = { 0xE9, 0xCC, 0xCC, 0xCC, 0xCC };

            // Set our detour function.
            *reinterpret_cast<int32_t*>(Bytes.data() + 1) = CalculateDisplacement<int32_t>(From, To, Bytes.size());
        }
        else
        {
            /*
            * jmp qword ptr ds:[0xCCCCCCCC]
            */
            Bytes = { 0xFF, 0x25, 0xCC, 0xCC, 0xCC, 0xCC };

            // Add the displacement right after our jump back to the original function which is located at "m_memoryBlock->GetAddress() + Size" and has a size of 16 bytes.
            auto Displacement = m_memoryBlock->GetAddress() + Size + 17;

            // Write the address in memory at RIP + Displacement.
            *reinterpret_cast<uintptr_t*>(Displacement) = To;

            // Set our detour function.
            *reinterpret_cast<int32_t*>(Bytes.data() + 2) = CalculateDisplacement<int32_t>(From, Displacement, Bytes.size());
        }
    }

    // Calculate the hook size in bytes.
    auto HookSize = sizeof(uint8_t) * Bytes.size();

    // Override the original bytes.
    std::memcpy(reinterpret_cast<uintptr_t*>(From), Bytes.data(), HookSize);

    return HookSize;
}