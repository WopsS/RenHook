#include <RenHook/RenHook.hpp>
#include <RenHook/Hooks/Hook.hpp>
#include <RenHook/Memory/Protection.hpp>
#include <RenHook/Threads/Threads.hpp>

RenHook::Hook::Hook(const uintptr_t Address, const uintptr_t Detour)
    : m_address(Address)
    , m_size(GetMinimumSize(Address))
    , m_memoryBlock(Address, m_size)
{
    RenHook::Managers::Threads Threads;
    Threads.Suspend();

    // Backup the original bytes.
    m_memoryBlock.CopyFrom(Address, m_size);

    Memory::Protection Protection(Address, m_size);
    Protection.Change(PAGE_EXECUTE_READWRITE);

    RelocateRIP();

    auto HookSize = WriteJump(Address, Detour, m_size);

    // Jump back to the original code (16 bytes).
    WriteJump(m_memoryBlock.GetAddress() + m_size, Address + m_size, 16);

    // Set unused bytes as NOP.
    if (HookSize < m_size)
    {
        std::memset(reinterpret_cast<uintptr_t*>(Address + HookSize), 0x90, m_size - HookSize);
    }

    Protection.Restore();
    Threads.Resume();
}

RenHook::Hook::~Hook()
{
    RenHook::Managers::Threads Threads;
    Threads.Suspend();

    Memory::Protection Protection(m_address, m_size);
    Protection.Change(PAGE_EXECUTE_READWRITE);

    // Restore the original bytes.
    m_memoryBlock.CopyTo(m_address, m_size);

    Protection.Restore();
    Threads.Resume();
}

std::shared_ptr<RenHook::Hook> RenHook::Hook::Get(const uintptr_t Address)
{
    return RenHook::Managers::Hooks::Get(Address);
}

std::shared_ptr<RenHook::Hook> RenHook::Hook::Get(const std::wstring& Key)
{
    return RenHook::Managers::Hooks::Get(Key);
}

std::shared_ptr<RenHook::Hook> RenHook::Hook::Get(const std::wstring& Module, const std::wstring& Function)
{
    return RenHook::Managers::Hooks::Get(Module, Function);
}

void RenHook::Hook::Remove(const uintptr_t Address)
{
    return RenHook::Managers::Hooks::Remove(Address);
}

void RenHook::Hook::Remove(const std::wstring& Key)
{
    return RenHook::Managers::Hooks::Remove(Key);
}

void RenHook::Hook::Remove(const std::wstring& Module, const std::wstring& Function)
{
    return RenHook::Managers::Hooks::Remove(Module, Function);
}

const size_t RenHook::Hook::CheckSize(const RenHook::Capstone& Capstone, const size_t MinimumSize) const
{
    size_t Size = 0;

    for (size_t i = 0; i < Capstone.GetTotalNumberOfInstruction(); i++)
    {
        Size += Capstone.GetInstructionSize(i);

        if (Size >= MinimumSize)
        {
            return Size;
        }
    }

    return 0;
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

const void RenHook::Hook::RelocateRIP() const
{
    RenHook::Capstone Capstone;
    auto Instructions = Capstone.Disassemble(m_address, m_size);

    for (size_t i = 0; i < Instructions; i++)
    {
        auto Instruction = Capstone.GetInstructionAt(i);
        auto Structure = Instruction->detail->x86;

        auto Mnemonic = std::string(Instruction->mnemonic);

        if (Mnemonic == "int3" || Structure.op_count > 1)
        {
            continue;
        }
        else if (Mnemonic != "jmp")
        {
            LOG_ERROR << L"Instruction has an unhandled mnemonic ("<< Instruction->mnemonic << L") at address " << std::hex << std::showbase << Instruction->address << LOG_LINE_SEPARATOR;
            continue;
        }

        // Check all operands.
        for (size_t j = 0; j < Structure.op_count; j++)
        {
            auto Operand = Structure.operands[j];
            auto InstructionAddress = reinterpret_cast<uint8_t*>(m_memoryBlock.GetAddress() + Instruction->address - m_address);

            uintptr_t DisplacementAddress = 0;

            // This is a hacky way to relocate RIP because Capstone doesn't let us access "displacementOffset" from "InternalInstruction" struct and I don't want to check the bytes.
            if (Operand.type == X86_OP_MEM && Operand.mem.base == X86_REG_RIP)
            {
                // Calculate the displacement address.
                DisplacementAddress = Instruction->address + Instruction->size + Structure.disp;

                // Set all instruction bytes to NOP.
                std::memset(InstructionAddress, 0x90, Instruction->size);
            }
            else if (Operand.type == X86_OP_IMM)
            {
                // Calculate the displacement address.
                DisplacementAddress = Structure.operands[0].imm;

                // Set all instruction bytes to NOP.
                std::memset(InstructionAddress, 0x90, Instruction->size);
            }

            if (DisplacementAddress > 0)
            {
                // Write the new instruction.
                if (Instruction->size >= 6)
                {
                    *reinterpret_cast<uint8_t*>(InstructionAddress) = 0xFF;
                    *reinterpret_cast<uint8_t*>(InstructionAddress + 1) = 0x25;
                    *reinterpret_cast<int32_t*>(InstructionAddress + 2) = CalculateDisplacement<int32_t>(reinterpret_cast<uintptr_t>(InstructionAddress), DisplacementAddress, 6);
                }
                else
                {
                    *reinterpret_cast<uint8_t*>(InstructionAddress) = 0xE9;
                    *reinterpret_cast<int32_t*>(InstructionAddress + 1) = CalculateDisplacement<int32_t>(reinterpret_cast<uintptr_t>(InstructionAddress), DisplacementAddress, 5);
                }
            }
        }
    }
}

const size_t RenHook::Hook::WriteJump(const uintptr_t Address, const uintptr_t Detour, const size_t Size) const
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
        *reinterpret_cast<uintptr_t*>(Bytes.data() + 3) = Detour;
    }
    else
    {
        // If the displacement is less than 2048 MB do a near jump or if the hook size is equal with 5, otherwise do a far jump.
        if (std::abs(reinterpret_cast<uintptr_t*>(Address) - reinterpret_cast<uintptr_t*>(Detour)) <= 0x7fff0000 || Size == 5)
        {
            /*
            * jmp 0xCCCCCCCC
            */
            Bytes = { 0xE9, 0xCC, 0xCC, 0xCC, 0xCC };

            // Set our detour function.
            *reinterpret_cast<int32_t*>(Bytes.data() + 1) = CalculateDisplacement<int32_t>(Address, Detour, Bytes.size());
        }
        else
        {
            /*
            * jmp qword ptr ds:[0xCCCCCCCC]
            */
            Bytes = { 0xFF, 0x25, 0xCC, 0xCC, 0xCC, 0xCC };

            // Add the displacement right after our jump back to the original function which is located at "m_memoryBlock.GetAddress() + Size" and has a size of 16 bytes.
            auto Displacement = m_memoryBlock.GetAddress() + Size + 17;

            // Write the address in memory at RIP + Displacement.
            *reinterpret_cast<uintptr_t*>(Displacement) = Detour;

            // Set our detour function.
            *reinterpret_cast<int32_t*>(Bytes.data() + 2) = CalculateDisplacement<int32_t>(Address, Displacement, Bytes.size());
        }
    }

    // Calculate the hook size in bytes.
    auto HookSize = sizeof(uint8_t) * Bytes.size();

    // Override the original bytes.
    std::memcpy(reinterpret_cast<uintptr_t*>(Address), Bytes.data(), HookSize);

    return HookSize;
}