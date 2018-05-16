#include <RenHook/RenHook.hpp>
#include <RenHook/Hooks/Hook.hpp>
#include <RenHook/Memory/Protection.hpp>
#include <RenHook/Threads/Threads.hpp>

RenHook::Hook::Hook(const uintptr_t aAddress, const uintptr_t aDetour)
    : m_address(aAddress)
    , m_size(GetMinimumSize(aAddress))
    , m_memoryBlock(nullptr)
{
    if (m_size >= 5)
    {
        // Create our memory block with hook size + necessary size for conditional jumps.
        m_memoryBlock = std::make_unique<RenHook::Memory::Block>(aAddress, m_size + (CountConditionalJumps(aAddress) * 16));

        RenHook::Managers::Threads threads;
        threads.Suspend();

        // Backup the original bytes.
        m_memoryBlock->CopyFrom(aAddress, m_size);

        Memory::Protection protection(aAddress, m_size);
        protection.Change(PAGE_EXECUTE_READWRITE);

        // Relocate RIP addresses with our address.
        RelocateRIP(aAddress, m_memoryBlock->GetAddress());

        auto hookSize = WriteJump(aAddress, aDetour, m_size);

        // Jump back to the original code (16 bytes).
        WriteJump(m_memoryBlock->GetAddress() + m_size, aAddress + m_size, 16);

        // Set unused bytes as NOP.
        if (hookSize < m_size)
        {
            std::memset(reinterpret_cast<uintptr_t*>(aAddress + hookSize), 0x90, m_size - hookSize);
        }

        protection.Restore();
        threads.Resume();
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
        RenHook::Managers::Threads threads;
        threads.Suspend();

        Memory::Protection protection(m_address, m_size);
        protection.Change(PAGE_EXECUTE_READWRITE);

        // Restore the original bytes.
        m_memoryBlock->CopyTo(m_address, m_size);

        // Relocate RIP addresses back to their original value.
        RelocateRIP(m_memoryBlock->GetAddress(), m_address);

        protection.Restore();
        threads.Resume();
    }
}

std::shared_ptr<RenHook::Hook> RenHook::Hook::Get(const uintptr_t aAddress)
{
    return RenHook::Managers::Hooks::Get(aAddress);
}

std::shared_ptr<RenHook::Hook> RenHook::Hook::Get(const std::string& aKey)
{
    return RenHook::Managers::Hooks::Get(aKey);
}

std::shared_ptr<RenHook::Hook> RenHook::Hook::Get(const std::string& aModule, const std::string& aFunction)
{
    return RenHook::Managers::Hooks::Get(aModule, aFunction);
}

void RenHook::Hook::Remove(const uintptr_t aAddress)
{
    return RenHook::Managers::Hooks::Remove(aAddress);
}

void RenHook::Hook::Remove(const std::string& aKey)
{
    return RenHook::Managers::Hooks::Remove(aKey);
}

void RenHook::Hook::Remove(const std::string& aModule, const std::string& aFunction)
{
    return RenHook::Managers::Hooks::Remove(aModule, aFunction);
}

void RenHook::Hook::RemoveAll()
{
    RenHook::Managers::Hooks::RemoveAll();
}

void RenHook::Hook::SetImageBase(const uintptr_t aValue)
{
    RenHook::Managers::Hooks::Private::ImageBase = aValue;
}

const bool RenHook::Hook::IsValid() const
{
    return m_size >= 5 && m_memoryBlock != nullptr && m_memoryBlock->GetAddress() > 0;
}

const size_t RenHook::Hook::CheckSize(const RenHook::Capstone& aCapstone, const size_t aMinimumSize) const
{
    size_t size = 0;

    for (size_t i = 0; i < aCapstone.GetTotalNumberOfInstructions(); i++)
    {
        size += aCapstone.GetInstructionSize(i);

        if (size >= aMinimumSize)
        {
            return size;
        }
    }

    return 0;
}

const size_t RenHook::Hook::CountConditionalJumps(const uintptr_t aAddress) const
{
    size_t result = 0;

    RenHook::Capstone capstone;
    capstone.Disassemble(aAddress, m_size);

    for (size_t i = 0; i < capstone.GetTotalNumberOfInstructions(); i++)
    {
        auto instruction = capstone.GetInstructionAt(i);
        auto& structure = instruction->detail->x86;

        // Check all operands.
        for (size_t j = 0; j < structure.op_count; j++)
        {
            auto& operand = structure.operands[j];

            if (operand.type == X86_OP_IMM && IsConditionalJump(instruction->bytes, instruction->size) == true)
            {
                result++;
            }
        }
    }

    return result;
}

const size_t RenHook::Hook::GetMinimumSize(const uintptr_t aAddress) const
{
    size_t size = 0;

    RenHook::Capstone capstone;
    capstone.Disassemble(aAddress, 128);

    // Check if we can do a 16 byte jump.
    size = CheckSize(capstone, 16);

    // Check if we can do a 6 byte jump if we can't do a 16 byte jump.
    if (size == 0)
    {
        size = CheckSize(capstone, 6);

        // Check if we can do a 5 byte jump if we can't do a 6 byte jump.
        if (size == 0)
        {
            size = CheckSize(capstone, 5);
        }
    }

    return size;
}

const bool RenHook::Hook::IsConditionalJump(const uint8_t* aBytes, const size_t aSize) const
{
    if (aSize > 0)
    {
        // See https://software.intel.com/sites/default/files/managed/a4/60/325383-sdm-vol-2abcd.pdf (Jcc - Jump if Condition Is Met).

        if (aBytes[0] == 0xE3)
        {
            return true;
        }
        else if (aBytes[0] >= 0x70 && aBytes[0] <= 0x7F)
        {
            return true;
        }
        else if ((aBytes[0] == 0x0F && aSize > 1) && (aBytes[1] >= 0x80 && aBytes[1] <= 0x8F))
        {
            return true;
        }
    }


    return false;
}

const void RenHook::Hook::RelocateRIP(const uintptr_t aFrom, const uintptr_t aTo) const
{
    RenHook::Capstone capstone;

    auto instructions = capstone.Disassemble(aFrom, m_size);
    size_t conditionalJumps = 0;

    for (size_t i = 0; i < instructions; i++)
    {
        auto instruction = capstone.GetInstructionAt(i);
        auto& structure = instruction->detail->x86;

        // Check all operands.
        for (size_t j = 0; j < structure.op_count; j++)
        {
            auto& operand = structure.operands[j];

            uintptr_t displacementAddress = 0;

            if (operand.type == X86_OP_MEM && operand.mem.base == X86_REG_RIP)
            {
                // Calculate the displacement address.
                displacementAddress = instruction->address + instruction->size + structure.disp;
            }
            else if (operand.type == X86_OP_IMM)
            {
                // Skip instructions like "sub something, something".
                if (structure.op_count > 1)
                {
                    continue;
                }

                // Calculate the displacement address.
                displacementAddress = structure.operands[0].imm;
            }

            if (displacementAddress > 0)
            {
                size_t usedBytes = 0;

                if (structure.rex > 0)
                {
                    usedBytes++;
                }

                for (int i = 0; i < sizeof(structure.opcode); i++)
                {
                    if (structure.opcode[i] == 0)
                    {
                        break;
                    }

                    usedBytes++;
                }

                if (structure.modrm > 0)
                {
                    usedBytes++;
                }

                auto displacementSize = instruction->size - usedBytes;
                auto instructionAddress = aTo + instruction->address - aFrom;

                if (IsConditionalJump(instruction->bytes, instruction->size) == true)
                {
                    conditionalJumps++;

                    // block_base_address + size_of_the_hook + (size_of_trampoline * total_number_of_conditional_jumps_until_now)
                    auto jumpAddress = m_memoryBlock->GetAddress() + m_size + (16 * conditionalJumps);
                    WriteJump(jumpAddress, displacementAddress, 16);

                    displacementAddress = jumpAddress;
                }

                switch (displacementSize)
                {
                    case 1:
                    {
                        *reinterpret_cast<int8_t*>(instructionAddress + usedBytes) = CalculateDisplacement<int8_t>(instructionAddress, displacementAddress, usedBytes + sizeof(int8_t));
                        break;
                    }
                    case 2:
                    {
                        *reinterpret_cast<int16_t*>(instructionAddress + usedBytes) = CalculateDisplacement<int16_t>(instructionAddress, displacementAddress, usedBytes + sizeof(int16_t));
                        break;
                    }
                    case 4:
                    {
                        *reinterpret_cast<int32_t*>(instructionAddress + usedBytes) = CalculateDisplacement<int32_t>(instructionAddress, displacementAddress, usedBytes + sizeof(int32_t));
                        break;
                    }
                    case 8:
                    {
                        *reinterpret_cast<int64_t*>(instructionAddress + usedBytes) = CalculateDisplacement<int64_t>(instructionAddress, displacementAddress, usedBytes + sizeof(int64_t));
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

const size_t RenHook::Hook::WriteJump(const uintptr_t aFrom, const uintptr_t aTo, const size_t aSize) const
{
    std::vector<uint8_t> bytes;

    // Should we do a x64 or x86 jump?
    if (aSize >= 16)
    {
        /*
        * push rax
        * mov rax, 0xCCCCCCCCCCCCCCCC
        * xchg rax, [rsp]
        * ret
        */
        bytes = { 0x50, 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x87, 0x04, 0x24, 0xC3 };

        // Set our detour function.
        *reinterpret_cast<uintptr_t*>(bytes.data() + 3) = aTo;
    }
    else
    {
        // If the displacement is less than 2048 MB do a near jump or if the hook size is equal with 5, otherwise do a far jump.
        if (std::abs(reinterpret_cast<uintptr_t*>(aFrom) - reinterpret_cast<uintptr_t*>(aTo)) <= 0x7fff0000 || aSize == 5)
        {
            /*
            * jmp 0xCCCCCCCC
            */
            bytes = { 0xE9, 0xCC, 0xCC, 0xCC, 0xCC };

            // Set our detour function.
            *reinterpret_cast<int32_t*>(bytes.data() + 1) = CalculateDisplacement<int32_t>(aFrom, aTo, bytes.size());
        }
        else
        {
            /*
            * jmp qword ptr ds:[0xCCCCCCCC]
            */
            bytes = { 0xFF, 0x25, 0xCC, 0xCC, 0xCC, 0xCC };

            // Add the displacement right after our jump back to the original function which is located at "m_memoryBlock->GetAddress() + Size" and has a size of 16 bytes.
            auto displacement = m_memoryBlock->GetAddress() + aSize + 17;

            // Write the address in memory at RIP + Displacement.
            *reinterpret_cast<uintptr_t*>(displacement) = aTo;

            // Set our detour function.
            *reinterpret_cast<int32_t*>(bytes.data() + 2) = CalculateDisplacement<int32_t>(aFrom, displacement, bytes.size());
        }
    }

    // Calculate the hook size in bytes.
    auto hookSize = sizeof(uint8_t) * bytes.size();

    // Override the original bytes.
    std::memcpy(reinterpret_cast<uintptr_t*>(aFrom), bytes.data(), hookSize);

    return hookSize;
}