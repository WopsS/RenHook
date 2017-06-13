#include <RenHook/RenHook.hpp>
#include <RenHook/Memory/Block.hpp>

RenHook::Memory::Block::Block(const uintptr_t Address, size_t Size)
    : m_size(Size)
{
    // Add space to jump back to the original code.
    Size += 16 + sizeof(uintptr_t);

    // Check 1024 MB up.
    m_address = Alloc(Address, Size, 0xFFFFFFFFC0000000);

    // If it cannot allocate a memory up try to allocate it down.
    if (m_address == nullptr)
    {
        m_address = Alloc(Address, Size, 0x40000000);
    }

#ifdef _DEBUG
    LOG_DEBUG << L"Memory block created at " << std::hex << std::showbase << reinterpret_cast<uintptr_t>(m_address) << L", size " << std::dec << Size << L" bytes" << LOG_LINE_SEPARATOR;
#endif
}

RenHook::Memory::Block::~Block()
{
    if (m_address != nullptr)
    {
        VirtualFree(m_address, 0, MEM_RELEASE);
    }
}

void RenHook::Memory::Block::CopyFrom(const uintptr_t Address, const size_t Size)
{
    if (Size > m_size)
    {
        LOG_ERROR << L"Cannot copy memory from " << std::hex << std::showbase << Address << L" because size (" << std::dec << Size << L") is greater than block's size (" << m_size << L")" << LOG_LINE_SEPARATOR;
        return;
    }

    std::memcpy(reinterpret_cast<uintptr_t*>(m_address), reinterpret_cast<uintptr_t*>(Address), Size);
}

void RenHook::Memory::Block::CopyTo(const uintptr_t Address, const size_t Size)
{
    if (Size > m_size)
    {
        LOG_ERROR << L"Cannot copy memory to " << std::hex << std::showbase << Address << L" because size (" << std::dec << Size << L") is greater than block's size (" << m_size << L")" << LOG_LINE_SEPARATOR;
        return;
    }

    std::memcpy(reinterpret_cast<uintptr_t*>(Address), reinterpret_cast<uintptr_t*>(m_address), Size);
}

const uintptr_t RenHook::Memory::Block::GetAddress() const
{
    return reinterpret_cast<uintptr_t>(m_address);
}

uintptr_t* RenHook::Memory::Block::Alloc(const uintptr_t Address, const size_t Size, const int64_t Delta)
{
    MEMORY_BASIC_INFORMATION MemoryInformation;
    uintptr_t MaximumAddress = Address + Delta;

    auto GetNextRegion = [&MemoryInformation](const int64_t Delta)
    {
        if (Delta > 0)
        {
            return reinterpret_cast<uintptr_t>(MemoryInformation.BaseAddress) + MemoryInformation.RegionSize + 1;
        }

        return reinterpret_cast<uintptr_t>(MemoryInformation.BaseAddress) - 1;
    };

    auto IsValidAddress = [](const uintptr_t StartAddress, const uintptr_t EndAddress, const int64_t Delta)
    {
        if (Delta > 0)
        {
            return StartAddress < EndAddress;
        }

        return StartAddress > EndAddress;
    };

    for (uintptr_t i = Address; IsValidAddress(i, MaximumAddress, Delta) == true; i = GetNextRegion(Delta))
    {
        if (VirtualQuery(reinterpret_cast<LPCVOID>(i), &MemoryInformation, sizeof(MemoryInformation)) == 0)
        {
            break;
        }

        if (MemoryInformation.State != MEM_FREE)
        {
            continue;
        }

        auto Result = reinterpret_cast<uintptr_t*>(VirtualAlloc(MemoryInformation.BaseAddress, Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

        if (Result != nullptr)
        {
            return Result;
        }
    }

    return nullptr;
}
