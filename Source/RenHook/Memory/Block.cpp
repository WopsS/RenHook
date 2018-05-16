#include <RenHook/RenHook.hpp>
#include <RenHook/Memory/Block.hpp>

RenHook::Memory::Block::Block(const uintptr_t aAddress, size_t aSize)
    : m_address(nullptr)
    , m_size(aSize)
{
    // Add space to jump back to the original code.
    aSize += 16 + sizeof(uintptr_t);

    // Check 1024 MB up.
    m_address = Alloc(aAddress, aSize, 0xFFFFFFFFC0000000);

    // If it cannot allocate a memory up try to allocate it down.
    if (m_address == nullptr)
    {
        m_address = Alloc(aAddress, aSize, 0x40000000);
    }
}

RenHook::Memory::Block::~Block()
{
    if (m_address != nullptr)
    {
        VirtualFree(m_address, 0, MEM_RELEASE);
    }
}

void RenHook::Memory::Block::CopyFrom(const uintptr_t aAddress, const size_t aSize)
{
    if (aSize > m_size)
    {
        throw std::length_error("Invalid size");
    }

    std::memcpy(m_address, reinterpret_cast<uintptr_t*>(aAddress), aSize);
}

void RenHook::Memory::Block::CopyTo(const uintptr_t aAddress, const size_t aSize)
{
    if (aSize > m_size)
    {
        throw std::length_error("Invalid size");
    }

    std::memcpy(reinterpret_cast<uintptr_t*>(aAddress), m_address, aSize);
}

const uintptr_t RenHook::Memory::Block::GetAddress() const
{
    return reinterpret_cast<uintptr_t>(m_address);
}

uintptr_t* RenHook::Memory::Block::Alloc(const uintptr_t aAddress, const size_t aSize, const int64_t aDelta)
{
    MEMORY_BASIC_INFORMATION memoryInformation;
    uintptr_t maximumAddress = aAddress + aDelta;

    auto getNextRegion = [&memoryInformation](const int64_t aDelta)
    {
        if (aDelta > 0)
        {
            return reinterpret_cast<uintptr_t>(memoryInformation.BaseAddress) + memoryInformation.RegionSize + 1;
        }

        return reinterpret_cast<uintptr_t>(memoryInformation.BaseAddress) - 1;
    };

    auto isValidAddress = [](const uintptr_t aStartAddress, const uintptr_t aEndAddress, const int64_t aDelta)
    {
        if (aDelta > 0)
        {
            return aStartAddress < aEndAddress;
        }

        return aStartAddress > aEndAddress;
    };

    for (uintptr_t i = aAddress; isValidAddress(i, maximumAddress, aDelta) == true; i = getNextRegion(aDelta))
    {
        if (VirtualQuery(reinterpret_cast<LPCVOID>(i), &memoryInformation, sizeof(memoryInformation)) == 0)
        {
            break;
        }

        if (memoryInformation.State != MEM_FREE)
        {
            continue;
        }

        auto result = reinterpret_cast<uintptr_t*>(VirtualAlloc(memoryInformation.BaseAddress, aSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (result != nullptr)
        {
            return result;
        }
    }

    return nullptr;
}
