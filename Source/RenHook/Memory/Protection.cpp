#include <RenHook/RenHook.hpp>
#include <RenHook/Memory/Protection.hpp>

RenHook::Memory::Protection::Protection(const uintptr_t Address, const size_t Size)
    : m_address(Address)
    , m_size(Size)
    , m_originalProtection(0)
{
}

RenHook::Memory::Protection::~Protection()
{
    Restore();
}

bool RenHook::Memory::Protection::Change(const uint32_t Protection)
{
    uint32_t OldProtection = 0;
    auto Result = VirtualProtect(reinterpret_cast<void*>(m_address), m_size, Protection, m_originalProtection == 0 ? reinterpret_cast<PDWORD>(&m_originalProtection) : reinterpret_cast<PDWORD>(&OldProtection)) != 0;

    if (Result == false)
    {
        throw std::runtime_error("Cannot change the protection");
    }

    return Result;
}

bool RenHook::Memory::Protection::Restore()
{
    return Change(m_originalProtection);
}
