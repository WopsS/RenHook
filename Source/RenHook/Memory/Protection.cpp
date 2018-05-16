#include <RenHook/RenHook.hpp>
#include <RenHook/Memory/Protection.hpp>

RenHook::Memory::Protection::Protection(const uintptr_t aAddress, const size_t aSize)
    : m_address(aAddress)
    , m_size(aSize)
    , m_originalProtection(0)
{
}

RenHook::Memory::Protection::~Protection()
{
    Restore();
}

bool RenHook::Memory::Protection::Change(const uint32_t aProtection)
{
    uint32_t oldProtection = 0;
    auto result = VirtualProtect(reinterpret_cast<void*>(m_address), m_size, aProtection, m_originalProtection == 0 ? reinterpret_cast<PDWORD>(&m_originalProtection) : reinterpret_cast<PDWORD>(&oldProtection)) != 0;

    if (result == false)
    {
        throw std::runtime_error("Cannot change the protection");
    }

    return result;
}

bool RenHook::Memory::Protection::Restore()
{
    return Change(m_originalProtection);
}
