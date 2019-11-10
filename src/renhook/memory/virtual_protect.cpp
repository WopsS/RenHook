#include <renhook/exception.hpp>
#include <renhook/memory/virtual_protect.hpp>

#include <Windows.h>

renhook::memory::virtual_protect::virtual_protect(void* address, size_t size, protection new_protection, bool permanent)
    : m_address(address)
    , m_size(size)
    , m_is_permanent(permanent)
{
    uint32_t protection_option = 0;

    if ((new_protection & protection::read) && (new_protection & protection::write) && (new_protection & protection::execute))
    {
        protection_option = PAGE_EXECUTE_READWRITE;
    }
    else if ((new_protection & protection::read) && (new_protection & protection::write) || new_protection == protection::write)
    {
        protection_option = PAGE_READWRITE;
    }
    else if ((new_protection & protection::read) && (new_protection & protection::execute))
    {
        protection_option = PAGE_EXECUTE_READ;
    }
    else if (new_protection == protection::read)
    {
        protection_option = PAGE_READONLY;
    }
    else if (new_protection == protection::execute)
    {
        protection_option = PAGE_EXECUTE;
    }

    if (!VirtualProtect(address, size, protection_option, reinterpret_cast<PDWORD>(&m_old_protection)))
    {
        throw renhook::exception("couldn't change protection", GetLastError());
    }
}

renhook::memory::virtual_protect::virtual_protect(uintptr_t address, size_t size, protection new_protection, bool permanent)
    : virtual_protect(reinterpret_cast<void*>(address), size, new_protection, permanent)
{
}

renhook::memory::virtual_protect::~virtual_protect() noexcept
{
    if (!m_is_permanent)
    {
        decltype(m_old_protection) old_protection;
        VirtualProtect(m_address, m_size, m_old_protection, reinterpret_cast<PDWORD>(&old_protection));
    }
}
