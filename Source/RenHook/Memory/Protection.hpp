#pragma once

namespace RenHook::Memory
{
    class Protection
    {
    public:

        Protection(uintptr_t aAddress, size_t aSize);
        ~Protection();

        bool Change(uint32_t aProtection);

        bool Restore();

    private:

        uintptr_t m_address;

        size_t m_size;

        uint32_t m_originalProtection;

    };
}