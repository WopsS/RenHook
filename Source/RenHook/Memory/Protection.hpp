#pragma once

namespace RenHook::Memory
{
    class Protection
    {
    public:

        Protection(const uintptr_t Address, const size_t Size);
        ~Protection();

        bool Change(const uint32_t Protection);

        bool Restore();

    private:

        uintptr_t m_address;

        size_t m_size;

        uint32_t m_originalProtection;

    };
}