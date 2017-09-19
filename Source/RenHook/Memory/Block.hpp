#pragma once

namespace RenHook::Memory
{
    class Block
    {
    public:

        Block(const uintptr_t Address, size_t Size);
        ~Block();

        void CopyFrom(const uintptr_t Address, const size_t Size);

        void CopyTo(const uintptr_t Address, const size_t Size);

        const uintptr_t GetAddress() const;

    private:

        uintptr_t* Alloc(const uintptr_t Address, const size_t Size, const int64_t Delta);

        uintptr_t* m_address;

        size_t m_size;
    };
}