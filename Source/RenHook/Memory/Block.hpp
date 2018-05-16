#pragma once

namespace RenHook::Memory
{
    class Block
    {
    public:

        Block(const uintptr_t aAddress, size_t aSize);
        ~Block();

        void CopyFrom(const uintptr_t aAddress, const size_t aSize);

        void CopyTo(const uintptr_t aAddress, const size_t aSize);

        const uintptr_t GetAddress() const;

    private:

        uintptr_t* Alloc(const uintptr_t aAddress, const size_t aSize, const int64_t aDelta);

        uintptr_t* m_address;

        size_t m_size;
    };
}