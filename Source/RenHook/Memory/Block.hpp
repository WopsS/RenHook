#pragma once

namespace RenHook::Memory
{
    class Block
    {
    public:

        Block(uintptr_t aAddress, size_t aSize);
        ~Block();

        void CopyFrom(uintptr_t aAddress, size_t aSize);

        void CopyTo(uintptr_t aAddress, size_t aSize);

        uintptr_t GetAddress() const;

    private:

        uintptr_t* Alloc(uintptr_t aAddress, size_t aSize, int64_t aDelta);

        uintptr_t* m_address;

        size_t m_size;
    };
}