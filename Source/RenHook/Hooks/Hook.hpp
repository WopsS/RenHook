#pragma once

#include <RenHook/Capstone/Capstone.hpp>
#include <RenHook/Memory/Block.hpp>

namespace RenHook
{
    class Hook
    {
    public:

        Hook(uintptr_t aAddress, uintptr_t aDetour);
        ~Hook();

        template<typename T>
        static std::shared_ptr<Hook> Create(uintptr_t aAddress, T aDetour, bool aIsInIDARange = false, const std::string& aKey = "")
        {
            return RenHook::Managers::Hooks::Create(aAddress, aDetour, aIsInIDARange, aKey);
        }

        template<typename T>
        static std::shared_ptr<Hook> Create(const std::string& aModule, const std::string& aFunction, T aDetour, const std::string& aKey = "")
        {
            return RenHook::Managers::Hooks::Create(aModule, aFunction, aDetour, aKey);
        }

        template<typename T>
        static std::shared_ptr<Hook> Create(std::string aPattern, T aDetour, const std::string& aKey = L"")
        {
            return RenHook::Managers::Hooks::Create(aPattern, aDetour, aKey);
        }

        static std::shared_ptr<Hook> Get(uintptr_t aAddress);

        static std::shared_ptr<Hook> Get(const std::string& aKey);

        static std::shared_ptr<Hook> Get(const std::string& aModule, const std::string& aFunction);

        static void Remove(uintptr_t aAddress);

        static void Remove(const std::string& aKey);

        static void Remove(const std::string& aModule, const std::string& aFunction);

        static void RemoveAll();

        static void SetImageBase(uintptr_t aValue);

        template<typename T, typename... Args>
        auto Call(Args&& ...aArgs)
        {
            return GetOriginal<T>()(std::forward<Args>(aArgs)...);
        }

        template<typename T>
        T GetOriginal()
        {
            return reinterpret_cast<T>(m_memoryBlock->GetAddress());
        }

        const bool IsValid() const;

    private:

        template<typename T>
        const T CalculateDisplacement(uintptr_t aFrom, uintptr_t aTo, size_t aSize) const
        {
            if (aTo < aFrom)
            {
                return static_cast<T>(0 - (aFrom - aTo) - aSize);
            }

            return static_cast<T>(aTo - (aFrom + aSize));
        }

        size_t CheckSize(const RenHook::Capstone& aCapstone, size_t aMinimumSize) const;

        size_t CountConditionalJumps(uintptr_t aAddress) const;

        size_t GetMinimumSize(uintptr_t aAddress) const;

        bool IsConditionalJump(const uint8_t* aBytes, size_t aSize) const;

        void RelocateRIP(uintptr_t aFrom, uintptr_t aTo) const;

        size_t WriteJump(uintptr_t aFrom, uintptr_t aTo, size_t aSize) const;

        uintptr_t m_address;

        size_t m_size;

        std::unique_ptr<RenHook::Memory::Block> m_memoryBlock;
    };
}