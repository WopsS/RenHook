#pragma once

#include <RenHook/Capstone/Capstone.hpp>
#include <RenHook/Memory/Block.hpp>

namespace RenHook
{
    class Hook
    {
    public:

        Hook(const uintptr_t Address, const uintptr_t Detour);
        ~Hook();

        template<typename T>
        static std::shared_ptr<Hook> Create(const uintptr_t Address, const T Detour, const std::wstring& Key = L"")
        {
            return RenHook::Managers::Hooks::Create(Address, Detour, Key);
        }

        template<typename T>
        static std::shared_ptr<Hook> Create(const std::wstring& Module, const std::wstring& Function, const T Detour, const std::wstring& Key = L"")
        {
            return RenHook::Managers::Hooks::Create(Module, Function, Detour, Key);
        }

        template<typename T>
        static std::shared_ptr<Hook> Create(const std::wstring& Pattern, const T Detour, const std::wstring& Key = L"")
        {
            return RenHook::Managers::Hooks::Create(Pattern, Detour, Key);
        }

        static std::shared_ptr<Hook> Get(const uintptr_t Address);

        static std::shared_ptr<Hook> Get(const std::wstring& Key);

        static std::shared_ptr<Hook> Get(const std::wstring& Module, const std::wstring& Function);

        static void Remove(const uintptr_t Address);

        static void Remove(const std::wstring& Key);

        static void Remove(const std::wstring& Module, const std::wstring& Function);

        template<typename Result, typename CallType, typename... Args>
        Result Call(Args&& ...args)
        {
            return GetOriginal<CallType>()(std::forward<Args>(args)...);
        }

        template<typename T>
        T GetOriginal()
        {
            return reinterpret_cast<T>(m_memoryBlock.GetAddress());
        }

    private:

        template<typename T>
        const T CalculateDisplacement(const uintptr_t From, const uintptr_t To, const size_t Size) const
        {
            if (To < From)
            {
                return static_cast<T>(0 - (From - To) - Size);
            }

            return static_cast<T>(To - (From + Size));
        }

        const size_t CheckSize(const RenHook::Capstone& Capstone, const size_t MinimumSize) const;

        const size_t GetMinimumSize(const uintptr_t Address) const;

        const void RelocateRIP(const uintptr_t From, const uintptr_t To) const;

        const size_t WriteJump(const uintptr_t Address, const uintptr_t Detour, const size_t Size) const;

        uintptr_t m_address;

        size_t m_size;

        RenHook::Memory::Block m_memoryBlock;
    };
}