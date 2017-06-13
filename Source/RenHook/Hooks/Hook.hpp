#pragma once

namespace RenHook
{
    class Hook
    {
    public:

        Hook(const uintptr_t Address, const uintptr_t Detour, const size_t Size);
        ~Hook();

        template<typename T>
        static std::shared_ptr<Hook> Create(const uintptr_t Address, const T Detour, const size_t Size, const std::wstring& Key = L"")
        {
            return RenHook::Managers::Hooks::Create(Address, Detour, Size, Key);
        }

        template<typename T>
        static std::shared_ptr<Hook> Create(const std::wstring& Module, const std::wstring& Function, const T Detour, const size_t Size, const std::wstring& Key = L"")
        {
            return RenHook::Managers::Hooks::Create(Module, Function, Detour, Size, Key);
        }

        template<typename T>
        static std::shared_ptr<Hook> Create(const std::wstring& Pattern, const T Detour, const size_t Size, const std::wstring& Key = L"")
        {
            return RenHook::Managers::Hooks::Create(Pattern, Detour, Size, Key);
        }

    private:

    };
}