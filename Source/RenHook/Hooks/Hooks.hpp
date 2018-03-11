#pragma once

#include <RenHook/ExecutableMeta/ExecutableMeta.hpp>
#include <RenHook/Hooks/Hook.hpp>
#include <RenHook/Pattern/Pattern.hpp>

namespace RenHook::Managers::Hooks
{
    namespace Private
    {
        std::shared_ptr<Hook> Create(const uintptr_t Address, const uintptr_t Detour, const std::string& Key);

        extern uintptr_t ImageBase;

        extern std::map<std::string, std::shared_ptr<RenHook::Hook>> Hooks;
    }

    template<typename T>
    std::shared_ptr<Hook> Create(uintptr_t Address, const T Detour, bool IsInIDARange, std::string Key)
    {
        if (Key.empty() == true)
        {
            Key = std::to_string(Address);
        }

        // Check if we already have a hooked function with that key.
        if (Private::Hooks.find(Key) != Private::Hooks.end())
        {
            return Private::Hooks.at(Key);
        }
        
        if (IsInIDARange == true)
        {
            Address = Address - Private::ImageBase + RenHook::ExecutableMeta::GetBaseAddress();
        }

        return Private::Create(Address, reinterpret_cast<uintptr_t>(Detour), Key);
    }

    template<typename T>
    std::shared_ptr<Hook> Create(const std::string& Module, const std::string& Function, const T Detour, std::string Key)
    {
        if (Key.empty() == true)
        {
            Key = Module + "::" + Function;
        }

        // Check if we already have a hooked function with that key.
        if (Private::Hooks.find(Key) != Private::Hooks.end())
        {
            return Private::Hooks.at(Key);
        }

        auto Handle = GetModuleHandleA(Module.c_str());

        // If we don't have the module loaded, try to load it.
        if (Handle == nullptr)
        {
            LoadLibraryA(Module.c_str());

            // Try again to get the module's handle.
            Handle = GetModuleHandleA(Module.c_str());

            // Is it loaded now?
            if (Handle == nullptr)
            {
                throw std::invalid_argument("Module not found");
            }
        }

        auto Address = GetProcAddress(Handle, Function.c_str());

        // Do we have an invalid address?
        if (Address == nullptr)
        {
            throw std::invalid_argument("Function not found in module");
        }

        return Private::Create(reinterpret_cast<uintptr_t>(Address), reinterpret_cast<uintptr_t>(Detour), Key);;
    }

    template<typename T>
    std::shared_ptr<Hook> Create(const std::string& Pattern, const T Detour, std::string Key)
    {
        if (Key.empty() == true)
        {
            Key = Pattern;
        }

        auto pattern = RenHook::Pattern(Pattern);

        // Check if we already have a hooked function with that pattern.
        if (Private::Hooks.find(Key) != Private::Hooks.end())
        {
            return Private::Hooks.at(Key);
        }

        auto Address = pattern.Expect(1).Get(1).To<uintptr_t>();

        if (Address == 0)
        {
            throw std::runtime_error("Pattern not found");
        }

        return Private::Create(Address, reinterpret_cast<uintptr_t>(Detour), Key);;
    }

    std::shared_ptr<Hook> Get(const uintptr_t Address);

    std::shared_ptr<Hook> Get(const std::string& Key);

    std::shared_ptr<Hook> Get(const std::string& Module, const std::string& Function);

    void Remove(const uintptr_t Address);

    void Remove(const std::string& Key);

    void Remove(const std::string& Module, const std::string& Function);

    void RemoveAll();
}