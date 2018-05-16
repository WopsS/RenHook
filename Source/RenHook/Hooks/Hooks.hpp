#pragma once

#include <RenHook/ExecutableMeta/ExecutableMeta.hpp>
#include <RenHook/Hooks/Hook.hpp>
#include <RenHook/Pattern/Pattern.hpp>

namespace RenHook::Managers::Hooks
{
    namespace Private
    {
        std::shared_ptr<Hook> Create(uintptr_t aAddress, uintptr_t aDetour, const std::string& aKey);

        extern uintptr_t ImageBase;

        extern std::map<std::string, std::shared_ptr<RenHook::Hook>> Hooks;
    }

    template<typename T>
    std::shared_ptr<Hook> Create(uintptr_t aAddress, T aDetour, bool aIsInIDARange, std::string aKey)
    {
        if (aKey.empty())
        {
            aKey = std::to_string(aAddress);
        }

        // Check if we already have a hooked function with that key.
        if (Private::Hooks.find(aKey) != Private::Hooks.end())
        {
            return Private::Hooks.at(aKey);
        }
        
        if (aIsInIDARange)
        {
            aAddress = aAddress - Private::ImageBase + RenHook::ExecutableMeta::GetBaseAddress();
        }

        return Private::Create(aAddress, reinterpret_cast<uintptr_t>(aDetour), aKey);
    }

    template<typename T>
    std::shared_ptr<Hook> Create(const std::string& aModule, const std::string& aFunction, T aDetour, std::string aKey)
    {
        if (aKey.empty())
        {
            aKey = aModule + "::" + aFunction;
        }

        // Check if we already have a hooked function with that key.
        if (Private::Hooks.find(aKey) != Private::Hooks.end())
        {
            return Private::Hooks.at(aKey);
        }

        auto handle = GetModuleHandleA(aModule.c_str());

        // If we don't have the module loaded, try to load it.
        if (!handle)
        {
            LoadLibraryA(aModule.c_str());

            // Try again to get the module's handle.
            handle = GetModuleHandleA(aModule.c_str());

            // Is it loaded now?
            if (!handle)
            {
                throw std::invalid_argument("Module not found");
            }
        }

        auto address = GetProcAddress(handle, aFunction.c_str());

        // Do we have an invalid address?
        if (!address)
        {
            throw std::invalid_argument("Function not found in module");
        }

        return Private::Create(reinterpret_cast<uintptr_t>(address), reinterpret_cast<uintptr_t>(aDetour), aKey);
    }

    template<typename T>
    std::shared_ptr<Hook> Create(const std::string& aPattern, T aDetour, std::string aKey)
    {
        if (aKey.empty())
        {
            aKey = aPattern;
        }

        auto pattern = RenHook::Pattern(aPattern);

        // Check if we already have a hooked function with that pattern.
        if (Private::Hooks.find(aKey) != Private::Hooks.end())
        {
            return Private::Hooks.at(aKey);
        }

        auto address = pattern.Expect(1).Get(1).To<uintptr_t>();

        if (address == 0)
        {
            throw std::runtime_error("Pattern not found");
        }

        return Private::Create(address, reinterpret_cast<uintptr_t>(aDetour), aKey);
    }

    std::shared_ptr<Hook> Get(uintptr_t aAddress);

    std::shared_ptr<Hook> Get(const std::string& aKey);

    std::shared_ptr<Hook> Get(const std::string& aModule, const std::string& aFunction);

    void Remove(uintptr_t aAddress);

    void Remove(const std::string& aKey);

    void Remove(const std::string& aModule, const std::string& aFunction);

    void RemoveAll();
}