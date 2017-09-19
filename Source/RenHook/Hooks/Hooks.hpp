#pragma once

#include <RenHook/ExecutableMeta/ExecutableMeta.hpp>
#include <RenHook/Hooks/Hook.hpp>
#include <RenHook/Pattern/Pattern.hpp>

namespace RenHook::Managers::Hooks
{
    namespace Private
    {
        std::shared_ptr<Hook> Create(const uintptr_t Address, const uintptr_t Detour, const std::wstring& Key);

        extern uintptr_t ImageBase;

        extern std::map<std::wstring, std::shared_ptr<RenHook::Hook>> Hooks;
    }

    template<typename T>
    std::shared_ptr<Hook> Create(uintptr_t Address, const T Detour, bool IsInIDARange, std::wstring Key)
    {
        if (Key.empty() == true)
        {
            Key = std::to_wstring(Address);
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

        auto Result = Private::Create(Address, reinterpret_cast<uintptr_t>(Detour), Key);

#ifdef _DEBUG
        if (Result->IsValid() == true)
        {
            LOG_DEBUG << L"Function at " << std::hex << std::showbase << Address << L" was successfully hooked" << LOG_LINE_SEPARATOR;
        }
#endif

        return Result;
    }

    template<typename T>
    std::shared_ptr<Hook> Create(const std::wstring& Module, const std::wstring& Function, const T Detour, std::wstring Key)
    {
        if (Key.empty() == true)
        {
            Key = Module + L"::" + Function;
        }

        // Check if we already have a hooked function with that key.
        if (Private::Hooks.find(Key) != Private::Hooks.end())
        {
            return Private::Hooks.at(Key);
        }

        auto Handle = GetModuleHandle(Module.c_str());

        // If we don't have the module loaded, try to load it.
        if (Handle == nullptr)
        {
            LoadLibrary(Module.c_str());

            // Try again to get the module's handle.
            Handle = GetModuleHandle(Module.c_str());

            // Is it loaded now?
            if (Handle == nullptr)
            {
                LOG_ERROR << L"Module " << std::quoted(Module) << L" cannot be found" << LOG_LINE_SEPARATOR;
                return nullptr;
            }
        }

        auto Address = GetProcAddress(Handle, std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(Function).c_str());

        // Do we have an invalid address?
        if (Address == nullptr)
        {
            LOG_ERROR << L"Cannot find the address for " << std::quoted(Function) << L" in module " << std::quoted(Module) << LOG_LINE_SEPARATOR;
            return nullptr;
        }

        auto Result = Private::Create(reinterpret_cast<uintptr_t>(Address), reinterpret_cast<uintptr_t>(Detour), Key);

#ifdef _DEBUG
        LOG_DEBUG << std::quoted(Function) << L" found at " << std::hex << std::showbase << reinterpret_cast<uintptr_t>(Address) << L" in module " << std::quoted(Module) << LOG_LINE_SEPARATOR;

        if (Result->IsValid() == true)
        {
            LOG_DEBUG << L"Function " << std::quoted(Key) << L" (" << std::hex << std::showbase << reinterpret_cast<uintptr_t>(Address) << L") was successfully hooked" << LOG_LINE_SEPARATOR;
        }
#endif

        return Result;
    }

    template<typename T>
    std::shared_ptr<Hook> Create(std::wstring Pattern, const T Detour, std::wstring Key)
    {
        if (Key.empty() == true)
        {
            Key = Pattern;
        }

        // Remove whitespaces between bytes.
        Pattern.erase(std::remove_if(Pattern.begin(), Pattern.end(), ::isspace), Pattern.end());

        // Make sure the pattern is properly aligned.
        if (Pattern.length() % 2 > 0)
        {
            LOG_ERROR << L"Pattern " << std::quoted(Pattern) << L" is not properly aligned" << LOG_LINE_SEPARATOR;
            return nullptr;
        }

        // Check if we already have a hooked function with that pattern.
        if (Private::Hooks.find(Key) != Private::Hooks.end())
        {
            return Private::Hooks.at(Key);
        }

        auto Address = RenHook::Pattern::Find(Pattern);

        if (Address == 0)
        {
            LOG_ERROR << L"Pattern " << std::quoted(Pattern) << L" not found" << LOG_LINE_SEPARATOR;
            return nullptr;
        }

        auto Result = Private::Create(Address, reinterpret_cast<uintptr_t>(Detour), Key);

#ifdef _DEBUG
        if (Result->IsValid() == true)
        {
            LOG_DEBUG << L"Function with pattern " << std::quoted(Pattern) << L" (" << std::hex << std::showbase << Address << L") was successfully hooked" << LOG_LINE_SEPARATOR;
        }
#endif

        return Result;
    }

    std::shared_ptr<Hook> Get(const uintptr_t Address);

    std::shared_ptr<Hook> Get(const std::wstring& Key);

    std::shared_ptr<Hook> Get(const std::wstring& Module, const std::wstring& Function);

    void Remove(const uintptr_t Address);

    void Remove(const std::wstring& Key);

    void Remove(const std::wstring& Module, const std::wstring& Function);

    void RemoveAll();
}