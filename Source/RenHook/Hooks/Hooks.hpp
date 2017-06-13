#pragma once

#include <RenHook/Hooks/Hook.hpp>
#include <RenHook/Pattern/Pattern.hpp>

namespace RenHook
{
    namespace Managers
    {
        namespace Hooks
        {
            namespace Private
            {
                std::shared_ptr<Hook> Create(const uintptr_t Address, const uintptr_t Detour, const size_t Size, const std::wstring& Key);

                extern std::map<std::wstring, std::shared_ptr<RenHook::Hook>> Hooks;
            }

            template<typename T>
            static std::shared_ptr<Hook> Create(const uintptr_t Address, const T Detour, const size_t Size, std::wstring Key)
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

                return Private::Create(Address, reinterpret_cast<uintptr_t>(Detour), Size, Key);
            }

            template<typename T>
            static std::shared_ptr<Hook> Create(const std::wstring& Module, const std::wstring& Function, const T Detour, const size_t Size, std::wstring Key)
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

#ifdef _DEBUG
                LOG_DEBUG << std::quoted(Function) << L" found at " << std::hex << std::showbase << reinterpret_cast<uintptr_t>(Address) << L" in module " << std::quoted(Module) << LOG_LINE_SEPARATOR;
#endif

                return Private::Create(reinterpret_cast<uintptr_t>(Address), reinterpret_cast<uintptr_t>(Detour), Size, Key);
            }

            template<typename T>
            static std::shared_ptr<Hook> Create(const std::wstring& Pattern, const T Detour, const size_t Size, std::wstring Key)
            {
                if (Key.empty() == true)
                {
                    Key = Pattern;

                    // Remove whitespaces between bytes.
                    Key.erase(std::remove_if(Key.begin(), Key.end(), ::isspace), Key.end());
                }

                // Make sure the pattern is properly aligned.
                if (Key.length() % 2 > 0)
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

                return Private::Create(Address, reinterpret_cast<uintptr_t>(Detour), Size, Key);
            }
        }
    }
}