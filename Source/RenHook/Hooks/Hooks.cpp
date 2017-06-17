#include <RenHook/RenHook.hpp>
#include <RenHook/Hooks/Hooks.hpp>

std::map<std::wstring, std::shared_ptr<RenHook::Hook>> RenHook::Managers::Hooks::Private::Hooks;

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Private::Create(const uintptr_t Address, const uintptr_t Detour, const std::wstring& Key)
{
    auto Result = std::make_shared<Hook>(Address, Detour);
    Hooks.emplace(Key, Result);

    return Result;
}

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Get(const uintptr_t Address)
{
    auto Key = std::to_wstring(Address);

    if (Private::Hooks.find(Key) != Private::Hooks.end())
    {
        return Private::Hooks.at(Key);
    }

    return nullptr;
}

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Get(const std::wstring& Key)
{
    if (Private::Hooks.find(Key) != Private::Hooks.end())
    {
        return Private::Hooks.at(Key);
    }

    return nullptr;
}

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Get(const std::wstring& Module, const std::wstring& Function)
{
    auto Key = Module + L"::" + Function;

    if (Private::Hooks.find(Key) != Private::Hooks.end())
    {
        return Private::Hooks.at(Key);
    }

    return nullptr;
}

void RenHook::Managers::Hooks::Remove(const uintptr_t Address)
{
    Private::Hooks.erase(std::to_wstring(Address));
}

void RenHook::Managers::Hooks::Remove(const std::wstring& Key)
{
    Private::Hooks.erase(Key);
}

void RenHook::Managers::Hooks::Remove(const std::wstring& Module, const std::wstring& Function)
{
    Private::Hooks.erase(Module + L"::" + Function);
}

void RenHook::Managers::Hooks::RemoveAll()
{
    Private::Hooks.clear();
}
