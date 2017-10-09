#include <RenHook/RenHook.hpp>
#include <RenHook/Hooks/Hooks.hpp>

uintptr_t RenHook::Managers::Hooks::Private::ImageBase = 0;
std::map<std::string, std::shared_ptr<RenHook::Hook>> RenHook::Managers::Hooks::Private::Hooks;

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Private::Create(const uintptr_t Address, const uintptr_t Detour, const std::string& Key)
{
    auto Result = std::make_shared<Hook>(Address, Detour);
    Hooks.emplace(Key, Result);

    return Result;
}

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Get(const uintptr_t Address)
{
    auto Key = std::to_string(Address);

    if (Private::Hooks.find(Key) != Private::Hooks.end())
    {
        return Private::Hooks.at(Key);
    }

    return nullptr;
}

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Get(const std::string& Key)
{
    if (Private::Hooks.find(Key) != Private::Hooks.end())
    {
        return Private::Hooks.at(Key);
    }

    return nullptr;
}

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Get(const std::string& Module, const std::string& Function)
{
    auto Key = Module + "::" + Function;

    if (Private::Hooks.find(Key) != Private::Hooks.end())
    {
        return Private::Hooks.at(Key);
    }

    return nullptr;
}

void RenHook::Managers::Hooks::Remove(const uintptr_t Address)
{
    Private::Hooks.erase(std::to_string(Address));
}

void RenHook::Managers::Hooks::Remove(const std::string& Key)
{
    Private::Hooks.erase(Key);
}

void RenHook::Managers::Hooks::Remove(const std::string& Module, const std::string& Function)
{
    Private::Hooks.erase(Module + "::" + Function);
}

void RenHook::Managers::Hooks::RemoveAll()
{
    Private::Hooks.clear();
}
