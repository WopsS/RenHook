#include <RenHook/RenHook.hpp>
#include <RenHook/Hooks/Hooks.hpp>

uintptr_t RenHook::Managers::Hooks::Private::ImageBase = 0;
std::map<std::string, std::shared_ptr<RenHook::Hook>> RenHook::Managers::Hooks::Private::Hooks;

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Private::Create(uintptr_t aAddress, uintptr_t aDetour, const std::string& aKey)
{
    auto result = std::make_shared<Hook>(aAddress, aDetour);
    Hooks.emplace(aKey, result);

    return result;
}

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Get(uintptr_t aAddress)
{
    auto key = std::to_string(aAddress);

    if (Private::Hooks.find(key) != Private::Hooks.end())
    {
        return Private::Hooks.at(key);
    }

    return nullptr;
}

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Get(const std::string& aKey)
{
    if (Private::Hooks.find(aKey) != Private::Hooks.end())
    {
        return Private::Hooks.at(aKey);
    }

    return nullptr;
}

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Get(const std::string& aModule, const std::string& aFunction)
{
    auto key = aModule + "::" + aFunction;

    if (Private::Hooks.find(key) != Private::Hooks.end())
    {
        return Private::Hooks.at(key);
    }

    return nullptr;
}

void RenHook::Managers::Hooks::Remove(uintptr_t aAddress)
{
    Private::Hooks.erase(std::to_string(aAddress));
}

void RenHook::Managers::Hooks::Remove(const std::string& aKey)
{
    Private::Hooks.erase(aKey);
}

void RenHook::Managers::Hooks::Remove(const std::string& aModule, const std::string& aFunction)
{
    Private::Hooks.erase(aModule + "::" + aFunction);
}

void RenHook::Managers::Hooks::RemoveAll()
{
    Private::Hooks.clear();
}
