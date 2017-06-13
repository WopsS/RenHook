#include <RenHook/RenHook.hpp>
#include <RenHook/Hooks/Hooks.hpp>

std::map<std::wstring, std::shared_ptr<RenHook::Hook>> RenHook::Managers::Hooks::Private::Hooks;

std::shared_ptr<RenHook::Hook> RenHook::Managers::Hooks::Private::Create(const uintptr_t Address, const uintptr_t Detour, const size_t Size, const std::wstring& Key)
{
    auto Result = std::make_shared<Hook>(Address, Detour, Size);
    Hooks.emplace(Key, Result);

    return Result;
}
