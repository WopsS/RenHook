#include <RenHook/RenHook.hpp>
#include <RenHook/ExecutableMeta/ExecutableMeta.hpp>

uintptr_t BaseAddress = 0;

uintptr_t EndAddress = 0;

const uintptr_t RenHook::ExecutableMeta::GetBaseAddress()
{
    if (BaseAddress == 0)
    {
        BaseAddress = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));

        auto NTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(BaseAddress + static_cast<uintptr_t>(reinterpret_cast<PIMAGE_DOS_HEADER>(BaseAddress)->e_lfanew));
        EndAddress = BaseAddress + NTHeaders->OptionalHeader.SizeOfImage;
    }

    return BaseAddress;
}

const uintptr_t RenHook::ExecutableMeta::GetEndAddress()
{
    if (EndAddress == 0)
    {
        GetBaseAddress();
    }

    return EndAddress;
}