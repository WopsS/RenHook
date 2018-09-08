#include <renhook/executable.hpp>

#include <mutex>

#include <Windows.h>
#include <winnt.h>

namespace
{
    uintptr_t base_address;

    uintptr_t code_base_address;
    uintptr_t code_end_address;

    PIMAGE_NT_HEADERS get_nt_header()
    {
        auto base_address = renhook::executable::get_base_address();
        auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
        return reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + static_cast<uintptr_t>(dos_header->e_lfanew));
    }
}

uintptr_t renhook::executable::get_base_address()
{
    static std::once_flag once_flag;
    std::call_once(once_flag, []()
    {
        base_address = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    });

    return base_address;
}

uintptr_t renhook::executable::get_code_base_address()
{
    static std::once_flag once_flag;
    std::call_once(once_flag, []()
    {
        auto nt_header = get_nt_header();
        code_base_address = get_base_address() + nt_header->OptionalHeader.BaseOfCode;
    });

    return code_base_address;
}

uintptr_t renhook::executable::get_code_end_address()
{
    static std::once_flag once_flag;
    std::call_once(once_flag, []()
    {
        auto nt_header = get_nt_header();
        code_end_address = get_code_base_address() + nt_header->OptionalHeader.SizeOfCode;
    });

    return code_end_address;
}
