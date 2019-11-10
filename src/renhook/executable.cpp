#include <renhook/executable.hpp>

#include <Windows.h>

namespace
{
    PIMAGE_NT_HEADERS get_nt_header()
    {
        auto base_address = renhook::executable::get_base_address();
        auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
        return reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + static_cast<uintptr_t>(dos_header->e_lfanew));
    }
}

uintptr_t renhook::executable::get_base_address()
{
    static auto base_address = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    return base_address;
}

uintptr_t renhook::executable::get_code_base_address()
{
    static auto code_base_address = get_base_address() + get_nt_header()->OptionalHeader.BaseOfCode;
    return code_base_address;
}

uintptr_t renhook::executable::get_code_end_address()
{
    static auto code_end_address = get_code_base_address() + get_nt_header()->OptionalHeader.SizeOfCode;
    return code_end_address;
}

size_t renhook::executable::get_code_size()
{
    static auto code_size = get_nt_header()->OptionalHeader.SizeOfCode;
    return code_size;
}
