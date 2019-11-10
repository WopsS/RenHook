#include <catch2/catch.hpp>

#include <Windows.h>
#include <renhook/executable.hpp>

TEST_CASE("executable")
{
    SECTION("base address")
    {
        REQUIRE(renhook::executable::get_base_address() == reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr)));
    }
    SECTION("code section")
    {
        auto base_address = renhook::executable::get_base_address();
        auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
        auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + static_cast<uintptr_t>(dos_header->e_lfanew));
        auto code_base_address = base_address + nt_header->OptionalHeader.BaseOfCode;

        SECTION("base address")
        {
            REQUIRE(code_base_address == renhook::executable::get_code_base_address());
        }
        SECTION("end address")
        {
            auto code_end_address = code_base_address + nt_header->OptionalHeader.SizeOfCode;
            REQUIRE(code_end_address == renhook::executable::get_code_end_address());
        }
        SECTION("size")
        {
            auto code_size = nt_header->OptionalHeader.SizeOfCode;
            REQUIRE(code_size == renhook::executable::get_code_size());
        }
    }
}
