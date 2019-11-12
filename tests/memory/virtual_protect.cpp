#include <catch2/catch.hpp>

#include <Windows.h>

#include <renhook/exception.hpp>
#include <renhook/memory/virtual_protect.hpp>

constexpr size_t allocation_size = 0x10000;

uint32_t get_memory_protection(void* address)
{
    MEMORY_BASIC_INFORMATION memory_info = { 0 };
    if (!VirtualQuery(address, &memory_info, sizeof(memory_info)))
    {
        throw renhook::exception("retrieving information about memory failed", GetLastError());
    }

    return memory_info.Protect;
}

TEST_CASE("memory::virtual_protect", "[memory][protection]")
{
    using protection = renhook::memory::protection;

    SECTION("valid address")
    {
        auto address = VirtualAlloc(nullptr, allocation_size, MEM_COMMIT, PAGE_NOACCESS);
        REQUIRE(get_memory_protection(address) == PAGE_NOACCESS);

        SECTION("protection::read")
        {
            renhook::memory::virtual_protect _(address, allocation_size, protection::read);
            REQUIRE(get_memory_protection(address) == PAGE_READONLY);
        }
        SECTION("protection::write")
        {
            renhook::memory::virtual_protect _(address, allocation_size, protection::write);
            REQUIRE(get_memory_protection(address) == PAGE_READWRITE);
        }
        SECTION("protection::execute")
        {
            renhook::memory::virtual_protect _(address, allocation_size, protection::execute);
            REQUIRE(get_memory_protection(address) == PAGE_EXECUTE);
        }
        SECTION("protection::read | protection::write")
        {
            renhook::memory::virtual_protect _(address, allocation_size, protection::read | protection::write);
            REQUIRE(get_memory_protection(address) == PAGE_READWRITE);
        }
        SECTION("protection::read | protection::execute")
        {
            renhook::memory::virtual_protect _(address, allocation_size, protection::read | protection::execute);
            REQUIRE(get_memory_protection(address) == PAGE_EXECUTE_READ);
        }
        SECTION("protection::read | protection::write | protection::execute")
        {
            renhook::memory::virtual_protect _(address, allocation_size, protection::read | protection::write | protection::execute);
            REQUIRE(get_memory_protection(address) == PAGE_EXECUTE_READWRITE);
        }

        REQUIRE(get_memory_protection(address) == PAGE_NOACCESS);

        SECTION("permanent change")
        {
            {
                renhook::memory::virtual_protect _(address, allocation_size, protection::read, true);
            }

            REQUIRE(get_memory_protection(address) == PAGE_READONLY);
        }

        VirtualFree(address, 0, MEM_RELEASE);
        address = nullptr;
    }
    SECTION("invalid address")
    {
        REQUIRE_THROWS(renhook::memory::virtual_protect(nullptr, allocation_size, protection::read));
        REQUIRE_THROWS(renhook::memory::virtual_protect(reinterpret_cast<void*>(1), allocation_size, protection::read));
        REQUIRE_THROWS(renhook::memory::virtual_protect(reinterpret_cast<uintptr_t*>(-1), allocation_size, protection::read));
    }
}
