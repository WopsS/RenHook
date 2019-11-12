#include <catch2/catch.hpp>

#include <Windows.h>

#include <renhook/memory/memory_allocator.hpp>
#include <renhook/memory/virtual_protect.hpp>

TEST_CASE("memory::memory_allocator", "[memory][memory_allocator]")
{
    SYSTEM_INFO system_info = { 0 };
    GetSystemInfo(&system_info);

    size_t region_size = system_info.dwAllocationGranularity;
    auto minimum_address = reinterpret_cast<uintptr_t>(system_info.lpMinimumApplicationAddress);
    auto maximum_address = reinterpret_cast<uintptr_t>(system_info.lpMaximumApplicationAddress);

    renhook::memory::memory_allocator allocator;

    char* block_a = static_cast<char*>(allocator.alloc(0, -1));

    MEMORY_BASIC_INFORMATION memoryInfo = { 0 };
    VirtualQuery(block_a, &memoryInfo, sizeof(memoryInfo));

    REQUIRE(memoryInfo.Protect == PAGE_EXECUTE_READ);

    renhook::memory::virtual_protect protection(block_a, renhook::memory::memory_allocator::block_size, renhook::memory::protection::write);

    REQUIRE(block_a != nullptr);
    block_a[0] = '1';
    block_a[255] = '1';

    auto block_b = allocator.alloc(minimum_address + 0x10000, maximum_address / 2);
    REQUIRE(block_b != nullptr);

    auto block_c = allocator.alloc(minimum_address + 0x10000, maximum_address / 2 + 0x500);
    REQUIRE(block_c != nullptr);

    size_t diff = std::abs(reinterpret_cast<intptr_t>(block_c) - reinterpret_cast<intptr_t>(block_b));
    REQUIRE(diff < region_size);

    REQUIRE_THROWS(allocator.alloc(reinterpret_cast<uintptr_t>(block_c), reinterpret_cast<uintptr_t>(block_c) + 0x10));

    auto block_d = allocator.alloc(maximum_address / 2 + 0x100, maximum_address);
    REQUIRE(block_d != nullptr);

    diff = std::abs(reinterpret_cast<intptr_t>(block_d) - reinterpret_cast<intptr_t>(block_b));
    REQUIRE(diff >= region_size);

    std::vector<void*> blocks;
    for (size_t i = 0; i < 10000; i++)
    {
        auto block = allocator.alloc(0, -1);
        blocks.emplace_back(block);
    }

    auto block_e = allocator.alloc(0, -1);
    auto block_f = allocator.alloc(0, -1);
    auto block_g = allocator.alloc(0, -1);

    allocator.free(block_a);

    auto block_h = allocator.alloc(0, -1);

    allocator.free(block_b);
    allocator.free(block_c);
    allocator.free(block_g);

    auto block_i = allocator.alloc(0, -1);
    allocator.free(block_h);

    allocator.free(block_d);
    allocator.free(block_e);
    allocator.free(block_f);
    allocator.free(block_i);

    for (auto block : blocks)
    {
        allocator.free(block);
    }
}
