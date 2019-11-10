#include <catch2/catch.hpp>

#include <Windows.h>

#include <renhook/memory/memory_allocator.hpp>
#include <renhook/memory/virtual_protect.hpp>

TEST_CASE("memory::memory_allocator", "[memory][memory_allocator]")
{
    renhook::memory::memory_allocator allocator;

    char* block_a = static_cast<char*>(allocator.alloc());

    MEMORY_BASIC_INFORMATION memoryInfo = { 0 };
    VirtualQuery(block_a, &memoryInfo, sizeof(memoryInfo));

    REQUIRE(memoryInfo.Protect == PAGE_EXECUTE_READ);

    renhook::memory::virtual_protect protection(block_a, renhook::memory::memory_allocator::block_size, renhook::memory::protection::write);

    REQUIRE(block_a != nullptr);
    block_a[0] = '1';
    block_a[255] = '1';

    auto block_b = allocator.alloc();
    REQUIRE(block_b != nullptr);

    auto block_c = allocator.alloc();
    REQUIRE(block_c != nullptr);

    std::vector<void*> blocks;
    for (size_t i = 0; i < 10000; i++)
    {
        auto block = allocator.alloc();
        blocks.emplace_back(block);
    }

    auto block_d = allocator.alloc();
    auto block_e = allocator.alloc();
    auto block_f = allocator.alloc();

    allocator.free(block_a);

    auto block_g = allocator.alloc();

    allocator.free(block_b);
    allocator.free(block_c);
    allocator.free(block_g);

    auto block_h = allocator.alloc();
    allocator.free(block_h);

    allocator.free(block_d);
    allocator.free(block_e);
    allocator.free(block_f);

    for (auto block : blocks)
    {
        allocator.free(block);
    }
}
