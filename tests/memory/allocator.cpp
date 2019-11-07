#include <catch2/catch.hpp>

#include <renhook/memory/allocator.hpp>

TEST_CASE("memory::allocator", "[memory][allocator]")
{
    renhook::memory::allocator allocator;

    char* block_a = static_cast<char*>(allocator.alloc());

    REQUIRE(block_a != nullptr);
    block_a[0] = '1';
    block_a[255] = '1';

    auto block_b = allocator.alloc();
    REQUIRE(block_b != nullptr);

    auto block_c = allocator.alloc();
    REQUIRE(block_c != nullptr);

    std::vector<void*> blocks;
    for (size_t i = 0; i < 1000000; i++)
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
