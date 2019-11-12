#include <catch2/catch.hpp>

#include <renhook/hook_writer.hpp>
#include <renhook/utils.hpp>

bool compare_memory(const uint8_t* memory, std::vector<uint8_t> bytes)
{
    if (bytes.size() == 0)
    {
        return false;
    }

    for (size_t i = 0; i < bytes.size(); i++)
    {
        auto byte = bytes[i];
        if (byte == 0xCC)
        {
            continue;
        }

        if (byte != memory[i])
        {
            return false;
        }
    }

    return true;
}

TEST_CASE("hook_writer")
{
    uint8_t bytes[64];
    uint8_t copy_bytes[] = { 0x57, 0x56, 0x55, 0x90, 0x90 };

#ifdef _WIN64
    size_t relative_jump_index = 19;
#else
    size_t relative_jump_index = 5;
#endif

    renhook::hook_writer writer(bytes);
    writer.copy_from(copy_bytes, sizeof(copy_bytes));

#ifdef _WIN64
    writer.write_indirect_jump(0);
#endif

    writer.write_relative_jump(reinterpret_cast<uintptr_t>(&bytes[relative_jump_index] + 5 - 0x30));
    writer.write_nops(5);

    std::vector<uint8_t> expected_bytes =
    {
        0x57, 0x56, 0x55, 0x90, 0x90,

#ifdef _WIN64
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#endif

        0xE9, 0xD0, 0xFF, 0xFF, 0xFF,
        0x90, 0x90, 0x90, 0x90, 0x90
    };

    REQUIRE(compare_memory(bytes, expected_bytes));
}
