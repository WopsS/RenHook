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
    uint8_t bytes[32];
    uint8_t copy_bytes[] = { 0x01, 0xFF, 0x32, 0x90, 0x45 };

    renhook::hook_writer writer(bytes);

    writer.copy_from(copy_bytes, sizeof(copy_bytes));
    writer.write_jump(0);
    writer.write_nops(5);

    std::vector<uint8_t> expected_bytes =
    {
        0x01, 0xFF, 0x32, 0x90, 0x45,

#ifdef _WIN64
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#else
        0xE9, 0x00, 0x00, 0x00, 0x00,
#endif

        0x90, 0x90, 0x90, 0x90, 0x90
    };

#ifndef _WIN64
    *(reinterpret_cast<uintptr_t*>(&expected_bytes[6])) = renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(&bytes[5]), 0, 5);
#endif

    REQUIRE(compare_memory(bytes, expected_bytes));
}
