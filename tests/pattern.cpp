#include <catch2/catch.hpp>

#include <renhook/pattern.hpp>

TEST_CASE("pattern")
{
    std::vector<uint8_t> fake_memory =
    {
        0x48, 0x89, 0x5C, 0x24, 0x08,               // mov [rsp+arg_0], rbx
        0x57,                                       // push rdi
        0x48, 0x83, 0xEC, 0x20,                     // sub rsp, 20h
        0x48, 0x8B, 0xD9,                           // mov rbx, rcx
        0x33, 0xFF,                                 // xor edi, edi
        0x48, 0x83, 0xC1, 0x08,                     // add rcx, 8
        0x48, 0x89, 0x79, 0xF8,                     // mov [rcx-8], rdi
        0xE8, 0x34, 0x32, 0xAF, 0xFE,               // call 0xFFFFFFFFFEAF3239
        0x48, 0x8B, 0x0D, 0x2D, 0x76, 0x2F, 0x01,   // mov rcx, [0x00000000012F7634]
        0xE8, 0x2B, 0x32, 0xAF, 0xFE,               // call 0xFFFFFFFFF4A13636
        0x48, 0x8D, 0x4B, 0x20,                     // mov rcx, [0xFFFFFFFFA1277631]
        0xE8, 0x22, 0x32, 0xAF, 0xFE,               // call 0x0000000045030105
        0x48, 0x89, 0x7B, 0x30,                     // mov [rbx+30h], rdi
        0x89, 0x7B, 0x38,                           // mov [rbx+38h], edi
        0x48, 0x8B, 0xC3,                           // mov rax, rbx
        0x48, 0x8B, 0x5C, 0x24, 0x30,               // mov rbx, [rsp+28h+arg_0]
        0x48, 0x83, 0xC4, 0x20,                     // add rsp, 20h
        0x5F,                                       // pop rdi
        0xC3                                        // retn
    };

    auto start = fake_memory.data();
    auto end = start + fake_memory.size();

    SECTION("{}")
    {
        renhook::pattern pattern;

        REQUIRE(pattern.empty());
        REQUIRE(pattern.size() == 0);
        REQUIRE_THROWS(pattern.find(0xCC, start, end));
    }
    SECTION("48 89 5C 24 08")
    {
        renhook::pattern pattern({ 0x48, 0x89, 0x5C, 0x24, 0x08 });

        REQUIRE(!pattern.empty());
        REQUIRE(pattern.size() == 5);

        auto offsets = pattern.find(0xCC, start, end);

        REQUIRE(offsets.size() == 1);
        REQUIRE(offsets[0] == reinterpret_cast<uintptr_t>(&fake_memory[0]));
    }
    SECTION("E8 ? ? ? ?")
    {
        renhook::pattern pattern({ 0xE8, 0xCC, 0xCC, 0xCC, 0xCC });

        REQUIRE(!pattern.empty());
        REQUIRE(pattern.size() == 5);

        auto offsets = pattern.find(0xCC, start, end);

        REQUIRE(offsets.size() == 3);
        REQUIRE(offsets[0] == reinterpret_cast<uintptr_t>(&fake_memory[23]));
        REQUIRE(offsets[1] == reinterpret_cast<uintptr_t>(&fake_memory[35]));
        REQUIRE(offsets[2] == reinterpret_cast<uintptr_t>(&fake_memory[44]));
    }
    SECTION("48 89 79 F8 E8 ? ? ? ? 48 8B 0D ? ? ? ?")
    {
        renhook::pattern pattern({ 0x48, 0x89, 0x79, 0xF8, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC });

        REQUIRE(!pattern.empty());
        REQUIRE(pattern.size() == 16);

        auto offsets = pattern.find(0xCC, start, end);

        REQUIRE(offsets.size() == 1);
        REQUIRE(offsets[0] == reinterpret_cast<uintptr_t>(&fake_memory[19]));
    }
}
