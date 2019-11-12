#include <catch2/catch.hpp>

#include <renhook/zydis.hpp>

TEST_CASE("zydis")
{
    uint8_t data[] =
    {
#ifdef _WIN64
        0x48, 0x89, 0x5C, 0x24, 0x08,               // mov [rsp+arg_0], rbx
        0x57,                                       // push rdi
        0x48, 0x83, 0xEC, 0x20,                     // sub rsp, 20h
        0x48, 0x8B, 0xD9,                           // mov rbx, rcx
        0x33, 0xFF,                                 // xor edi, edi
        0x48, 0x83, 0xC1, 0x08,                     // add rcx, 8
        0x48, 0x89, 0x79, 0xF8,                     // mov [rcx-8], rdi
        0xE8, 0x34, 0x32, 0xAF, 0xFE,               // call 0xFFFFFFFFFEAF3239
        0x48, 0x8B, 0x0D, 0x2D, 0x76, 0x2F, 0x01    // mov rcx, [0x00000000012F7634]
#else
        0x89, 0x54, 0x24, 0x08,                     // mov [esp+arg_0], ebx
        0x57,                                       // push edi
        0x83, 0xEC, 0x20,                           // sub esp, 20h
        0x8B, 0xD9,                                 // mov ebx, ecx
        0x33, 0xFF,                                 // xor edi, edi
        0x83, 0xC1, 0x08,                           // add ecx, 8
        0x89, 0x79, 0xF8,                           // mov [ecx-8], edi
        0xE8, 0x34, 0x32, 0xAF, 0xFE,               // call 0xEAF3239
        0x8B, 0x0D, 0x2D, 0x76, 0x2F, 0x01          // mov ecx, [0x12F7634]
#endif
    };

    size_t decoded_length;

    renhook::zydis zydis;
    auto decoded_info = zydis.decode(reinterpret_cast<uintptr_t>(&data), sizeof(data), 5, decoded_length);

#ifdef _WIN64
    REQUIRE(decoded_length == 5);
    REQUIRE(decoded_info.instructions.size() == 1);

    decoded_info = zydis.decode(reinterpret_cast<uintptr_t>(&data), sizeof(data), 16, decoded_length);

    REQUIRE(decoded_length == 19);
    REQUIRE(decoded_info.instructions.size() == 6);

    decoded_info = zydis.decode(reinterpret_cast<uintptr_t>(&data), sizeof(data), 32, decoded_length);

    REQUIRE(decoded_length == 35);
    REQUIRE(decoded_info.instructions.size() == 9);
#else
    REQUIRE(decoded_length == 5);
    REQUIRE(decoded_info.instructions.size() == 2);

    decoded_info = zydis.decode(reinterpret_cast<uintptr_t>(&data), sizeof(data), 14, decoded_length);

    REQUIRE(decoded_length == 15);
    REQUIRE(decoded_info.instructions.size() == 6);

    decoded_info = zydis.decode(reinterpret_cast<uintptr_t>(&data), sizeof(data), 29, decoded_length);

    REQUIRE(decoded_length == 29);
    REQUIRE(decoded_info.instructions.size() == 9);
#endif
}
