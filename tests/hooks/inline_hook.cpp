#include <catch2/catch.hpp>

#include <renhook/utils.hpp>
#include <renhook/hooks/inline_hook.hpp>

template<typename T>
class inline_hook_ex : public renhook::inline_hook<T>
{
public:

    using renhook::inline_hook<T>::inline_hook;

    const uint8_t* get_block_address() const
    {
        return renhook::inline_hook<T>::get_block_address();
    }
};

template<typename T>
using hook_t = inline_hook_ex<T>;

extern renhook::memory::memory_allocator global_allocator;
extern bool compare_memory(const uint8_t* memory, std::vector<uint8_t> bytes);

__declspec(noinline) uint32_t fibonacci(uint32_t a)
{
    if (a == 0 || a == 1)
    {
        return a;
    }

    return fibonacci(a - 1) + fibonacci(a - 2);
}

__declspec(noinline) uint32_t fibonacci_hooked(uint32_t a)
{
    return a;
}

TEST_CASE("hooks::inline_hook", "[hooks][inline_hook]")
{
    using void_func_t = void(*)();
     
    SECTION("skip jumps")
    {
        uint8_t data[] =
        {
            0xEB, 0x00,
            0xE9, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,

#ifdef _WIN64
            0x48, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
#endif

            0xE9, 0x06, 0x00, 0x00, 0x00,
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
            0xEB, 0x00,

            0x57,                               // push edi / rdi
            0x8D, 0x85, 0xE8, 0x03, 0x00, 0x00, // lea r8, [rbp+3C0h+arg_1]
            0x8D, 0x54, 0x24, 0x50,             // lea rdx, [rsp+4C0h+var_2]
            0x8B, 0xC8,                         // mov rcx, rax
            0xE8, 0x00, 0x00, 0x00, 0x00        // call 0x00000000                    
        };

#ifndef _WIN64
        *(reinterpret_cast<uintptr_t*>(&data[9])) = reinterpret_cast<uintptr_t>(&data[13]);
        *(reinterpret_cast<uintptr_t*>(&data[20])) = reinterpret_cast<uintptr_t>(&data[24]);
#endif

        hook_t<void_func_t> hook(reinterpret_cast<uintptr_t>(&data), static_cast<uintptr_t>(0));
        hook.attach();

        auto block = hook.get_block_address();
        std::vector<uint8_t> expected_block_bytes =
        {
            0x57,
            0x8D, 0x85, 0xE8, 0x03, 0x00, 0x00
        };

        REQUIRE(compare_memory(block, expected_block_bytes));
    }
    SECTION("empty hook")
    {
        hook_t<void_func_t> empty_hook;
        REQUIRE_THROWS(empty_hook.attach());
    }
    SECTION("fake hook")
    {
        SECTION("without relative instruction pointers")
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

            hook_t<void_func_t> hook(reinterpret_cast<uintptr_t>(&data), static_cast<uintptr_t>(0));
            hook.attach();

            auto block = hook.get_block_address();
            std::vector<uint8_t> expected_data_bytes =
            {
#ifdef _WIN64
                0xE9, 0x00, 0x00, 0x00, 0x00,
                0x57,
                0x48, 0x83, 0xEC, 0x20,
                0x48, 0x8B, 0xD9,
                0x33, 0xFF,
                0x48, 0x83, 0xC1, 0x08,
                0x48, 0x89, 0x79, 0xF8
#else
                0xE9, 0x00, 0x00, 0x00, 0x00,
                0x83, 0xEC, 0x20
#endif
            };

            std::vector<uint8_t> expected_block_bytes =
            {
#ifdef _WIN64
                0x48, 0x89, 0x5C, 0x24, 0x08,
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#else
                0x89, 0x54, 0x24, 0x08,
                0x57,
                0xE9, 0x00, 0x00, 0x00, 0x00
#endif
            };

#ifdef _WIN64
            *(reinterpret_cast<int32_t*>(&expected_data_bytes[1])) = static_cast<int32_t>(renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(&data), reinterpret_cast<uintptr_t>(block + 5 + hook_t<void_func_t>::indirect_jump_size), 5));
            *(reinterpret_cast<uintptr_t*>(&expected_block_bytes[11])) = reinterpret_cast<uintptr_t>(&data[5]);
#else
            *(reinterpret_cast<int32_t*>(&expected_data_bytes[1])) = static_cast<int32_t>(renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(&data), 0, 5));
            *(reinterpret_cast<int32_t*>(&expected_block_bytes[6])) = renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(block + 5), reinterpret_cast<uintptr_t>(&data[5]), 5);
#endif

            REQUIRE(compare_memory(data, expected_data_bytes));
            REQUIRE(compare_memory(block, expected_block_bytes));

            hook.detach();

            expected_data_bytes =
            {
#ifdef _WIN64
                0x48, 0x89, 0x5C, 0x24, 0x08,
                0x57,
                0x48, 0x83, 0xEC, 0x20,
                0x48, 0x8B, 0xD9,
                0x33, 0xFF,
                0x48, 0x83, 0xC1, 0x08,
                0x48, 0x89, 0x79, 0xF8
#else
                0x89, 0x54, 0x24, 0x08,
                0x57,
                0x83, 0xEC, 0x20
#endif
            };

            REQUIRE(compare_memory(data, expected_data_bytes));
        }
        SECTION("with relative instruction pointers")
        {
            uint8_t data[] =
            {
                0x57,                               // push edi / rdi
                0x74, 0x60,                         // jz 0x60
                0x0F, 0x84, 0x80, 0xFF, 0xFF, 0xFF, // jz 0xFFFFFF80
                0x8D, 0x85, 0xE8, 0x03, 0x00, 0x00, // lea r8, [rbp+3C0h+arg_1]
                0x8D, 0x54, 0x24, 0x50,             // lea rdx, [rsp+4C0h+var_2]
                0x8B, 0xC8,                         // mov rcx, rax
                0xE8, 0x97, 0x05, 0xD0, 0x00,       // call 0x00D0059C
                0x8B, 0xC8                          // mov rcx, rax
            };

            auto first_jump_real_addr = reinterpret_cast<uintptr_t>(&data[1]) + data[2] + 2;
            auto second_jump_real_addr = reinterpret_cast<uintptr_t>(&data[3]) + *reinterpret_cast<int32_t*>(&data[5]) + 6;

            hook_t<void_func_t> hook(reinterpret_cast<uintptr_t>(&data), static_cast<uintptr_t>(0));
            hook.attach();

            auto block = hook.get_block_address();
            std::vector<uint8_t> expected_data_bytes =
            {
                0xE9, 0x00, 0x00, 0x00, 0x00,
                0x90, 0x90, 0x90, 0x90,
                0x8D, 0x85, 0xE8, 0x03, 0x00, 0x00
            };

            std::vector<uint8_t> expected_block_bytes =
            {
                0x57,
                0x74, 0x00,
                0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,

#ifdef _WIN64
                // Return to function jump.
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

                // Indirect jump to detour.
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

                // First item in jump table (for the 2 bytes jump).
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#else
                // Return to function jump.
                0xE9, 0x00, 0x00, 0x00, 0x00,

                // First item in jump table (for the 2 bytes jump).
                0xE9, 0x00, 0x00, 0x00, 0x00,
#endif
            };

#ifdef _WIN64
            *(reinterpret_cast<int32_t*>(&expected_data_bytes[1])) = static_cast<int32_t>(renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(&data), reinterpret_cast<uintptr_t>(block + 9 + hook_t<void_func_t>::indirect_jump_size), 5));

            *(reinterpret_cast<int8_t*>(&expected_block_bytes[2])) = static_cast<int8_t>(renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(&data[1]), reinterpret_cast<uintptr_t>(&data[0] + 37), 2));
            *(reinterpret_cast<uintptr_t*>(&expected_block_bytes[15])) = reinterpret_cast<uintptr_t>(&data[9]);
            *(reinterpret_cast<uintptr_t*>(&expected_block_bytes[43])) = first_jump_real_addr;
            *(reinterpret_cast<int32_t*>(&expected_block_bytes[5])) = static_cast<int32_t>(renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(block + 3), second_jump_real_addr, 6));
#else
            *(reinterpret_cast<int32_t*>(&expected_data_bytes[1])) = static_cast<int32_t>(renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(&data), 0, 5));

            *(reinterpret_cast<int8_t*>(&expected_block_bytes[2])) = static_cast<int8_t>(renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(&data[1]), reinterpret_cast<uintptr_t>(&data[0] + 14), 2));
            *(reinterpret_cast<int32_t*>(&expected_block_bytes[5])) = renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(&data[3]), reinterpret_cast<uintptr_t>(&data[0] + 19), 6);
            *(reinterpret_cast<int32_t*>(&expected_block_bytes[10])) = renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(block + 9), reinterpret_cast<uintptr_t>(&data[9]), 5);
            *(reinterpret_cast<int32_t*>(&expected_block_bytes[15])) = renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(block + 14), first_jump_real_addr, 5);
            *(reinterpret_cast<int32_t*>(&expected_block_bytes[5])) = renhook::utils::calculate_displacement(reinterpret_cast<uintptr_t>(block + 3), second_jump_real_addr, 6);
#endif

            REQUIRE(compare_memory(data, expected_data_bytes));
            REQUIRE(compare_memory(block, expected_block_bytes));

            hook.detach();

            expected_data_bytes =
            {
                0x57,
                0x74, 0x60,
                0x0F, 0x84, 0x80, 0xFF, 0xFF, 0xFF,
                0x8D, 0x85, 0xE8, 0x03, 0x00, 0x00,
                0x8D, 0x54, 0x24, 0x50
            };

            REQUIRE(compare_memory(data, expected_data_bytes));
        }
    }
    SECTION("real hook")
    {
        REQUIRE(fibonacci(10) == 55);

        using fibonacci_t = uint32_t (*)(uint32_t);
        hook_t<fibonacci_t> hook(reinterpret_cast<uintptr_t>(&fibonacci), &fibonacci_hooked);

        hook.attach();
        REQUIRE(fibonacci(10) == 10);

        hook.detach();
        REQUIRE(fibonacci(10) == 55);
    }
}
