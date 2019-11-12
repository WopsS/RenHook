#ifndef RENHOOK_HOOKS_INLINE_HOOK_H
#define RENHOOK_HOOKS_INLINE_HOOK_H

#include <algorithm>
#include <limits>
#include <string>

#include <Windows.h>

#include <renhook/exception.hpp>
#include <renhook/executable.hpp>
#include <renhook/hook_writer.hpp>
#include <renhook/pattern.hpp>
#include <renhook/suspend_threads.hpp>
#include <renhook/utils.hpp>
#include <renhook/zydis.hpp>

#include <renhook/memory/memory_allocator.hpp>
#include <renhook/memory/virtual_protect.hpp>

#undef min
#undef max

namespace renhook
{
    /**
     * @brief An inline hook.
     *
     * @tparam T The hooked function type.
     */
    template<typename T>
    class inline_hook
    {
    public:

        /**
         * @brief The size of a relative jump.
         */
        static constexpr size_t relative_jump_size = 5;

        /**
         * @brief The size of an indirect jump.
         */
        static constexpr size_t indirect_jump_size = 14;

        /**
         * @brief Construct an empty hook.
         */
        inline_hook()
            : m_target_address(0)
            , m_detour_address(0)
            , m_wildcard(0)
            , m_offset(0)
            , m_attached(false)
            , m_decoded_length(0)
            , m_block(nullptr)
        {
        }

        /**
         * @brief Construct a new hook.
         *
         * @param target_address[in] The address of the function that will be hooked.
         * @param detour_address[in] The address of the callback.
         */
        inline_hook(uintptr_t target_address, uintptr_t detour_address)
            : inline_hook()
        {
            m_target_address = target_address;
            m_detour_address = detour_address;
        }

        /**
         * @brief Construct a new hook.
         *
         * @param target_address[in] The address of the function that will be hooked.
         * @param detour_address[in] The address of the callback.
         */
        inline_hook(uintptr_t target_address, T detour_address)
            : inline_hook(target_address, reinterpret_cast<uintptr_t>(detour_address))
        {
        }

        /**
         * @brief Construct a new hook using a pattern.
         *
         * @param pattern[in]           The pattern of the function that will be hooked.
         * @param detour_address[in]    The address of the callback.
         * @param wildcard[in]          The wildcard for #pattern.
         * @param offset[in]            The offset of the #pattern.
         */
        inline_hook(pattern pattern, uintptr_t detour_address, uint8_t wildcard = 0xCC, size_t offset = 0)
            : inline_hook()
        {
            m_detour_address = detour_address;
            m_pattern = std::move(pattern);
            m_wildcard = wildcard;
            m_offset = offset;
        }

        /**
         * @brief Construct a new hook using a pattern.
         *
         * @param pattern[in]           The pattern of the function that will be hooked.
         * @param detour_address[in]    The address of the callback.
         * @param wildcard[in]          The wildcard for #pattern.
         * @param offset[in]            The offset of the #pattern.
         */
        inline_hook(pattern pattern, T detour_address, uint8_t wildcard = 0xCC, size_t offset = 0)
            : inline_hook(pattern, reinterpret_cast<uintptr_t>(detour_address), wildcard, offset)
        {
        }

        /**
         * @brief Construct a new hook.
         *
         * @param module[in]            The module which contain the #function.
         * @param function[in]          The function that will be hooked.
         * @param detour_address[in]    The address of the callback.
         *
         * @note If the module is not loaded, the library will load it when the hook is attached.
         */
        inline_hook(const std::string& module, const std::string& function, uintptr_t detour_address)
            : inline_hook()
        {
            m_module = module;
            m_function = function;
            m_detour_address = detour_address;
        }

        /**
         * @brief Construct a new hook.
         *
         * @param module[in]            The module which contain the #function.
         * @param function[in]          The function that will be hooked.
         * @param detour_address[in]    The address of the callback.
         *
         * @note If the module is not loaded, the library will load it when the hook is attached.
         */
        inline_hook(const std::string& module, const std::string& function, T detour_address)
            : inline_hook(module, function, reinterpret_cast<uintptr_t>(detour_address))
        {
        }

        inline_hook(inline_hook&& rhs) noexcept
            : m_target_address(rhs.m_target_address)
            , m_detour_address(rhs.m_detour_address)
            , m_pattern(std::move(rhs.m_pattern))
            , m_wildcard(rhs.m_wildcard)
            , m_offset(rhs.m_offset)
            , m_attached(rhs.m_attached)
            , m_decoded_length(rhs.m_decoded_length)
            , m_block(rhs.m_block)
        {
            rhs.m_attached = false;
            rhs.m_block = nullptr;
        }

        ~inline_hook()
        {
            if (m_attached)
            {
                // Hacky fix: Check if the memory is stil valid. Usually it isn't when the program is finished and all global variables are uninitialized.
                // Another solution would be to store the global allocator and all hooks in a structure then remove the hooks when the structure's destructor is called,
                // but that would require the library to consume more memory.

                MEMORY_BASIC_INFORMATION memory_info = { 0 };
                if (VirtualQuery(m_block, &memory_info, sizeof(memory_info)))
                {
                    if (memory_info.State == MEM_COMMIT)
                    {
                        detach();
                    }
                }
            }
        }

        inline_hook& operator=(inline_hook&& rhs) noexcept
        {
            m_target_address = rhs.m_target_address;
            m_detour_address = rhs.m_detour_address;
            m_pattern = std::move(rhs.m_pattern);
            m_wildcard = rhs.m_wildcard;
            m_offset = rhs.m_offset;
            m_attached = rhs.m_attached;
            m_decoded_length = rhs.m_decoded_length;
            m_block = rhs.m_block;

            rhs.m_attached = false;
            rhs.m_block = nullptr;

            return *this;
        }

        inline_hook(inline_hook&) = delete;
        inline_hook& operator=(const inline_hook&) = delete;

        /**
         * @brief Call the original function.
         *
         * @return The value returned by the original function.
         */
        operator T() const
        {
            return reinterpret_cast<T>(m_block);
        }

        /**
         * @brief Enable the hook.
         */
        void attach()
        {
            using namespace renhook::memory;

            if (m_attached)
            {
                return;
            }

            if (!m_module.empty())
            {
                auto module_handle = GetModuleHandleA(m_module.c_str());
                if (!module_handle)
                {
                    LoadLibraryA(m_module.c_str());

                    module_handle = GetModuleHandleA(m_module.c_str());
                    if (!module_handle)
                    {
                        throw renhook::exception("module not found");
                    }
                }

                m_target_address = reinterpret_cast<uintptr_t>(GetProcAddress(module_handle, m_function.c_str()));
                if (m_target_address == 0)
                {
                    throw renhook::exception("cannot find function in module");
                }
            }

            if (m_target_address == 0)
            {
                if (m_pattern.empty())
                {
                    throw renhook::exception("cannot attach an empty hook");
                }

                auto addresses = m_pattern.find(m_wildcard);
                m_target_address = addresses.at(m_offset);
            }

            m_target_address = skip_jumps(m_target_address);
            m_detour_address = skip_jumps(m_detour_address);

            renhook::zydis zydis;
            auto decoded_info = zydis.decode(m_target_address, executable::get_code_size(), relative_jump_size, m_decoded_length);

            // Find the jump bounds (± 2GB).
            auto lower_bound = std::min(m_target_address, decoded_info.lowest_relative_address);
            auto upper_bound = std::max(m_target_address, decoded_info.highest_relative_address);

            constexpr auto two_gb_in_bytes = std::numeric_limits<int32_t>::max();
            constexpr auto max_pointer_address = std::numeric_limits<uintptr_t>::max();

            // Used to prevent upper bound overflow.
            constexpr auto max_upper_bound_memory = max_pointer_address - two_gb_in_bytes;

            if (lower_bound > two_gb_in_bytes)
            {
                lower_bound -= two_gb_in_bytes;
            }

            if (upper_bound < max_pointer_address)
            {
                upper_bound += two_gb_in_bytes;
            }

            suspend_threads threads(m_target_address, m_decoded_length);

            extern memory_allocator global_allocator;
            m_block = static_cast<uint8_t*>(global_allocator.alloc(lower_bound, upper_bound));

            // Write the bytes to our memory.
            virtual_protect block_protection(m_block, memory_allocator::block_size, protection::read | protection::write | protection::execute);
            hook_writer block_writer(m_block);

            block_writer.copy_from(m_target_address, m_decoded_length);

#ifdef _WIN64
            block_writer.write_indirect_jump(m_target_address + m_decoded_length);
#else
            block_writer.write_relative_jump(m_target_address + m_decoded_length);
#endif

#ifdef _WIN64
            // On x86-64 place an indirect jump to the detour. It might be far away.
            block_writer.write_indirect_jump(m_detour_address);
#endif

            relocate_instructions(decoded_info.instructions, &block_writer);

            // Write the jump in the original function.
            virtual_protect func_protection(m_target_address, m_decoded_length, protection::read | protection::write | protection::execute);
            hook_writer func_writer(m_target_address);

#ifdef _WIN64
            // On x86-64 jump to our memory then jump to the detour.
            func_writer.write_relative_jump(reinterpret_cast<uintptr_t>(m_block) + m_decoded_length + indirect_jump_size);
#else
            // On x86 jump directly to the detour.
            func_writer.write_relative_jump(m_detour_address);
#endif

            func_writer.write_nops(m_decoded_length - relative_jump_size);

            flush_cache();
            m_attached = true;
        }

        /**
         * @brief Disable the hook.
         */
        void detach()
        {
            using namespace renhook::memory;

            if (!m_attached)
            {
                return;
            }

            suspend_threads threads(m_target_address, m_decoded_length);
            virtual_protect func_protection(m_target_address, m_decoded_length, protection::read | protection::write | protection::execute);

            hook_writer func_writer(m_target_address);
            func_writer.copy_from(m_block, m_decoded_length);

            renhook::zydis zydis;
            auto decoded_info = zydis.decode(reinterpret_cast<uintptr_t>(m_block), executable::get_code_size(), m_decoded_length, m_decoded_length);

            relocate_instructions(decoded_info.instructions, nullptr);

            extern memory_allocator global_allocator;
            global_allocator.free(m_block);

            m_block = nullptr;

            flush_cache();
            m_attached = false;
        }

    protected:

        /**
         * @brief Get the block address.
         *
         * @return The block address.
         *
         * @note This is only used in tests.
         */
        const uint8_t* get_block_address() const
        {
            return m_block;
        }

    private:

        /**
         * @brief Check if the first instruction is a jump, if it is follow it until the real address of the function is found.
         *
         * @param address[in] The address to check.
         *
         * @return The real function's address.
         */
        uintptr_t skip_jumps(uintptr_t address) const
        {
            if (address == 0)
            {
                return 0;
            }

            auto memory = reinterpret_cast<uint8_t*>(address);
            if (memory[0] == 0xEB)
            {
                // We have a 8-bit offset to the target.
                address = reinterpret_cast<uintptr_t>(memory + 2 + *reinterpret_cast<int8_t*>(&memory[1]));
                return skip_jumps(address);
            }
            else if (memory[0] == 0xE9)
            {
                // We have a 32-bit offset to the target.
                address = reinterpret_cast<uintptr_t>(memory + 5 + *reinterpret_cast<int32_t*>(&memory[1]));
                return skip_jumps(address);
            }
            else if (memory[0] == 0xFF && memory[1] == 0x25)
            {
#ifdef _WIN64
                // We have a 32bit offset to the target.
                address = reinterpret_cast<uintptr_t>(memory + 6 + *reinterpret_cast<int32_t*>(&memory[2]));
#else
                // We have an absolute pointer.
                address = *reinterpret_cast<uintptr_t*>(&memory[2]);
#endif

                return skip_jumps(address);
            }
#ifdef _WIN64
            else if (memory[0] == 0x48 && memory[1] == 0xFF && memory[2] == 0x25)
            {
                // We have a 32bit offset to the target.
                address = reinterpret_cast<uintptr_t>(memory + 7 + *reinterpret_cast<int32_t*>(&memory[3]));
                return skip_jumps(address);
            }
#endif

            return address;
        }

        /**
         * @brief Relocate all EIP / RIP instructions.
         *
         * @param instructions[in] An array of decoded instructions.
         * @param block_writer[in] The writer of the block (only necessary if the hook is attached).
         */
        void relocate_instructions(std::vector<zydis::decoded_info::instruction>& instructions, hook_writer* block_writer)
        {
            auto instr_address = m_attached ? m_target_address : reinterpret_cast<uintptr_t>(m_block);
            size_t index = 0;

            for (auto& instr : instructions)
            {
                if (instr.is_relative)
                {
                    // Calculate where the displacement is in instruction.
                    auto disp_address = instr_address + instr.disp.offset;

                    if (instr.add_to_jump_table && instr.disp.size < sizeof(int32_t) * 8)
                    {
#ifdef _WIN64
                        constexpr size_t jmp_size = indirect_jump_size;
                        constexpr size_t jmp_instr_size = 6;
#else
                        constexpr size_t jmp_size = relative_jump_size;
                        constexpr size_t jmp_instr_size = 1;
#endif

                        auto table_address = m_block + m_decoded_length + jmp_size;

#ifdef _WIN64
                        // On x86-64 we have another jump that redirect the target to detour.
                        table_address += indirect_jump_size;
#endif

                        // The address of the jump instruction in jump table for the current instruction.
                        auto jmp_instr_address = table_address + (jmp_size * index);

                        // Create a jump table if it is not attached, else get the real address from jump table.
                        if (!m_attached)
                        {
#ifdef _WIN64
                            block_writer->write_indirect_jump(instr.disp.absolute_address);
#else
                            block_writer->write_relative_jump(instr.disp.absolute_address);
#endif

                            instr.disp.absolute_address = reinterpret_cast<uintptr_t>(jmp_instr_address);
                        }
                        else
                        {
                            instr.disp.absolute_address = *reinterpret_cast<uintptr_t*>(jmp_instr_address + jmp_instr_size);

#ifndef _WIN64
                            // On x86 we have a displacement instead of absolute address.
                            instr.disp.absolute_address += reinterpret_cast<uintptr_t>(jmp_instr_address) + jmp_size;
#endif
                        }
                    }

                    switch (instr.disp.size)
                    {
                        case 8:
                        {
                            *reinterpret_cast<int8_t*>(disp_address) = static_cast<int8_t>(utils::calculate_displacement(instr_address, instr.disp.absolute_address, instr.length));
                            break;
                        }
                        case 16:
                        {
                            *reinterpret_cast<int16_t*>(disp_address) = static_cast<int16_t>(utils::calculate_displacement(instr_address, instr.disp.absolute_address, instr.length));
                            break;
                        }
                        case 32:
                        {
                            *reinterpret_cast<int32_t*>(disp_address) = static_cast<int32_t>(utils::calculate_displacement(instr_address, instr.disp.absolute_address, instr.length));
                            break;
                        }
                        case 64:
                        {
                            *reinterpret_cast<int64_t*>(disp_address) = static_cast<int64_t>(utils::calculate_displacement(instr_address, instr.disp.absolute_address, instr.length));
                            break;
                        }
                    }

                    index++;
                }

                instr_address += instr.length;
            }
        }

        /**
         * @brief Flush instruction cache for the original function and for the codecave.
         */
        void flush_cache() const
        {
            auto current_process = GetCurrentProcess();

            FlushInstructionCache(current_process, m_block, memory::memory_allocator::block_size);
            FlushInstructionCache(current_process, reinterpret_cast<void*>(m_target_address), m_decoded_length);
        }

        uintptr_t m_target_address;
        uintptr_t m_detour_address;

        pattern m_pattern;
        uint8_t m_wildcard;
        size_t m_offset;

        std::string m_module;
        std::string m_function;

        bool m_attached;

        size_t m_decoded_length;
        uint8_t* m_block;
    };
}
#endif
