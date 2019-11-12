#ifndef RENHOOK_HOOK_WRITER_H
#define RENHOOK_HOOK_WRITER_H

#include <cstdint>

namespace renhook
{
    /**
     * @brief Helper class for writing a codecave.
     */
    class hook_writer
    {
    public:

        /**
         * @brief Construct a hook writer.
         *
         * @param address[in] The address where to write.
         */
        hook_writer(uint8_t* address);

        /**
         * @copydoc renhook::hook_writer::hook_writer(uint8_t*)
         */
        hook_writer(uintptr_t address);

        ~hook_writer() = default;

        /**
         * @brief Copy bytes to the codecave.
         *
         * @param address[in]   The address from where to copy.
         * @param length[in]    The length.
         */
        void copy_from(uint8_t* address, size_t length);

        /**
         * @copydoc renhook::hook_writer::copy_from(uint8_t*, size_t)
         */
        void copy_from(uintptr_t address, size_t length);

#ifdef _WIN64
        /**
         * @brief Write an indirect (14 bytes) jump to #target_address.
         *
         * @param target_address[in] The address where the jump is.
         */
        void write_indirect_jump(uintptr_t target_address);
#endif

        /**
         * @brief Write a relative (5 bytes) jump to #target_address.
         *
         * @param target_address[in] The address where the jump is.
         */
        void write_relative_jump(uintptr_t target_address);

        /**
         * @brief Write NOP.
         *
         * @param size[in] The number of NOPs.
         */
        void write_nops(size_t size);

    private:

        uint8_t* m_address;
    };
}
#endif
