#ifndef RENHOOK_ZYDIS_H
#define RENHOOK_ZYDIS_H

#include <vector>
#include <Zydis/Zydis.h>

namespace renhook
{
    /**
     * @brief A Zydis C++ wrapper.
     */
    class zydis
    {
    public:

        struct instruction
        {
            ZydisDecodedInstruction decoded;

            bool is_relative;

            struct _disp
            {
                uintptr_t absolute_address;
                uint8_t offset;
                uint8_t size;
            } disp;
        };

        zydis();
        ~zydis() = default;

        /**
         * @brief Decode instructions until #minimum_decoded_length is met.
         *
         * @param address[in]                   The start address where to begin the decoding.
         * @param length[in]                    The length of the code section.
         * @param minimum_decoded_length[in]    The minimum length of decoded instructions.
         * @param decoded_length[out]           The actual decoded length.
         *
         * @return An array of decoded instructions.
         */
        std::vector<zydis::instruction> decode(uintptr_t address, size_t length, size_t minimum_decoded_length, size_t& decoded_length);

    private:

        static ZydisDecoder m_decoder;
        static bool m_initialized;
    };
}
#endif
