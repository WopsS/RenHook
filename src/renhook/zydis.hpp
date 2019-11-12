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

        struct decoded_info
        {
            struct instruction
            {
                struct displacement
                {
                    uintptr_t absolute_address;
                    uint8_t offset;

                    
                    /**
                    * @brief The size of displacement in bits.
                    */
                    uint8_t size;
                };

                uint8_t length;

                bool is_relative;
                bool add_to_jump_table;

                displacement disp;
            };

            std::vector<instruction> instructions;

            uintptr_t lowest_relative_address;
            uintptr_t highest_relative_address;
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
         * @return A structure containing the decoded information.
         */
        const decoded_info decode(uintptr_t address, size_t length, size_t minimum_decoded_length, size_t& decoded_length) const;

    private:

        void get_absolute_address(uintptr_t instr_address, const ZydisDecodedInstruction& decoded_instr, decoded_info::instruction::displacement& displacement) const;

        static ZydisDecoder m_decoder;
        static bool m_initialized;
    };
}
#endif
