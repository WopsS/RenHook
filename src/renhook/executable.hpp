#ifndef RENHOOK_EXECUTABLE_H
#define RENHOOK_EXECUTABLE_H

#include <cstdint>

namespace renhook
{
    /**
     * @brief Helper namespace for the executable.
     */
    namespace executable
    {
        /**
         * @brief Returns the base address of the executable.
         *
         * @return The address of the executable.
         */
        uintptr_t get_base_address();

        /**
         * @brief Returns the start of the code section .
         *
         * @return The start of the code section.
         */
        uintptr_t get_code_base_address();

        /**
         * @brief Returns the base address of the executable.
         *
         * @return The address of the executable.
         */
        uintptr_t get_code_end_address();
    }
}
#endif
