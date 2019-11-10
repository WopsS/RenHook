#ifndef RENHOOK_UTILS_H
#define RENHOOK_UTILS_H

#include <cstdint>

namespace renhook
{
    namespace utils
    {
        /**
         * @brief Calculate the displacement between two addresses.
         *
         * @param from[in]              The source.
         * @param to[in]                The destination.
         * @param instruction_size[in]  The size of the instruction at the source (#from).
         *
         * @return The displacement.
         */
        intptr_t calculate_displacement(uintptr_t from, uintptr_t to, size_t instruction_size);
    }
}
#endif
