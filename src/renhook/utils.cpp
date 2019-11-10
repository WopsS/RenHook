#include <renhook/utils.hpp>

intptr_t renhook::utils::calculate_displacement(uintptr_t from, uintptr_t to, size_t instruction_size)
{
    if (to < from)
    {
        return 0 - (from - to) - instruction_size;
    }

    return to - (from + instruction_size);
}
