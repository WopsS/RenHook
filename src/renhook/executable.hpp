#pragma once

#include <cstdint>

namespace renhook
{
    namespace executable
    {
        uintptr_t get_base_address();

        uintptr_t get_code_base_address();
        uintptr_t get_code_end_address();
    }
}