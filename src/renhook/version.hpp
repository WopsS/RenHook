#pragma once

#include <cstdint>

namespace renhook
{
    namespace version
    {
        constexpr const char* as_string()
        {
            return "1.0.0";
        }

        constexpr uint32_t as_int()
        {
            return 10000;
        }

        constexpr uint8_t get_major()
        {
            return 1;
        }

        constexpr uint8_t get_minor()
        {
            return 0;
        }

        constexpr uint8_t get_patch()
        {
            return 0;
        }
    }
}
