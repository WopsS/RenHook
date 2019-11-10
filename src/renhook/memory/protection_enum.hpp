#ifndef RENHOOK_PROTECTION_ENUM_H
#define RENHOOK_PROTECTION_ENUM_H

#include <cstdint>
#include <type_traits>

namespace renhook
{
    namespace memory
    {
        enum class protection : uint8_t
        {
            read = 1 << 0,
            write = 1 << 1,
            execute = 1 << 2
        };

        inline std::underlying_type<protection>::type operator&(protection lhs, protection rhs)
        {
            using underlying_type = std::underlying_type<protection>::type;
            return static_cast<underlying_type>(lhs) & static_cast<underlying_type>(rhs);
        }   

        inline protection operator|(protection lhs, protection rhs)
        {
            using underlying_type = std::underlying_type<protection>::type;
            return static_cast<protection>(static_cast<underlying_type>(lhs) | static_cast<underlying_type>(rhs));
        }
    }
}
#endif
