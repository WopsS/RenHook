#ifndef RENHOOK_VERSION_H
#define RENHOOK_VERSION_H

#include <cstdint>

namespace renhook
{
    /**
     * @brief The namespace containing library version helpers.
     */
    namespace version
    {
        /**
         * @brief Return the version as string.
         *
         * @return The version as string.
         */
        constexpr const char* as_string()
        {
            return "1.0.0";
        }

        /**
         * @brief Return the version as integer (uint32_t).
         *
         * @return The version as integer (uint32_t).
         */
        constexpr uint32_t as_int()
        {
            return 10000;
        }

        /**
         * @brief Return the major version of the library.
         *
         * @return The major version of the library.
         */
        constexpr uint8_t get_major()
        {
            return 1;
        }

        /**
         * @brief Return the minor version of the library.
         *
         * @return The minor version of the library.
         */
        constexpr uint8_t get_minor()
        {
            return 0;
        }

        /**
         * @brief Return the patch version of the library.
         *
         * @return The patch version of the library.
         */
        constexpr uint8_t get_patch()
        {
            return 0;
        }
    }
}
#endif
