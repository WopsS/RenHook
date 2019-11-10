#ifndef RENHOOK_MEMORY_UTILS_H
#define RENHOOK_MEMORY_UTILS_H

#include <type_traits>

namespace renhook
{
    namespace memory
    {
        namespace utils
        {
            /**
             * @brief Return the aligned down number by the specified #alignment.
             *
             * @tparam T            The type of the numbers.
             * @param[in] number    The number to be aligned.
             * @param[in] alignment The alignment.
             *
             * @return The number aligned by the specified #alignment.
             */
            template<typename T, typename = typename std::enable_if<std::is_integral<T>::value, T>::type>
            inline T align_down(T number, T alignment)
            {
                return number & ~(alignment - 1);
            }

            /**
             * @brief Return the aligned up number by the specified #alignment.
             *
             * @tparam T            The type of the numbers.
             * @param[in] number    The number to be aligned.
             * @param[in] alignment The alignment.
             *
             * @return The number aligned by the specified #alignment.
             */
            template<typename T, typename = typename std::enable_if<std::is_integral<T>::value, T>::type>
            inline T align_up(T number, T alignment)
            {
                return align_down(number + (alignment - 1), alignment);
            }
        }
    }
}
#endif
