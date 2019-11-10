#ifndef RENHOOK_PATTERN_H
#define RENHOOK_PATTERN_H

#include <cstdint>
#include <initializer_list>
#include <vector>

namespace renhook
{
    /**
     * @brief The pattern class.
     */
    class pattern
    {
    public:

        /**
         * @brief Construct a new empty pattern.
         */
        pattern() = default;

        /**
         * @brief Construct a new pattern.
         *
         * @param[in] pattern The pattern.
         */
        pattern(std::vector<uint8_t> pattern);

        /**
         * @brief Construct a new pattern.
         *
         * @param[in] pattern The pattern.
         */
        pattern(std::initializer_list<uint8_t> pattern);

        ~pattern() = default;

        /**
         * @brief Checks if the pattern is empty.
         *
         * @return true if the pattern is empty.
         * @return false otherwise.
         */
        bool empty() const;

        /**
         * @brief Return the size of the pattern.
         *
         * @return The size of the patter.
         */
        size_t size() const;

        /**
         * @brief Return an array of addresses where the pattern was found.
         *
         * @param[in] wildcard  The wildcard.
         * @param[in] start     The start address. If value is \b 0 then \ref renhook::executable::get_code_base_address() is used.
         * @param[in] end       The end address. If value is \b 0 then \ref renhook::executable::get_code_end_address() is used.
         *
         * @return An array of addresses where the pattern was found.
         *
         * @par Examples
         *
         * The following
         *
         * @code{.cpp}
         * renhook::pattern pattern({ 0x48, 0x89, 0x5C, 0x24, 0x08 });
         * auto addresses = pattern.find(0xCC);
         *
         * std::cout << addresses.size() << " matches found\n";
         *
         * for (auto& address : addresses)
         * {
         *      std::cout << "Pattern found at " << std::hex << address << '\n';
         * }
         * @endcode
         *
         * is equivalent with
         *
         * @code{.cpp}
         * renhook::pattern pattern({ 0x48, 0x89, 0x5C, 0x24, 0x08 });
         * auto addresses = pattern.find(0xCC, renhook::executable::get_code_base_address(), renhook::executable::get_code_end_address());
         *
         * std::cout << addresses.size() << " matches found\n";
         *
         * for (auto& address : addresses)
         * {
         *      std::cout << "Pattern found at " << std::hex << address << '\n';
         * }
         * @endcode
         */
        std::vector<uintptr_t> find(uint8_t wildcard, uint8_t* start = 0, uint8_t* end = 0) const;

    private:

        /**
         * @brief Pattern to search.
         */
        std::vector<uint8_t> m_pattern;
    };
}
#endif
