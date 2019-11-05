#pragma once

#include <cstdint>
#include <initializer_list>
#include <vector>

namespace renhook
{
    class pattern
    {
    public:

        pattern(std::vector<uint8_t> pattern);
        pattern(std::initializer_list<uint8_t> pattern);

        ~pattern() = default;

        std::vector<uintptr_t> find(uint8_t wildcard, uint8_t* start = 0, uint8_t* end = 0) const;

    private:

        std::vector<uint8_t> m_pattern;
    };
}