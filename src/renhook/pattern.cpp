#include <renhook/pattern.hpp>

#include <algorithm>
#include <renhook/executable.hpp>
#include <renhook/exception.hpp>

renhook::pattern::pattern(std::vector<uint8_t> pattern)
    : m_pattern(std::move(pattern))
{
}

renhook::pattern::pattern(std::initializer_list<uint8_t> pattern)
    : m_pattern(pattern)
{
}

bool renhook::pattern::empty() const
{
    return m_pattern.empty();
}

size_t renhook::pattern::size() const
{
    return m_pattern.size();
}

std::vector<uintptr_t> renhook::pattern::find(uint8_t wildcard, uint8_t* start, uint8_t* end) const
{
    if (empty())
    {
        throw renhook::exception("pattern is empty");
    }

    if (start == 0)
    {
        start = reinterpret_cast<uint8_t*>(executable::get_code_base_address());
    }

    if (end == 0)
    {
        end = reinterpret_cast<uint8_t*>(executable::get_code_end_address());
    }

    std::vector<uintptr_t> offsets;

    while (true)
    {
        auto offset = std::search(start, end, m_pattern.begin(), m_pattern.end(), [&wildcard](uint8_t memory_value, uint8_t pattern_value)
        {
            return memory_value == pattern_value || pattern_value == wildcard;
        });

        // Did we found something?
        if (offset >= end)
        {
            break;
        }

        offsets.emplace_back(reinterpret_cast<uintptr_t>(offset));
        start = offset + m_pattern.size();
    }

    return offsets;
}
