#include <RenHook/RenHook.hpp>
#include <RenHook/Pattern/Pattern.hpp>
#include <RenHook/ExecutableMeta/ExecutableMeta.hpp>

RenHook::Pattern::Match::Match(const uintptr_t aAddress)
    : m_address(aAddress)
{
}

RenHook::Pattern::Match& RenHook::Pattern::Match::Extract(const size_t aBytes)
{
    m_address = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(m_address) + aBytes);
    return *this;
}

RenHook::Pattern::Pattern(std::string aPattern)
{
    // Remove whitespaces between bytes.
    aPattern.erase(std::remove_if(aPattern.begin(), aPattern.end(), ::isspace), aPattern.end());

    // Make sure the pattern is properly aligned.
    if (aPattern.length() % 2 > 0)
    {
        throw std::invalid_argument("Pattern is not properly aligned");
    }
    else
    {
        // Transform the string pattern to bytes and mark which byte should be ignored.
        std::vector<std::pair<uint8_t, bool>> transformedPattern;

        for (size_t i = 0; i < aPattern.length() / 2; i++)
        {
            std::string byte(aPattern.data() + (i * 2), 2);

            // Should it be ignored?
            if (byte == "??")
            {
                transformedPattern.emplace_back(0x00, false);
            }
            else
            {
                transformedPattern.emplace_back(static_cast<uint8_t>(std::stoi(byte, nullptr, 16)), true);
            }
        }

        auto baseAddress = reinterpret_cast<uint8_t*>(ExecutableMeta::GetBaseAddress());
        auto memorySize = ExecutableMeta::GetEndAddress() - ExecutableMeta::GetBaseAddress();

        // Find the pattern.
        for (size_t i = 0, index = 0; i < memorySize; i++)
        {
            // Check if the current byte should be ignored or if both bytes match.
            if (transformedPattern.at(index).second == false || baseAddress[i] == transformedPattern.at(index).first)
            {
                // If the index match the pattern size, we found it.
                if (++index == transformedPattern.size())
                {
                    // Try to create the hook.
                    m_matches.emplace_back(reinterpret_cast<uintptr_t>(baseAddress + i - transformedPattern.size() + 1));
                    index = 0;
                }
            }
            else if (index > 0)
            {
                i -= index;
                index = 0;
            }
        }
    }
}

RenHook::Pattern& RenHook::Pattern::Expect(const size_t aExpected)
{
    if (m_matches.size() != aExpected)
    {
        throw std::runtime_error("Pattern expected " + std::to_string(aExpected) + (aExpected == 1 ? " match" : " matches") + ", found " + std::to_string(m_matches.size()));
    }

    return *this;
}

RenHook::Pattern::Match& RenHook::Pattern::Get(const size_t aIndex)
{
    if (aIndex == 0)
    {
        return m_matches.at(aIndex);
    }

    return m_matches.at(aIndex - 1);
}
