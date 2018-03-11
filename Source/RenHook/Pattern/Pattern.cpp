#include <RenHook/RenHook.hpp>
#include <RenHook/Pattern/Pattern.hpp>
#include <RenHook/ExecutableMeta/ExecutableMeta.hpp>

RenHook::Pattern::Match::Match(const uintptr_t Address)
    : m_address(Address)
{
}

RenHook::Pattern::Match& RenHook::Pattern::Match::Extract(const size_t Bytes)
{
    m_address = reinterpret_cast<uintptr_t>(reinterpret_cast<char*>(m_address) + Bytes);
    return *this;
}

RenHook::Pattern::Pattern(std::string Pattern)
{
    // Remove whitespaces between bytes.
    Pattern.erase(std::remove_if(Pattern.begin(), Pattern.end(), ::isspace), Pattern.end());

    // Make sure the pattern is properly aligned.
    if (Pattern.length() % 2 > 0)
    {
        throw std::invalid_argument("Pattern is not properly aligned");
    }
    else
    {
        // Transform the string pattern to bytes and mark which byte should be ignored.
        std::vector<std::pair<uint8_t, bool>> TransformedPattern;

        for (size_t i = 0; i < Pattern.length() / 2; i++)
        {
            std::string Byte(Pattern.data() + (i * 2), 2);

            // Should it be ignored?
            if (Byte == "??")
            {
                TransformedPattern.emplace_back(0x00, false);
            }
            else
            {
                TransformedPattern.emplace_back(static_cast<uint8_t>(std::stoi(Byte, nullptr, 16)), true);
            }
        }

        auto BaseAddress = reinterpret_cast<uint8_t*>(ExecutableMeta::GetBaseAddress());
        auto MemorySize = ExecutableMeta::GetEndAddress() - ExecutableMeta::GetBaseAddress();

        // Find the pattern.
        for (size_t i = 0, Index = 0; i < MemorySize; i++)
        {
            // Check if the current byte should be ignored or if both bytes match.
            if (TransformedPattern.at(Index).second == false || BaseAddress[i] == TransformedPattern.at(Index).first)
            {
                // If the index match the pattern size, we found it.
                if (++Index == TransformedPattern.size())
                {
                    // Try to create the hook.
                    m_matches.emplace_back(reinterpret_cast<uintptr_t>(BaseAddress + i - TransformedPattern.size() + 1));
                    Index = 0;
                }
            }
            else if (Index > 0)
            {
                i -= Index;
                Index = 0;
            }
        }
    }
}

RenHook::Pattern& RenHook::Pattern::Expect(const size_t Expected)
{
    if (m_matches.size() != Expected)
    {
        throw std::runtime_error("Pattern expected " + std::to_string(Expected) + (Expected == 1 ? " match" : " matches") + ", found " + std::to_string(m_matches.size()));
    }

    return *this;
}

RenHook::Pattern::Match& RenHook::Pattern::Get(const size_t Index)
{
    if (Index == 0)
    {
        return m_matches.at(Index);
    }

    return m_matches.at(Index - 1);
}
