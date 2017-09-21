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

RenHook::Pattern::Pattern(const std::wstring& Pattern)
{
    // Make sure the pattern is properly aligned.
    if (Pattern.length() % 2 > 0)
    {
        LOG_ERROR << L"Pattern " << std::quoted(Pattern) << L" is not properly aligned" << LOG_LINE_SEPARATOR;
    }
    else
    {
#ifdef _DEBUG
        auto StartClock = std::chrono::high_resolution_clock::now();

        LOG_WARNING << L"Be careful, pattern search in debug configuration is slow because \"Optimization\" is disabled and \"Basic Runtime Checks\" is on" << LOG_LINE_SEPARATOR;
#endif

        // Transform the string pattern to bytes and mark which byte should be ignored.
        std::vector<std::pair<uint8_t, bool>> TransformedPattern;

        for (size_t i = 0; i < Pattern.length() / 2; i++)
        {
            std::wstring Byte(Pattern.data() + (i * 2), 2);

            // Should it be ignored?
            if (Byte == L"??")
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
                    auto Address = reinterpret_cast<uintptr_t>(BaseAddress + i - TransformedPattern.size() + 1);

#ifdef _DEBUG
                    LOG_DEBUG << L"Pattern " << std::quoted(Pattern) << L" found at " << std::hex << std::showbase << Address << std::dec << L" in " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - StartClock).count() << L" milliseconds" << LOG_LINE_SEPARATOR;
#endif

                    m_matches.emplace_back(Address);
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

RenHook::Pattern& RenHook::Pattern::Except(const size_t Excepted)
{
    if (m_matches.size() != Excepted)
    {
        LOG_ERROR << L"Pattern excepted " << std::to_wstring(Excepted) << (Excepted == 1 ? L" match" : L" matches") << L", found " << std::to_wstring(m_matches.size());
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
