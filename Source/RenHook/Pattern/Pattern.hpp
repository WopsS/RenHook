#pragma once

namespace RenHook
{
    class Pattern
    {
    public:

        class Match
        {
        public:

            Match(const uintptr_t Address);
            ~Match() = default;

            Match& Extract(const size_t Bytes);

            template<typename T>
            T To()
            {
                if constexpr (std::is_same_v<uintptr_t, T> == true)
                {
                    return m_address;
                }
                else if constexpr (std::is_integral_v<T> == true)
                {
                    return static_cast<T>(m_address);
                }
                else
                {
                    return reinterpret_cast<T>(m_address);
                }
            }

        private:

            uintptr_t m_address;
        };

        Pattern(std::string Pattern);
        ~Pattern() = default;

        Pattern& Expect(const size_t Expected);

        Match& Get(const size_t Index);

    private:

        std::vector<Match> m_matches;
    };
}