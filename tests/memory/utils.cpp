#include <catch2/catch.hpp>
#include <renhook/memory/utils.hpp>

TEST_CASE("memory::utils", "[memory][utils]")
{
    constexpr size_t granularity = 128;

    SECTION("align up")
    {
        REQUIRE(renhook::memory::utils::align_up<size_t>(1, granularity) == 128);
        REQUIRE(renhook::memory::utils::align_up<size_t>(127, granularity) == 128);
        REQUIRE(renhook::memory::utils::align_up<size_t>(128, granularity) == 128);

        REQUIRE(renhook::memory::utils::align_up<size_t>(129, granularity) == 256);
        REQUIRE(renhook::memory::utils::align_up<size_t>(200, granularity) == 256);
        REQUIRE(renhook::memory::utils::align_up<size_t>(240, granularity) == 256);

        REQUIRE(renhook::memory::utils::align_up<size_t>(257, granularity) == 384);
    }
    SECTION("align down")
    {
        REQUIRE(renhook::memory::utils::align_down<size_t>(1, granularity) == 0);
        REQUIRE(renhook::memory::utils::align_down<size_t>(30, granularity) == 0);
        REQUIRE(renhook::memory::utils::align_down<size_t>(127, granularity) == 0);

        REQUIRE(renhook::memory::utils::align_down<size_t>(128, granularity) == 128);
        REQUIRE(renhook::memory::utils::align_down<size_t>(129, granularity) == 128);
        REQUIRE(renhook::memory::utils::align_down<size_t>(240, granularity) == 128);

        REQUIRE(renhook::memory::utils::align_down<size_t>(256, granularity) == 256);
    }
}