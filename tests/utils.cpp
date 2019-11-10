#include <catch2/catch.hpp>

#include <renhook/utils.hpp>

TEST_CASE("utils")
{
    REQUIRE(renhook::utils::calculate_displacement(100, 50, 5) == -55);
    REQUIRE(renhook::utils::calculate_displacement(30, 60, 5) == 25);
}
