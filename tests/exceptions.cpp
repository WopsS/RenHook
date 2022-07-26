#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <renhook/exceptions.hpp>

using Catch::Matchers::Equals;

TEST_CASE("a generic exception should contain the function signature and the message", "[exception]")
{
    auto ex = renhook::generic_exception::create("TEST_CASE(...)", "a test exception");
    REQUIRE_THAT(ex.what(), Equals("TEST_CASE(...): a test exception"));
}
