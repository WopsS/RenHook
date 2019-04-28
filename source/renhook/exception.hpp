#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

namespace renhook
{
    class exception : public std::runtime_error
    {
    public:

        exception(const char* message);

        exception(const std::string& message);
        exception(const std::string& message, uint32_t last_error);

        ~exception() = default;
    };
}