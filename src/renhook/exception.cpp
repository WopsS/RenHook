#include <renhook/exception.hpp>

renhook::exception::exception(const char* message)
    : runtime_error(message)
{
}

renhook::exception::exception(const std::string& message)
    : runtime_error(message)
{
}

renhook::exception::exception(const std::string& message, uint32_t last_error)
    : runtime_error(message + ", last_error: " + std::to_string(last_error))
{
}
