#include <renhook/exceptions.hpp>

#include <cassert>

renhook::exception::exception(const std::string& what_arg) noexcept
    : std::exception(what_arg.c_str())
{
}

RENHOOK_NODISCARD std::string renhook::exception::create_message(
    const char* function_signature, const char* what_arg,
    std::function<void(std::ostringstream&)> status_code_appender_fn,
    std::function<void(std::ostringstream&)> extra_info_appender_fn)
{
    assert(function_signature);
    assert(what_arg);

    std::ostringstream message;
    message << function_signature << ": " << what_arg;

    if (status_code_appender_fn)
    {
        message << " (";
        status_code_appender_fn(message);
        message << ")";
    }

    if (extra_info_appender_fn)
    {
        message << ": ";
        extra_info_appender_fn(message);
    }

    return message.str();
}

renhook::generic_exception renhook::generic_exception::create(const char* function_signature, const char* what_arg)
{
    return {create_message(function_signature, what_arg)};
}
