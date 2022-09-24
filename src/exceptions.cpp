#include <renhook/exceptions.hpp>

#include <renhook/config.hpp>

renhook::exception::exception(const std::string& what_arg) noexcept
    : std::exception(what_arg.c_str())
{
}

RENHOOK_NODISCARD std::string renhook::exception::create_message(
    const char* function_signature, const char* what_arg,
    const std::function<void(std::ostringstream&)>& status_code_appender_fn,
    const std::function<void(std::ostringstream&)>& extra_info_appender_fn)
{
    RENHOOK_ASSERT(function_signature);
    RENHOOK_ASSERT(what_arg);

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
