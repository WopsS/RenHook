#pragma once

#include <exception>
#include <functional>
#include <sstream>
#include <string>

#include <renhook/detail/core.hpp>

namespace renhook
{
class RENHOOK_NODISCARD exception : public std::exception
{
public:
    exception(const exception&) noexcept = default;
    exception& operator=(const exception&) noexcept = default;

    virtual ~exception() noexcept = default;

protected:
    exception(const std::string& what_arg) noexcept;

    RENHOOK_NODISCARD static std::string create_message(
        const char* function_signature, const char* what_arg,
        const std::function<void(std::ostringstream&)>& status_code_appender_fn = {},
        const std::function<void(std::ostringstream&)>& extra_info_appender_fn = {});
};

class RENHOOK_NODISCARD generic_exception : public exception
{
public:
    static generic_exception create(const char* function_signature, const char* what_arg);

    generic_exception(const generic_exception&) noexcept = default;
    generic_exception& operator=(const generic_exception&) noexcept = default;

    virtual ~generic_exception() noexcept = default;

private:
    using exception::exception;
};
} // namespace renhook
