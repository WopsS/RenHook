#ifndef RENHOOK_EXCEPTION_H
#define RENHOOK_EXCEPTION_H

#include <cstdint>
#include <stdexcept>
#include <string>

namespace renhook
{
    /**
     * @brief The general exception of the library.
     */
    class exception : public std::runtime_error
    {
    public:

        /**
         * @brief Construct a new exception.
         *
         * @param[in] message The message.
         */
        exception(const char* message);

        /**
         * @brief Construct a new exception.
         *
         * @param[in] message The message.
         */
        exception(const std::string& message);

        /**
         * @brief Construct a new exception.
         *
         * @param[in] message       The message.
         * @param[in] last_error    The error code returned by <a href="https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror">GetLastError</a>.
         */
        exception(const std::string& message, uint32_t last_error);

        ~exception() = default;
    };
}
#endif
