#ifndef RENHOOK_SUSPEND_THREADS_H
#define RENHOOK_SUSPEND_THREADS_H

#include <cstdint>
#include <vector>

namespace renhook
{
    /**
     * @brief Temporary suspend all threads, except the running one, in a RAII fashion.
     */
    class suspend_threads
    {
    public:

        /**
         * @brief Suspends all threads and make sure their instruction pointer is not in range.
         *
         * @param ip_address[in]    The address of the instruction pointer.
         * @param ip_length[in]     The length of the instruction pointer.
         */
        suspend_threads(uintptr_t ip_address, size_t ip_length);

        suspend_threads(suspend_threads&) = delete;
        suspend_threads(suspend_threads&&) = delete;

        ~suspend_threads();

        suspend_threads& operator=(const suspend_threads&) = delete;
        suspend_threads& operator=(suspend_threads&&) = delete;

    private:

        void suspend(uintptr_t ip_address, size_t ip_length);
        void resume();

        void* suspend_thread(uint32_t id, uintptr_t ip_address, size_t ip_length);
        void resume_thread(void* handle);

        std::vector<void*> m_handles;
    };
}
#endif
