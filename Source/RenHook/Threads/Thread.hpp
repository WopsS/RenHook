#pragma once

namespace RenHook
{
    namespace Threads
    {
        class Thread
        {
        public:

            Thread(const uint32_t Id);
            Thread(const Thread&) = delete;
            Thread(Thread&& rhs);

            ~Thread();

            Thread& operator=(const Thread&) = delete;

            Thread& operator=(Thread&&) = delete;

            void Resume();

            void Suspend();

        private:

            void* m_thread;

            bool m_suspended;
        };
    }
}