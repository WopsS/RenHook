#pragma once

namespace RenHook::Threads
{
    class Thread
    {
    public:

        Thread(uint32_t aId);
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