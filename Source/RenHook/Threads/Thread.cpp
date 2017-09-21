#include <RenHook/RenHook.hpp>
#include <RenHook/Threads/Thread.hpp>

RenHook::Threads::Thread::Thread(const uint32_t Id) 
    : m_thread(nullptr)
    , m_suspended(false)
{
    m_thread = OpenThread(THREAD_SUSPEND_RESUME, false, Id);

    if (m_thread == nullptr)
    {
        throw std::runtime_error("Cannot open the thread");
    }
}

RenHook::Threads::Thread::Thread(Thread&& rhs)
    : m_thread(nullptr)
    , m_suspended(false)
{
    std::swap(m_thread, rhs.m_thread);
    std::swap(m_suspended, rhs.m_suspended);
}

RenHook::Threads::Thread::~Thread()
{
    if (m_suspended == true)
    {
        Resume();
    }

    if (m_thread != nullptr)
    {
        CloseHandle(m_thread);
    }
}

void RenHook::Threads::Thread::Resume()
{
    if (m_thread != nullptr)
    {
        m_suspended = ResumeThread(m_thread) != -1;
    }
}

void RenHook::Threads::Thread::Suspend()
{
    if (m_thread != nullptr)
    {
        m_suspended = SuspendThread(m_thread) != -1;
    }
}