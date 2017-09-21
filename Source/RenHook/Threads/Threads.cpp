#include <RenHook/RenHook.hpp>
#include <RenHook/Threads/Threads.hpp>

void RenHook::Managers::Threads::Resume()
{
    for (auto& Thread : m_threads)
    {
        Thread.Resume();
    }
}

void RenHook::Managers::Threads::Suspend()
{
    Update();

    for (auto& Thread : m_threads)
    {
        Thread.Suspend();
    }
}

void RenHook::Managers::Threads::Update()
{
    // If we have any thread in the list, clear it.
    if (m_threads.empty() == false)
    {
        m_threads.clear();
    }

    auto Handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (Handle == INVALID_HANDLE_VALUE)
    {
        throw std::runtime_error("Cannot create snapshot for the threads");
    }

    THREADENTRY32 ThreadEntry;
    ThreadEntry.dwSize = sizeof(ThreadEntry);

    if (Thread32First(Handle, &ThreadEntry) == false)
    {
        throw std::runtime_error("Cannot retrive information about the first thread");
    }

    do
    {
        if (ThreadEntry.dwSize >= RTL_SIZEOF_THROUGH_FIELD(THREADENTRY32, th32OwnerProcessID) && ThreadEntry.th32ThreadID != GetCurrentThreadId() && ThreadEntry.th32OwnerProcessID == GetCurrentProcessId())
        {
            m_threads.emplace_back(ThreadEntry.th32ThreadID);
        }
    } while (Thread32Next(Handle, &ThreadEntry));

    CloseHandle(Handle);
}
