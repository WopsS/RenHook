#include <RenHook/RenHook.hpp>
#include <RenHook/Threads/Threads.hpp>

void RenHook::Managers::Threads::Resume()
{
    for (auto& thread : m_threads)
    {
        thread.Resume();
    }
}

void RenHook::Managers::Threads::Suspend()
{
    Update();

    for (auto& thread : m_threads)
    {
        thread.Suspend();
    }
}

void RenHook::Managers::Threads::Update()
{
    // If we have any thread in the list, clear it.
    if (m_threads.empty() == false)
    {
        m_threads.clear();
    }

    auto handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (handle == INVALID_HANDLE_VALUE)
    {
        throw std::runtime_error("Cannot create snapshot for the threads");
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(threadEntry);

    if (Thread32First(handle, &threadEntry) == false)
    {
        throw std::runtime_error("Cannot retrive information about the first thread");
    }

    do
    {
        if (threadEntry.dwSize >= RTL_SIZEOF_THROUGH_FIELD(THREADENTRY32, th32OwnerProcessID) && threadEntry.th32ThreadID != GetCurrentThreadId() && threadEntry.th32OwnerProcessID == GetCurrentProcessId())
        {
            m_threads.emplace_back(threadEntry.th32ThreadID);
        }
    } while (Thread32Next(handle, &threadEntry));

    CloseHandle(handle);
}
