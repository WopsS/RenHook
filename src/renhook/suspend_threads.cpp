#include <renhook/suspend_threads.hpp>

#include <chrono>
#include <thread>

#include <Windows.h>
#include <TlHelp32.h>

#include <renhook/exception.hpp>

renhook::suspend_threads::suspend_threads(uintptr_t ip_address, size_t ip_length)
{
    suspend(ip_address, ip_length);
}

renhook::suspend_threads::~suspend_threads()
{
    resume();
}

void renhook::suspend_threads::suspend(uintptr_t ip_address, size_t ip_length)
{
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        throw renhook::exception("cannot take process snapshot", GetLastError());
    }

    THREADENTRY32 entry;
    entry.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(snapshot, &entry))
    {
        throw renhook::exception("cannot retrieves information about the first thread", GetLastError());
    }

    auto process_id = GetCurrentProcessId();
    auto thread_id = GetCurrentThreadId();

    do
    {
        if (entry.th32OwnerProcessID == process_id && entry.th32ThreadID != thread_id)
        {
            auto handle = suspend_thread(entry.th32ThreadID, ip_address, ip_length);
            m_handles.emplace_back(handle);
        }
    } while (Thread32Next(snapshot, &entry));
}

void renhook::suspend_threads::resume()
{
    for (auto handle : m_handles)
    {
        resume_thread(handle);
    }

    m_handles.clear();
}

void* renhook::suspend_threads::suspend_thread(uint32_t id, uintptr_t ip_address, size_t ip_length)
{
    auto handle = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, false, id);
    if (!handle)
    {
        throw renhook::exception("cannot open thread object", GetLastError());
    }

    auto count = SuspendThread(handle);
    if (count == -1)
    {
        CloseHandle(handle);
        throw renhook::exception("cannot suspend thread", GetLastError());
    }

    size_t tries = 1;
    do
    {
        CONTEXT context = { 0 };
        context.ContextFlags = CONTEXT_CONTROL;

        if (!GetThreadContext(handle, &context))
        {
            auto a = GetLastError();
            throw renhook::exception("cannot get thread context", GetLastError());
        }

#ifdef _WIN64
        auto ip = context.Rip;
#else
        auto ip = context.Eip;
#endif

        if (ip_address < ip || ip_address > (ip + ip_length))
        {
            break;
        }

        if (tries <= 3)
        {
            ResumeThread(handle);

            using namespace std::chrono_literals;
            std::this_thread::sleep_for(tries * 50ms);

            SuspendThread(handle);
        }

        tries++;
    } while (tries <= 3);

    return handle;
}

void renhook::suspend_threads::resume_thread(void* handle)
{
    ResumeThread(handle);
    CloseHandle(handle);
}
