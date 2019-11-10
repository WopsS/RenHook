#include <catch2/catch.hpp>

#include <atomic>
#include <thread>
#include <Windows.h>

#include <renhook/suspend_threads.hpp>

namespace
{
    std::atomic_bool running = true;
    void suspend_threads_test()
    {
        while (running)
        {
        }
    }
}

TEST_CASE("suspend_threads")
{
    std::thread thread(suspend_threads_test);
    auto handle = thread.native_handle();

    {
        renhook::suspend_threads _(0, 0);

        auto count = SuspendThread(handle);
        ResumeThread(handle);

        REQUIRE(count > 0);

        running = false;
    }

    auto count = SuspendThread(handle);
    ResumeThread(handle);

    REQUIRE(count == 0);

    thread.join();
}
