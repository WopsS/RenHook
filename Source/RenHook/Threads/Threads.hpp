#pragma once

#include <RenHook/Threads/Thread.hpp>

namespace RenHook::Managers
{
    class Threads
    {
    public:

        Threads() = default;
        ~Threads() = default;

        void Resume();

        void Suspend();

    private:

        void Update();

        std::vector<RenHook::Threads::Thread> m_threads;

    };
}