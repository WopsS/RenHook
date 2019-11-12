# RenHook

[![Build Status](https://dev.azure.com/wopss/RenHook/_apis/build/status/WopsS.RenHook?branchName=master)](https://dev.azure.com/wopss/RenHook/_build/latest?definitionId=5&branchName=master)
[![Build status](https://ci.appveyor.com/api/projects/status/8lg179n3y460q4lw?svg=true)](https://ci.appveyor.com/project/WopsS/renhook)

An open-source **x86 / x86-64** hooking library for **Windows**.

## Features

* Supports x86 and x86-64 (uses [Zydis](https://github.com/zyantific/zydis) as diassembler)
* Completely written in C++11
* Safe and easy to use
* Hooking methods
  * **Inline hook** - Patches the prologue of a function to redirect its code flow, also allocates a trampoline to that can be used to execute the original function.

## Quick examples

### Hooking by address

```cpp
#include <Windows.h>
#include <renhook/renhook.hpp>

void func_detour();

using func_t = void(*)();
renhook::inline_hook<func_t> func_hook(0x14000000, &func_detour);

void func_detour()
{
    OutputDebugStringA("Hello from the hook!\n");
    func_hook();
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow)
{
    func_hook.attach();
    func_hook();
    func_hook.detach();

    func_hook();
    return 0;
}
```

### Hooking by pattern

```cpp
#include <Windows.h>
#include <renhook/renhook.hpp>

void func_detour();

using func_t = void(*)();
renhook::inline_hook<func_t> func_hook({ 0x89, 0x79, 0xF8, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC }, &func_detour, 0xCC, 3);

void func_detour()
{
    OutputDebugStringA("Hello from the hook!\n");
    func_hook();
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow)
{
    func_hook.attach();
    func_hook();
    func_hook.detach();

    func_hook();
    return 0;
}
```

### Hooking a function from a module

```cpp
#include <Windows.h>
#include <renhook/renhook.hpp>

int WINAPI msgbox_detour(HWND wnd, LPCWSTR text, LPCWSTR caption, UINT type);

using MessageBoxW_t = int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT);
renhook::inline_hook<MessageBoxW_t> msgbox_hook("user32", "MessageBoxW", &msgbox_detour);

int WINAPI msgbox_detour(HWND wnd, LPCWSTR text, LPCWSTR caption, UINT type)
{
    return msgbox_hook(wnd, L"Hello from the hook!", L"RenHook", MB_OK | MB_ICONINFORMATION);
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow)
{
    msgbox_hook.attach();
    MessageBoxW(nullptr, L"Hello", L"Message", MB_OK);
    msgbox_hook.detach();

    MessageBoxW(nullptr, L"Hello", L"Message", MB_OK);
    return 0;
}
```

## Build instructions

### Requirements

* **[CMake 3.8+](https://cmake.org/)**.

### Windows

1. Download and install **[Visual Studio 2019 Community Edition](https://www.visualstudio.com/)** or a higher version.
2. Download and install the **[Requirements](#requirements)**.
3. Clone this repository.
4. Clone the dependencies (`git submodule update --init --recursive`).
5. Create a directory named `build` and run **[CMake](https://cmake.org/)** in it.
6. Open the solution (**RenHook.sln**) located in **build** directory.
7. Build the projects.
