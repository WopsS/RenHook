# RenHook

[![Build status](https://ci.appveyor.com/api/projects/status/8lg179n3y460q4lw?svg=true)](https://ci.appveyor.com/project/WopsS/renhook)

An open-source **x64** hooking library for **Windows**.

## Build instructions

### Requirements

* **[PREMAKE 5](https://github.com/premake/premake-core/releases)**.

### Windows

1. Download and install **[Visual Studio 2017 Community Edition](https://www.visualstudio.com/)** or a higher version.
2. Clone this repository.
3. Extract the content of **[PREMAKE 5](https://github.com/premake/premake-core/releases)** into **Premake** directory.
11. Go to the **Premake** directory and run **GenerateVisualStudioProjects.bat**.
12. Open the solution (**RenHook.sln**) located in **Premake/Projects** directory.
13. Build the projects.

## Examples

### Basic usage

```cpp
#include <RenHook/RenHook.hpp>

int IsDebuggerPresentFunction()
{
    return 0;
}

int main()
{
    RenHook::Hook::Create(L"kernel32", L"IsDebuggerPresent", &IsDebuggerPresentFunction);
    std::cout << IsDebuggerPresent() << std::endl;

    return 0;
}
```

### Trampolines

```cpp
#include <RenHook/RenHook.hpp>

MessageBoxWFunction(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    auto Hook = RenHook::Hook::Get(L"user32", L"MessageBoxW");

    using MessageBoxW_t = int(*)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
    return Hook->Call<MessageBoxW_t>(hWnd, L"Hello from the hook!", L"Hooked MessageBoxW", MB_OK);
}

int main()
{
    RenHook::Hook::Create(L"user32", L"MessageBoxW", &MessageBoxWFunction);
    MessageBoxW(nullptr, L"Hello", L"MessageBoxW", MB_OK);

    return 0;
}
```

### Trampolines (with [std::shared_ptr](http://en.cppreference.com/w/cpp/memory/shared_ptr))

```cpp
#include <RenHook/RenHook.hpp>

std::shared_ptr<RenHook::Hook> MessageBoxWHook;

int MessageBoxWFunction(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    using MessageBoxW_t = int(WINAPI*)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
    return MessageBoxWHook->Call<int, MessageBoxW_t>(hWnd, L"Hello from the hook!", L"Hooked MessageBoxW", MB_OK);
}

int main()
{
    MessageBoxWHook = RenHook::Hook::Create(L"user32", L"MessageBoxW", &MessageBoxWFunction);
    MessageBoxW(nullptr, L"Hello", L"MessageBoxW", MB_OK);

    return 0;
}
```