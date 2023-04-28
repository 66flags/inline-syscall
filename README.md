
# direct-syscall

A simple single header direct syscall wrapper written in C++ with compatibility for x86 and x64 programs.


## Implementation

You could just easily add the single header file into your project, no external dependencies needed.

Compile using MSVC not tested with clang or LLVM yet.


## Usage


Single line example with "NtUserGetAsyncKeyState"
```cpp
    syscall::invoke_simple<SHORT>("NtUserGetAsyncKeyState", VK_INSERT);
```

Another example if you don't want to create a syscall again.

```cpp
    syscall::create_function syscall_test("win32u.dll", "NtUserGetAsyncKeyState");
    
    syscall_test.invoke<SHORT>(VK_INSERT);
```