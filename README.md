
# direct-syscall

A simple single header direct syscall wrapper written in C++ with compatibility for x86 and x64 programs.


## Implementation

You could just easily add the single header file into your project, no external dependencies needed.

Compile using MSVC not tested with clang or LLVM yet.


## Usage


Single line example with "NtUserGetAsyncKeyState"
```cpp
    INVOKE_SYSCALL(SHORT, NtUserGetAsyncKeyState, VK_INSERT);
```

Another example if you don't want to create a syscall over again.

```cpp
    syscall::create_function syscall_test(DS_HASH_CT("win32u.dll"), 
                                          DS_HASH_CT("NtUserGetAsyncKeyState"));

    syscall_test.invoke_call<SHORT>(VK_INSERT);
```