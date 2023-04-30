
# direct-syscall

A simple single header direct syscall wrapper written in C++ with compatibility for x86 and x64 programs.


## Implementation

You could just easily add the single header file into your project, no external dependencies needed.

Compile using MSVC not tested with clang or LLVM yet.


## Usage


```cpp
    INVOKE_SYSCALL_SIMPLE( SHORT, NtUserGetAsyncKeyState, VK_INSERT );
```
<b>NOTE: </b> This library does not automatically find an exported function without specifying a module with a syscall table.

Another example but for reading process memory.

```cpp
#include <direct_syscall.hpp>
#include <iostream>
#include <memoryapi.h>

int lol = 0;

auto main( int argc, char **argv ) -> int
{
    int read_int = 0;
    int * address = &lol;
    *reinterpret_cast< int* >( address ) = 420;

    size_t sizeof_bytes = 0;

    auto hi = INVOKE_SYSCALL_SIMPLE( NTSTATUS,
                                     "ntdll.dll",
                                     ZwReadVirtualMemory,
                                     GetCurrentProcess( ),
                                     address,
                                     &read_int,
                                     sizeof( int ), &sizeof_bytes );

    printf( "%d", read_int );

    return 1;
}
```

Another example if you don't want to create a syscall over again.

```cpp
    syscall::create_function syscall_test( DS_HASH_CT( "win32u.dll" ), 
                                           DS_HASH_CT( "NtUserGetAsyncKeyState" ) );

    syscall_test.invoke_call< SHORT >( VK_INSERT );
```

## Decompiler output
Compile time string "encryption" included.
![](https://i.imgur.com/XQUspS2.png)