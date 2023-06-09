
# direct-syscall

A simple single header direct syscall wrapper written in C++ with compatibility for x86 and x64 programs.


## Implementation

You could just easily add the single header file into your project, no external dependencies needed.

Compile using MSVC not tested with clang or LLVM yet.


## Usage


```cpp
    INVOKE_SYSCALL( SHORT, NtUserGetAsyncKeyState, VK_INSERT );
```

Another example if you don't want to create a syscall over again.

```cpp
    syscall::create_function syscall_test( SYSCALL_HASH_CT( "NtUserGetAsyncKeyState" ) );

    syscall_test.invoke_call< SHORT >( VK_INSERT );
```

<b>NOTE: </b> This library does not automatically find an exported function without specifying a module with a syscall table.

Another example but for reading process memory.

```cpp
#include "direct_syscall.hpp"
#include <iostream>
#include <memoryapi.h>

int lol = 0;

auto main( int argc, char **argv ) -> int
{
    int read_int = 0;
    int * address = &lol;
    *reinterpret_cast< int* >( address ) = 420;

    size_t sizeof_bytes = 0;

    auto hi = INVOKE_SYSCALL( NTSTATUS,
                              ZwReadVirtualMemory,
                              GetCurrentProcess( ),
                              address,
                              &read_int,
                              sizeof( int ), &sizeof_bytes );

    printf( "%d", read_int );

    return 1;
}
```

As expected, it prints out 420...

## Benchmarking
```cpp
auto main( int argc, char **argv ) -> int
{
    auto start = std::chrono::high_resolution_clock::now( );
    
    int read_int = 0;
    int * address = &lol;
    *reinterpret_cast< int* >( address ) = 420;

    size_t sizeof_bytes = 0;

    auto hi = INVOKE_SYSCALL( NTSTATUS,
                              ZwReadVirtualMemory,
                              GetCurrentProcess( ),
                              address,
                              &read_int,
                              sizeof( int ), &sizeof_bytes );

    auto end = std::chrono::high_resolution_clock::now( );
    auto elapsed_time = duration_cast< std::chrono::microseconds >( end - start ).count( );

    // print out elapsed time after computation.
    std::printf( "ZwReadVirtualMemory completed in %d microseconds\n", elapsed_time );

    return 1;
}
```

Code provided is a simple benchmarking test for "ZwReadVirtualMemory" or "NtReadVirtualMemory" which managed to finish executing within 80 microseconds.

<b>Console output </b>
```
ZwReadVirtualMemory completed in 1ms or 0.80ms
```

## Calling imports
This single header library also includes a macro where you can call exports without imports showing up directly in your import list.
You can call any function like this.

```cpp
INVOKE_LAZY_FN( int, MessageBoxA, NULL, "Hello world.", "MessageBox", MB_OK );
```

## Decompiler output
Compile time string "encryption" included.
![](https://i.imgur.com/XQUspS2.png)

## Issues
If you encounter any issues or crashes within this library make sure to report it to [issues](https://github.com/linux-pe/direct-syscall/issues).