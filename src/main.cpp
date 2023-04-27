#include <cstdint>
#include <direct_syscall.hpp>
#include <iostream>
#include <windows.h>

auto main( ) -> int {
    LoadLibraryA( "win32u.dll" );

    // example.
    while ( !syscall::invoke_syscall< SHORT >( "win32u.dll", "NtUserGetAsyncKeyState", VK_INSERT ) & 1 )
        printf( "lol\n" );

    return 1;
}