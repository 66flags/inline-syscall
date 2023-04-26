#include <cstdint>
#include <iostream>
#include <windows.h>
#include <direct_syscall.hpp>

auto main( ) -> int
{
    LoadLibraryA( "win32u.dll" );

    auto id = direct_syscall::get_syscall_id( "win32u.dll", "NtUserGetAsyncKeyState" );

    std::printf( "%d", id );

    return 1;
}