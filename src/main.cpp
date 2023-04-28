#include <cstdint>
#include <direct_syscall.hpp>
#include <iostream>
#include <windows.h>

auto main( ) -> int {
    LoadLibraryA( "win32u.dll" );

    {
        syscall::create_function NtUserGetAsyncKeyState( "win32u.dll", "NtUserGetAsyncKeyState" );

        while ( !NtUserGetAsyncKeyState.invoke< SHORT >( VK_INSERT ) )
            std::printf( "lol\n" );
    }

    return 1;
}