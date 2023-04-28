#include <windows.h>
#include <cstdint>
#include <direct_syscall.hpp>

auto main( ) -> int {
    while ( !syscall::invoke_simple< SHORT >( "NtUserGetAsyncKeyState", VK_INSERT ) )
        std::printf( "NtUserGetAsyncKeyState\n" );

    return 1;
}