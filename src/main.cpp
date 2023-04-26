#include <cstdint>
#include <iostream>
#include <windows.h>
#include <direct_syscall.hpp>

auto main( ) -> int
{
    LoadLibraryA( "ntdll.dll" );

    auto test1 = direct_syscall::utils::get_module_handle< void* >( nullptr );

    std::printf( "0x%p\n", test1 );

    auto test2 = ( void* )GetModuleHandle( nullptr );

    std::printf( "0x%p\n", test2 );

    return 1;
}