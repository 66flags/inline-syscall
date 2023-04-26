#include <cstdint>
#include <iostream>
#include <windows.h>
#include <direct_syscall.hpp>

auto main( ) -> int
{
    LoadLibraryA( "ntdll.dll" );

    return 1;
}