/*
    Copyright (C) 2023 hypnotic

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef DIRECT_SYSCALL_HPP
#define DIRECT_SYSCALL_HPP

#include <cstdint>
#include <string>
#include <windows.h>

#ifndef SYSCALL_NO_FORCEINLINE
#if defined( _MSC_VER )
#define SYSCALL_FORCEINLINE __forceinline
#endif
#else
#define SYSCALL_FORCEINLINE inline
#endif

#include <intrin.h>

namespace syscall {
    namespace win {
        typedef enum _LDR_DLL_LOAD_REASON {
            LoadReasonStaticDependency,
            LoadReasonStaticForwarderDependency,
            LoadReasonDynamicForwarderDependency,
            LoadReasonDelayloadDependency,
            LoadReasonDynamicLoad,
            LoadReasonAsImageLoad,
            LoadReasonAsDataLoad,
            LoadReasonEnclavePrimary,// since REDSTONE3
            LoadReasonEnclaveDependency,
            LoadReasonPatchImage,// since WIN11
            LoadReasonUnknown = -1
        } LDR_DLL_LOAD_REASON,
                *PLDR_DLL_LOAD_REASON;

        struct UNICODE_STRING {
            uint16_t Length;
            uint16_t MaximumLength;
            wchar_t *Buffer;
        };

        typedef struct _PEB_LDR_DATA {
            ULONG Length;
            BOOLEAN Initialized;
            PVOID SsHandle;
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
        } PEB_LDR_DATA, *PPEB_LDR_DATA;

        typedef struct _LDR_MODULE {
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
            PVOID BaseAddress;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
            ULONG Flags;
            SHORT LoadCount;
            SHORT TlsIndex;
            LIST_ENTRY HashTableEntry;
            ULONG TimeDateStamp;

        } LDR_MODULE, *PLDR_MODULE;

        typedef struct _PEB_FREE_BLOCK {
            _PEB_FREE_BLOCK *Next;
            ULONG Size;
        } PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

        typedef struct _RTL_DRIVE_LETTER_CURDIR {
            USHORT Flags;
            USHORT Length;
            ULONG TimeStamp;
            UNICODE_STRING DosPath;
        } RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

        typedef struct _RTL_USER_PROCESS_PARAMETERS {
            ULONG MaximumLength;
            ULONG Length;
            ULONG Flags;
            ULONG DebugFlags;
            PVOID ConsoleHandle;
            ULONG ConsoleFlags;
            HANDLE StdInputHandle;
            HANDLE StdOutputHandle;
            HANDLE StdErrorHandle;
            UNICODE_STRING CurrentDirectoryPath;
            HANDLE CurrentDirectoryHandle;
            UNICODE_STRING DllPath;
            UNICODE_STRING ImagePathName;
            UNICODE_STRING CommandLine;
            PVOID Environment;
            ULONG StartingPositionLeft;
            ULONG StartingPositionTop;
            ULONG Width;
            ULONG Height;
            ULONG CharWidth;
            ULONG CharHeight;
            ULONG ConsoleTextAttributes;
            ULONG WindowFlags;
            ULONG ShowWindowFlags;
            UNICODE_STRING WindowTitle;
            UNICODE_STRING DesktopName;
            UNICODE_STRING ShellInfo;
            UNICODE_STRING RuntimeData;
            RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[ 0x20 ];
        } RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

        typedef struct _PEB {
            BOOLEAN InheritedAddressSpace;
            BOOLEAN ReadImageFileExecOptions;
            BOOLEAN BeingDebugged;
            BOOLEAN Spare;
            HANDLE Mutant;
            PVOID ImageBaseAddress;
            PPEB_LDR_DATA LoaderData;
            RTL_USER_PROCESS_PARAMETERS ProcessParameters;
            PVOID SubSystemData;
            PVOID ProcessHeap;
            PVOID FastPebLock;
            uintptr_t FastPebLockRoutine;
            uintptr_t FastPebUnlockRoutine;
            ULONG EnvironmentUpdateCount;
            uintptr_t KernelCallbackTable;
            PVOID EventLogSection;
            PVOID EventLog;
            PPEB_FREE_BLOCK FreeList;
            ULONG TlsExpansionCounter;
            PVOID TlsBitmap;
            ULONG TlsBitmapBits[ 0x2 ];
            PVOID ReadOnlySharedMemoryBase;
            PVOID ReadOnlySharedMemoryHeap;
            uintptr_t ReadOnlyStaticServerData;
            PVOID AnsiCodePageData;
            PVOID OemCodePageData;
            PVOID UnicodeCaseTableData;
            ULONG NumberOfProcessors;
            ULONG NtGlobalFlag;
            BYTE Spare2[ 0x4 ];
            LARGE_INTEGER CriticalSectionTimeout;
            ULONG HeapSegmentReserve;
            ULONG HeapSegmentCommit;
            ULONG HeapDeCommitTotalFreeThreshold;
            ULONG HeapDeCommitFreeBlockThreshold;
            ULONG NumberOfHeaps;
            ULONG MaximumNumberOfHeaps;
            uintptr_t *ProcessHeaps;
            PVOID GdiSharedHandleTable;
            PVOID ProcessStarterHelper;
            PVOID GdiDCAttributeList;
            PVOID LoaderLock;
            ULONG OSMajorVersion;
            ULONG OSMinorVersion;
            ULONG OSBuildNumber;
            ULONG OSPlatformId;
            ULONG ImageSubSystem;
            ULONG ImageSubSystemMajorVersion;
            ULONG ImageSubSystemMinorVersion;
            ULONG GdiHandleBuffer[ 0x22 ];
            ULONG PostProcessInitRoutine;
            ULONG TlsExpansionBitmap;
            BYTE TlsExpansionBitmapBits[ 0x80 ];
            ULONG SessionId;
        } PEB, *PPEB;

        typedef BOOLEAN( NTAPI *PLDR_INIT_ROUTINE )( _In_ PVOID DllHandle,
                                                     _In_ ULONG Reason,
                                                     _In_opt_ PVOID Context );

        typedef struct _LDRP_CSLIST {
            PSINGLE_LIST_ENTRY Tail;
        } LDRP_CSLIST, *PLDRP_CSLIST;

        typedef struct _LDR_SERVICE_TAG_RECORD {
            struct _LDR_SERVICE_TAG_RECORD *Next;
            ULONG ServiceTag;
        } LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;

        typedef enum _LDR_DDAG_STATE {
            LdrModulesMerged = -5,
            LdrModulesInitError = -4,
            LdrModulesSnapError = -3,
            LdrModulesUnloaded = -2,
            LdrModulesUnloading = -1,
            LdrModulesPlaceHolder = 0,
            LdrModulesMapping = 1,
            LdrModulesMapped = 2,
            LdrModulesWaitingForDependencies = 3,
            LdrModulesSnapping = 4,
            LdrModulesSnapped = 5,
            LdrModulesCondensed = 6,
            LdrModulesReadyToInit = 7,
            LdrModulesInitializing = 8,
            LdrModulesReadyToRun = 9
        } LDR_DDAG_STATE;

        typedef struct _LDR_DDAG_NODE {
            LIST_ENTRY Modules;
            PLDR_SERVICE_TAG_RECORD ServiceTagList;
            ULONG LoadCount;
            ULONG LoadWhileUnloadingCount;
            ULONG LowestLink;
            union {
                LDRP_CSLIST Dependencies;
                SINGLE_LIST_ENTRY RemovalLink;
            };
            LDRP_CSLIST IncomingDependencies;
            LDR_DDAG_STATE State;
            SINGLE_LIST_ENTRY CondenseLink;
            ULONG PreorderNumber;
        } LDR_DDAG_NODE, *PLDR_DDAG_NODE;

        typedef struct _RTL_BALANCED_NODE {
            union {
                struct _RTL_BALANCED_NODE *Children[ 2 ];
                struct {
                    struct _RTL_BALANCED_NODE *Left;
                    struct _RTL_BALANCED_NODE *Right;
                };
            };
            union {
                UCHAR Red : 1;
                UCHAR Balance : 2;
                ULONG_PTR ParentValue;
            };
        } RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

        typedef struct _LDR_DATA_TABLE_ENTRY {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            union {
                LIST_ENTRY InInitializationOrderLinks;
                LIST_ENTRY InProgressLinks;
            };
            PVOID DllBase;
            PLDR_INIT_ROUTINE EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
            union {
                UCHAR FlagGroup[ 4 ];
                ULONG Flags;
                struct {
                    ULONG PackagedBinary : 1;
                    ULONG MarkedForRemoval : 1;
                    ULONG ImageDll : 1;
                    ULONG LoadNotificationsSent : 1;
                    ULONG TelemetryEntryProcessed : 1;
                    ULONG ProcessStaticImport : 1;
                    ULONG InLegacyLists : 1;
                    ULONG InIndexes : 1;
                    ULONG ShimDll : 1;
                    ULONG InExceptionTable : 1;
                    ULONG ReservedFlags1 : 2;
                    ULONG LoadInProgress : 1;
                    ULONG LoadConfigProcessed : 1;
                    ULONG EntryProcessed : 1;
                    ULONG ProtectDelayLoad : 1;
                    ULONG ReservedFlags3 : 2;
                    ULONG DontCallForThreads : 1;
                    ULONG ProcessAttachCalled : 1;
                    ULONG ProcessAttachFailed : 1;
                    ULONG CorDeferredValidate : 1;
                    ULONG CorImage : 1;
                    ULONG DontRelocate : 1;
                    ULONG CorILOnly : 1;
                    ULONG ChpeImage : 1;
                    ULONG ChpeEmulatorImage : 1;
                    ULONG ReservedFlags5 : 1;
                    ULONG Redirected : 1;
                    ULONG ReservedFlags6 : 2;
                    ULONG CompatDatabaseProcessed : 1;
                };
            };
            USHORT ObsoleteLoadCount;
            USHORT TlsIndex;
            LIST_ENTRY HashLinks;
            ULONG TimeDateStamp;
            struct _ACTIVATION_CONTEXT *EntryPointActivationContext;
            PVOID Lock;// RtlAcquireSRWLockExclusive
            PLDR_DDAG_NODE DdagNode;
            LIST_ENTRY NodeModuleLink;
            struct _LDRP_LOAD_CONTEXT *LoadContext;
            PVOID ParentDllBase;
            PVOID SwitchBackContext;
            RTL_BALANCED_NODE BaseAddressIndexNode;
            RTL_BALANCED_NODE MappingInfoIndexNode;
            ULONG_PTR OriginalBase;
            LARGE_INTEGER LoadTime;
            ULONG BaseNameHashValue;
            LDR_DLL_LOAD_REASON LoadReason;// since WIN8
            ULONG ImplicitPathOptions;
            ULONG ReferenceCount;// since WIN10
            ULONG DependentLoadFlags;
            UCHAR SigningLevel;// since REDSTONE2
            ULONG CheckSum;    // since 22H1
            PVOID ActivePatchImageBase;
            uintptr_t HotPatchState;
        } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
    }// namespace win

    namespace hash {
        constexpr uint32_t fnv_prime_value = 0x01000193;
        constexpr uint32_t fnv_offset_basis = 0x811c9dc5;

        template< typename S >
        struct fnv1a;

        template<>
        struct fnv1a< uint32_t > {
            static constexpr uint32_t hash_const( const char *input, uint32_t val = fnv_offset_basis ) {
                return input[ 0 ] == '\0' ? val : hash_const( input + 1, ( val ^ *input ) * fnv_prime_value );
            }
        };
    };// namespace hash

    using fnv1a = hash::fnv1a< uint32_t >;

    namespace utils {
        SYSCALL_FORCEINLINE win::PEB *get_peb( ) noexcept {
#if _WIN32 || _WIN64
#if defined( _M_X64 )
            return reinterpret_cast< win::PEB * >( __readgsqword( 0x60 ) );
#else
            return reinterpret_cast< win::PEB * >( __readfsdword( 0x30 ) );
#endif
#endif
        }

        SYSCALL_FORCEINLINE std::string wide_to_string( wchar_t *buffer ) noexcept {
            auto string = std::wstring( buffer );

            if ( string.empty( ) )
                return "";

            return std::string( string.begin( ), string.end( ) );
        }

        template< typename T >
        SYSCALL_FORCEINLINE T get_module_handle_from_hash( const uint32_t &module_hash ) noexcept {
            auto peb = utils::get_peb( );

            if ( !peb )
                return NULL;

            auto head = &peb->LoaderData->InLoadOrderModuleList;

            for ( auto it = head->Flink; it != head; it = it->Flink ) {
                win::_LDR_DATA_TABLE_ENTRY *ldr_entry = CONTAINING_RECORD( it, win::LDR_DATA_TABLE_ENTRY,
                                                                           InLoadOrderLinks );

                if ( !ldr_entry->BaseDllName.Buffer )
                    continue;

                auto name = utils::wide_to_string( ldr_entry->BaseDllName.Buffer );

                if ( fnv1a::hash_const( name.data( ) ) == module_hash )
                    return reinterpret_cast< T >( ldr_entry->DllBase );
            }

            return NULL;
        }

        template< typename T >
        SYSCALL_FORCEINLINE T get_module_handle( const char *module_name ) noexcept {
            auto peb = utils::get_peb( );

            if ( !module_name )
                return static_cast< T >( peb->ImageBaseAddress );

            return get_module_handle_from_hash< T >( fnv1a::hash_const( module_name ) );
        }

        template< typename T >
        SYSCALL_FORCEINLINE T get_module_export( const char *module_name, const char *export_name ) noexcept {
            auto module_handle = utils::get_module_handle< void * >( module_name );

            if ( module_handle ) {
                auto dos_headers = reinterpret_cast< PIMAGE_DOS_HEADER >( module_handle );
                auto nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS >( reinterpret_cast< uintptr_t >( module_handle ) + dos_headers->e_lfanew );

                if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
                    return NULL;

                auto image_export_directory = reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >( reinterpret_cast< uintptr_t >( module_handle ) + nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
                auto image_ordinal_array = reinterpret_cast< uint16_t * >( reinterpret_cast< uintptr_t >( module_handle ) + image_export_directory->AddressOfNameOrdinals );
                auto image_function_addresses = reinterpret_cast< uint32_t * >( reinterpret_cast< uintptr_t >( module_handle ) + image_export_directory->AddressOfFunctions );
                auto image_name_addresses = reinterpret_cast< uint32_t * >( reinterpret_cast< uintptr_t >( module_handle ) + image_export_directory->AddressOfNames );

                for ( auto i = 0; i < image_export_directory->NumberOfFunctions; i++ ) {
                    auto export_address_name = reinterpret_cast< const char * >(
                            reinterpret_cast< uintptr_t >( module_handle ) + image_name_addresses[ i ] );

                    if ( !export_address_name )
                        continue;

                    if ( fnv1a::hash_const( export_address_name ) == fnv1a::hash_const( export_name ) )
                        return static_cast< T >( reinterpret_cast< uintptr_t >( module_handle ) + image_function_addresses[ image_ordinal_array[ i ] ] );
                }
            }

            return NULL;
        }
    }// namespace utils

    SYSCALL_FORCEINLINE int32_t get_syscall_table_id( const char *module_name, const char *export_name ) noexcept {
#if _WIN32 || _WIN64
#if defined( _M_X64 )
        auto export_address = utils::get_module_export< uintptr_t >( module_name, export_name ) + 3;
#else
        auto export_address = utils::get_module_export< uintptr_t >( module_name, export_name );
#endif
#endif

        if ( !export_address )
            return NULL;

        return *reinterpret_cast< int32_t * >( export_address + 1 );
    }

    struct create_function {
    public:
        SYSCALL_FORCEINLINE create_function( ) = default;

        SYSCALL_FORCEINLINE create_function( const char *module_name, const char *export_name ) noexcept {
            this->_module_name = module_name;
            this->_export_name = export_name;

            unsigned char shellcode[ ] = {
#if _WIN32 || _WIN64
#if defined( _M_X64 )
                0x49, 0x89, 0xCA,                       // mov r10, rcx
                0xB8, 0x3F, 0x10, 0x00, 0x00,           // mov eax, <syscall_id>
                0x0F, 0x05,                             // syscall
                0xC3                                    // ret
#else
                0xB8, 0x00, 0x10, 0x00, 0x00,           // mov eax, <syscall_id>
                0x64, 0x8B,0x15, 0xC0, 0x00, 0x00, 0x00,// mov edx, DWORD PTR fs:0xc0 (
                0xFF, 0xD2,                             // call edx
                0xC2, 0x04, 0x00                        // ret 4
#endif
#endif
            };

            static auto syscall_table_id = syscall::get_syscall_table_id( this->_module_name, this->_export_name );

#if _WIN32 || _WIN64
#if defined( _M_X64 )
            memcpy( &shellcode[ 4 ], &syscall_table_id, sizeof( int32_t ) );
#else
            memcpy( &shellcode[ 1 ], &syscall_table_id, sizeof( int32_t ) );
#endif
#endif
            auto allocated_memory = VirtualAlloc( nullptr, sizeof( shellcode ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

            if ( !allocated_memory )
                return;

            memcpy( allocated_memory, shellcode, sizeof( shellcode ) );
            *reinterpret_cast< void ** >( &this->_function ) = allocated_memory;
        }

        SYSCALL_FORCEINLINE bool is_valid( ) {
            return this->_function != nullptr;
        }

        template< typename T, typename... Args >
        SYSCALL_FORCEINLINE T invoke( Args... arguments ) noexcept {
            return reinterpret_cast< T ( __stdcall * )( Args... ) >( this->_function )( arguments... );
        }

    protected:
        const char *_module_name;
        const char *_export_name;
        void *_function = nullptr;
    };

    template< typename T, typename... Args >
    SYSCALL_FORCEINLINE T invoke_simple( const char *export_name, Args... arguments ) noexcept {
        auto syscall = syscall::create_function{ "win32u.dll", export_name };

        if ( !syscall.is_valid( ) ) {
            return NULL;
        }

        return syscall.invoke< T >( arguments... );
    }
}// namespace syscall

#endif//DIRECT_SYSCALL_HPP
