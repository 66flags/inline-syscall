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
#include <memory>

#define SYSCALL_HASH_CT( str )                                        \
    [ ]( ) [[msvc::forceinline]]                                      \
    {                                                                 \
        constexpr uint32_t out = ::syscall::fnv1a::hash_ctime( str ); \
                                                                      \
        return out;                                                   \
    }( )

#define SYSCALL_HASH( str ) ::syscall::fnv1a::hash_rtime( str )

#define INVOKE_SYSCALL( type, export_name, ... )                                \
    [ & ]( ) [[msvc::forceinline]]                                              \
    {                                                                           \
        constexpr uint32_t name = ::syscall::fnv1a::hash_ctime( #export_name ); \
                                                                                \
        return syscall::invoke_simple< type >( name, __VA_ARGS__ );             \
    }( )

namespace syscall {
    namespace nt {
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
                struct
                {
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
                struct
                {
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
            uint32_t LoadReason;// since WIN8
            ULONG ImplicitPathOptions;
            ULONG ReferenceCount;// since WIN10
            ULONG DependentLoadFlags;
            UCHAR SigningLevel;// since REDSTONE2
            ULONG CheckSum;    // since 22H1
            PVOID ActivePatchImageBase;
            uintptr_t HotPatchState;
        } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
    }// namespace nt

    namespace fnv1a {
        constexpr uint32_t fnv_prime_value = 0x01000193;
        constexpr uint32_t fnv_offset_basis = 0x811c9dc5;

        // only use these for compile-time hashing.
        consteval uint32_t hash_ctime( const char *input, uint32_t val = fnv_offset_basis )
        {
            return input[ 0 ] == '\0' ? val : hash_ctime( input + 1, ( val ^ *input ) * fnv_prime_value );
        }

        // only used for comparing strings, etc during runtime.
        constexpr uint32_t hash_rtime( const char *input, uint32_t val = fnv_offset_basis )
        {
            return input[ 0 ] == '\0' ? val : hash_rtime( input + 1, ( val ^ *input ) * fnv_prime_value );
        }
    }// namespace fnv1a

    namespace utils {
        SYSCALL_FORCEINLINE std::string wide_to_string( wchar_t *buffer ) noexcept
        {
            auto string = std::wstring( buffer );

            if ( string.empty( ) )
                return "";

            return std::string( string.begin( ), string.end( ) );
        }
    }// namespace utils

    namespace win {
        SYSCALL_FORCEINLINE nt::PEB *get_peb( ) noexcept
        {
#if defined( _M_IX86 ) || defined( __i386__ )
            return reinterpret_cast< nt::PEB * >( __readfsdword( 0x30 ) );
#else
            return reinterpret_cast< nt::PEB * >( __readgsqword( 0x60 ) );
#endif
        }

        template< typename T >
        static SYSCALL_FORCEINLINE T get_module_handle_from_hash( const uint32_t &module_hash ) noexcept
        {
            auto peb = win::get_peb( );

            if ( !peb )
                return NULL;

            auto head = &peb->LoaderData->InLoadOrderModuleList;

            for ( auto it = head->Flink; it != head; it = it->Flink ) {
                nt::_LDR_DATA_TABLE_ENTRY *ldr_entry = CONTAINING_RECORD( it, nt::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

                if ( !ldr_entry->BaseDllName.Buffer )
                    continue;

                auto name = utils::wide_to_string( ldr_entry->BaseDllName.Buffer );

                if ( SYSCALL_HASH( name.data( ) ) == module_hash )
                    return reinterpret_cast< T >( ldr_entry->DllBase );
            }

            return NULL;
        }

        template< typename T >
        static SYSCALL_FORCEINLINE T get_module_export_from_table( uintptr_t module_address,
                                                                   const uint32_t &export_hash ) noexcept
        {
            auto dos_headers = reinterpret_cast< IMAGE_DOS_HEADER * >( module_address );

            if ( dos_headers->e_magic != IMAGE_DOS_SIGNATURE )
                return NULL;

            auto nt_headers32 = reinterpret_cast< PIMAGE_NT_HEADERS32 >( module_address + dos_headers->e_lfanew );
            auto nt_headers64 = reinterpret_cast< PIMAGE_NT_HEADERS64 >( module_address + dos_headers->e_lfanew );

            PIMAGE_OPTIONAL_HEADER32 optional_header32 = &nt_headers32->OptionalHeader;
            PIMAGE_OPTIONAL_HEADER64 optional_header64 = &nt_headers64->OptionalHeader;

            PIMAGE_EXPORT_DIRECTORY export_directory = nullptr;

            if ( nt_headers32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ) {
                if ( optional_header32->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size <= 0U )
                    return NULL;

                export_directory = reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >( module_address + optional_header32->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
            } else if ( nt_headers64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ) {
                if ( optional_header64->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size <= 0U )
                    return NULL;

                export_directory = reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >( module_address + optional_header64->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
            }

            auto names_rva = reinterpret_cast< uint32_t * >( module_address + export_directory->AddressOfNames );
            auto functions_rva = reinterpret_cast< uint32_t * >( module_address + export_directory->AddressOfFunctions );
            auto name_ordinals = reinterpret_cast< unsigned short * >( module_address + export_directory->AddressOfNameOrdinals );

            uint32_t number_of_names = export_directory->NumberOfNames;

            for ( size_t i = 0; i < number_of_names; i++ ) {
                const char *export_name = reinterpret_cast< const char * >( module_address + names_rva[ i ] );

                if ( export_hash == SYSCALL_HASH( export_name ) )
                    return static_cast< T >( module_address + functions_rva[ name_ordinals[ i ] ] );
            }

            return 0x0;
        }

        template< typename T >
        SYSCALL_FORCEINLINE T force_find_export( const uint32_t &export_hash ) noexcept
        {
            auto peb = ::syscall::win::get_peb( );

            if ( !peb || !export_hash )
                return NULL;

            auto head = &peb->LoaderData->InLoadOrderModuleList;

            for ( auto it = head->Flink; it != head; it = it->Flink ) {
                nt::_LDR_DATA_TABLE_ENTRY *ldr_entry = CONTAINING_RECORD( it,
                                                                          nt::LDR_DATA_TABLE_ENTRY,
                                                                           InLoadOrderLinks );

                if ( !ldr_entry->BaseDllName.Buffer )
                    continue;

                auto name = ::syscall::utils::wide_to_string( ldr_entry->BaseDllName.Buffer );

                auto export_address = ::syscall::win::get_module_export_from_table< uintptr_t >(
                        reinterpret_cast< uintptr_t >( ldr_entry->DllBase ),
                        export_hash );

                if ( !export_address )
                    continue;

                return static_cast< T >( export_address );
            }
        }
    }// namespace win

    SYSCALL_FORCEINLINE uint16_t get_return_code_from_export( uintptr_t export_address ) noexcept
    {
        if ( !export_address )
            return NULL;

        return *reinterpret_cast< int * >( static_cast< uintptr_t >( export_address + 12 ) + 1 );
    }

    SYSCALL_FORCEINLINE int get_syscall_id_from_export( uintptr_t export_address ) noexcept
    {
        if ( !export_address )
            return NULL;

#if defined( _M_IX86 ) || defined( __i386__ )
        return *reinterpret_cast< int * >( static_cast< uintptr_t >( export_address ) + 1 );
#else
        return *reinterpret_cast< int * >( static_cast< uintptr_t >( export_address + 3 ) + 1 );
#endif
    }

    struct create_function {
        void *_allocated_memory = nullptr;
        void *_function = nullptr;
        uint32_t _export_hash;

    public:
        SYSCALL_FORCEINLINE ~create_function( ) noexcept
        {
            if ( this->_allocated_memory ) {
                VirtualFree( this->_allocated_memory, 0, MEM_RELEASE );
                this->_allocated_memory = nullptr;
            }
        }

        SYSCALL_FORCEINLINE create_function( uint32_t export_hash ) noexcept
            : _export_hash( export_hash )
        {

            static auto exported_address = ::syscall::win::force_find_export< uintptr_t >( this->_export_hash );
            static auto syscall_table_id = ::syscall::get_syscall_id_from_export( exported_address );

            if ( !!exported_address || !syscall_table_id )
                return;

            unsigned char shellcode[ ] =
            {
#if defined( _M_IX86 ) || defined( __i386__ )
                0xB8, 0x00, 0x10, 0x00, 0x00,           // mov eax, <syscall_id>
                0x64, 0x8B, 0x15, 0xC0, 0x00, 0x00, 0x00,// mov edx, DWORD PTR fs:0xc0 (
                0xFF, 0xD2,                             // call edx
                0xC2, 0x04, 0x00                        // ret 4
#else
                0x49, 0x89, 0xCA,                       // mov r10, rcx
                0xB8, 0x3F, 0x10, 0x00, 0x00,           // mov eax, <syscall_id>
                0x0F, 0x05,                             // syscall
                0xC3                                    // ret
#endif
            };

#if defined( _M_IX86 ) || defined( __i386__ )
            static auto syscall_return_code = ::syscall::get_return_code_from_export(
                    exported_address );
#endif

#if defined( _M_IX86 ) || defined( __i386__ )
            std::memcpy( &shellcode[ 15 ], &syscall_return_code, sizeof( uint16_t ) );
            std::memcpy( &shellcode[ 1 ], &syscall_table_id, sizeof( int ) );
#else
            std::memcpy( &shellcode[ 4 ], &syscall_table_id, sizeof( int ) );
#endif
            this->_allocated_memory = VirtualAlloc( nullptr,
                                                    sizeof( shellcode ),
                                                    MEM_COMMIT | MEM_RESERVE,
                                                    PAGE_EXECUTE_READWRITE );

            if ( !this->_allocated_memory ) {
                return;
            }

            std::memcpy( this->_allocated_memory, shellcode, sizeof( shellcode ) );
            *reinterpret_cast< void ** >( &this->_function ) = this->_allocated_memory;
        }

        SYSCALL_FORCEINLINE bool is_valid_address( ) noexcept
        {
            return this->_function != nullptr;
        }

        template< typename T, typename... Args >
        SYSCALL_FORCEINLINE T invoke_call( Args... arguments ) noexcept
        {
            return reinterpret_cast< T( __stdcall * )( Args... ) >( this->_function )( arguments... );
        }
    };

    template< typename T, typename... Args >
    SYSCALL_FORCEINLINE T invoke_simple( uint32_t export_hash, Args... arguments ) noexcept
    {
        static auto syscall_fn = ::syscall::create_function( export_hash );

        if ( !syscall_fn.is_valid_address( ) ) {
            return NULL;
        }

        return syscall_fn.invoke_call< T >( arguments... );
    }
}// namespace syscall

#endif//DIRECT_SYSCALL_HPP