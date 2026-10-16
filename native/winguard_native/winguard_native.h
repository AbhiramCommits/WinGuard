// ---------------------------------------------------------------------------
// WinGuard native collector — C ABI shared by the Win32 collector and the ETW
// consumer, and P/Invoked by WinGuard.Agent.
//
// All strings are fixed-size wide-character buffers so that no memory is ever
// allocated on one side of the boundary and freed on the other. Structs are
// packed to 8 bytes; the managed side declares matching [StructLayout]s.
// ---------------------------------------------------------------------------

#ifndef WINGUARD_NATIVE_H
#define WINGUARD_NATIVE_H

#include <stdint.h>

#if defined(_WIN32)
#include <windows.h>
#define WG_API extern "C" __declspec(dllexport)
#define WG_CALL __stdcall
#else
#define WG_API extern "C"
#define WG_CALL
typedef unsigned short wchar_t;
#endif

#define WG_PATH_CHARS 520
#define WG_NAME_CHARS 260

// Return codes shared with the managed side.
#define WG_OK               0
#define WG_ERR_FAILURE     -1
#define WG_ERR_BUFFER      -2  // capacity too small; *count holds the required size
#define WG_ERR_ACCESS      -3
#define WG_ERR_NOT_FOUND   -4

// Signature status values (mirror WinGuard.Core.Models.SignatureStatus).
#define WG_SIG_UNKNOWN      0
#define WG_SIG_UNSIGNED     1
#define WG_SIG_SELF_SIGNED  2
#define WG_SIG_SIGNED       3

#pragma pack(push, 8)

typedef struct WG_ProcessInfo
{
    uint32_t pid;
    uint32_t parent_pid;
    wchar_t  image_path[WG_PATH_CHARS];
    wchar_t  process_name[WG_NAME_CHARS];
} WG_ProcessInfo;

typedef struct WG_ModuleInfo
{
    uint64_t base_address;
    uint64_t size;
    int32_t  signature_status;
    uint32_t flags;                     // bit 0 = backed by file
    wchar_t  path[WG_PATH_CHARS];
    wchar_t  module_name[WG_NAME_CHARS];
    wchar_t  signer_name[WG_NAME_CHARS];
} WG_ModuleInfo;

typedef struct WG_RegionInfo
{
    uint64_t base_address;
    uint64_t size;
    uint32_t protection;                // PAGE_* constant
    uint32_t region_type;               // MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE
    uint8_t  has_backing_file;
    wchar_t  backing_file[WG_PATH_CHARS];
} WG_RegionInfo;

typedef struct WG_ImageLoadEvent
{
    uint32_t pid;
    uint32_t tid;
    uint64_t image_base;
    uint64_t image_size;
    wchar_t  image_path[WG_PATH_CHARS];
} WG_ImageLoadEvent;

#pragma pack(pop)

typedef void (WG_CALL *wg_image_load_callback)(const WG_ImageLoadEvent* evt);

// ---- Process / module / memory enumeration --------------------------------

WG_API int32_t WG_CALL wg_native_abi_version(void);

WG_API int32_t WG_CALL wg_native_last_error(void);

WG_API int32_t WG_CALL wg_enumerate_processes(
    WG_ProcessInfo* out,
    int32_t         capacity,
    int32_t*        count);

WG_API int32_t WG_CALL wg_enumerate_modules(
    uint32_t        pid,
    WG_ModuleInfo*  out,
    int32_t         capacity,
    int32_t*        count);

WG_API int32_t WG_CALL wg_enumerate_regions(
    uint32_t        pid,
    WG_RegionInfo*  out,
    int32_t         capacity,
    int32_t*        count);

// Reads the mapped .text section of the image loaded at `base` in `pid`.
// `written` receives the number of bytes copied (never more than capacity).
WG_API int32_t WG_CALL wg_read_text_section(
    uint32_t  pid,
    uint64_t  base,
    uint8_t*  out,
    uint32_t  capacity,
    uint32_t* written);

// ---- ETW consumer (Microsoft-Windows-Kernel-Process image loads) -----------

WG_API int32_t WG_CALL wg_etw_start(
    const wchar_t*          session_name,
    wg_image_load_callback  callback,
    uint64_t*               session_handle);

WG_API int32_t WG_CALL wg_etw_stop(uint64_t session_handle);

#endif // WINGUARD_NATIVE_H
