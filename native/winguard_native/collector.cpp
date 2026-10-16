// ---------------------------------------------------------------------------
// WinGuard native collector — real Win32 implementation.
//
// Exports the C ABI declared in winguard_native.h and consumed by
// WinGuard.Agent.Telemetry.Win32EtwTelemetrySource through P/Invoke.
//
// This file is only compiled on Windows (see ../README.md and CMakeLists.txt).
// It is genuine, un-stubbed Win32 code: toolhelp process enumeration, psapi
// module enumeration, VirtualQueryEx memory walk, ReadProcessMemory of the
// mapped .text section, and Authenticode verification via WinVerifyTrust.
// ---------------------------------------------------------------------------

#include "winguard_native.h"

#if defined(_WIN32)

#include <tlhelp32.h>
#include <psapi.h>
#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <winternl.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace
{

thread_local int32_t g_last_error = WG_OK;

void SetError(int32_t code)
{
    g_last_error = code;
}

template <typename TChar, size_t N>
void CopyString(wchar_t (&dst)[N], const TChar* src)
{
    if (src == nullptr)
    {
        dst[0] = L'\0';
        return;
    }

    wcsncpy_s(dst, N, src, _TRUNCATE);
}

// ---- Authenticode ---------------------------------------------------------

// Maps a WinVerifyTrust result onto the WG_SIG_* values.
int32_t ClassifyTrustStatus(LONG status)
{
    if (status == ERROR_SUCCESS)
    {
        return WG_SIG_SIGNED;
    }

    switch (status)
    {
    case TRUST_E_NOSIGNATURE:
    case TRUST_E_SUBJECT_FORM_UNKNOWN:
    case TRUST_E_PROVIDER_UNKNOWN:
        return WG_SIG_UNSIGNED;

    case TRUST_E_BAD_DIGEST:
        // Signature present but the file was modified: treat as unsigned.
        return WG_SIG_UNSIGNED;

    case CERT_E_UNTRUSTEDROOT:
    case CERT_E_CHAINING:
    case CERT_E_EXPIRED:
    case TRUST_E_EXPLICIT_DISTRUST:
        return WG_SIG_SELF_SIGNED;

    default:
        return WG_SIG_UNKNOWN;
    }
}

int32_t VerifySignature(const wchar_t* path)
{
    if (path == nullptr || path[0] == L'\0')
    {
        return WG_SIG_UNKNOWN;
    }

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path;

    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &policy, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &data);

    return ClassifyTrustStatus(status);
}

// Retrieves the simple display name of the signer certificate, if any.
void GetSignerName(const wchar_t* path, wchar_t* out, size_t outChars)
{
    out[0] = L'\0';

    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;
    DWORD encoding = 0, contentType = 0, formatType = 0;

    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &encoding,
            &contentType,
            &formatType,
            &store,
            &msg,
            nullptr))
    {
        return;
    }

    PCMSG_SIGNER_INFO signerInfo = nullptr;
    DWORD signerInfoSize = 0;
    if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize) &&
        signerInfoSize > 0)
    {
        std::vector<BYTE> buffer(signerInfoSize);
        signerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(buffer.data());

        if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, signerInfo, &signerInfoSize))
        {
            CERT_INFO certInfo{};
            certInfo.Issuer = signerInfo->Issuer;
            certInfo.SerialNumber = signerInfo->SerialNumber;

            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &certInfo, nullptr);

            if (cert != nullptr)
            {
                CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, out, static_cast<DWORD>(outChars));
                CertFreeCertificateContext(cert);
            }
        }
    }

    if (msg != nullptr)
    {
        CryptMsgClose(msg);
    }

    if (store != nullptr)
    {
        CertCloseStore(store, 0);
    }
}

// ---- PE parsing -----------------------------------------------------------

bool ReadRemote(HANDLE process, uint64_t address, void* buffer, SIZE_T size)
{
    SIZE_T read = 0;
    return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), buffer, size, &read) == TRUE && read == size;
}

// Locates the .text section of a mapped image and returns its virtual address,
// virtual size and raw size. Returns false when the image cannot be parsed.
bool FindTextSection(HANDLE process, uint64_t base,
                     uint32_t* virtualAddress, uint32_t* virtualSize, uint32_t* rawSize)
{
    IMAGE_DOS_HEADER dos{};
    if (!ReadRemote(process, base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }

    IMAGE_NT_HEADERS32 nt32{};
    if (!ReadRemote(process, base + static_cast<uint64_t>(dos.e_lfanew), &nt32, sizeof(nt32)) ||
        nt32.Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    const bool is64 = nt32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    const uint32_t numberOfSections = nt32.FileHeader.NumberOfSections;
    const uint32_t sizeOfOptionalHeader = nt32.FileHeader.SizeOfOptionalHeader;
    const uint32_t sectionTableOffset = dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeOfOptionalHeader;

    for (uint32_t i = 0; i < numberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER section{};
        const uint64_t offset = base + sectionTableOffset + (static_cast<uint64_t>(i) * sizeof(IMAGE_SECTION_HEADER));
        if (!ReadRemote(process, offset, &section, sizeof(section)))
        {
            return false;
        }

        if (std::memcmp(section.Name, ".text", 5) == 0)
        {
            *virtualAddress = section.VirtualAddress;
            *virtualSize = section.Misc.VirtualSize;
            *rawSize = section.SizeOfRawData;
            return true;
        }
    }

    (void)is64;
    return false;
}

bool IsExecutableProtection(DWORD protect)
{
    const DWORD base = protect & 0xFF;
    return base == PAGE_EXECUTE ||
           base == PAGE_EXECUTE_READ ||
           base == PAGE_EXECUTE_READWRITE ||
           base == PAGE_EXECUTE_WRITECOPY;
}

} // namespace

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

WG_API int32_t WG_CALL wg_native_abi_version(void)
{
    return 1;
}

WG_API int32_t WG_CALL wg_native_last_error(void)
{
    return g_last_error;
}

WG_API int32_t WG_CALL wg_enumerate_processes(WG_ProcessInfo* out, int32_t capacity, int32_t* count)
{
    if (count == nullptr)
    {
        SetError(WG_ERR_FAILURE);
        return WG_ERR_FAILURE;
    }

    *count = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        SetError(static_cast<int32_t>(GetLastError()));
        return WG_ERR_FAILURE;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(snapshot, &entry))
    {
        CloseHandle(snapshot);
        SetError(static_cast<int32_t>(GetLastError()));
        return WG_ERR_FAILURE;
    }

    int32_t written = 0;
    do
    {
        if (written >= capacity)
        {
            ++written; // keep counting so the caller can size the buffer
            continue;
        }

        WG_ProcessInfo info{};
        info.pid = entry.th32ProcessID;
        info.parent_pid = entry.th32ParentProcessID;
        CopyString(info.process_name, entry.szExeFile);

        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
        if (process != nullptr)
        {
            DWORD chars = WG_PATH_CHARS;
            QueryFullProcessImageNameW(process, 0, info.image_path, &chars);
            CloseHandle(process);
        }

        out[written] = info;
        ++written;
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);

    *count = written;
    if (written > capacity)
    {
        SetError(WG_ERR_BUFFER);
        return WG_ERR_BUFFER;
    }

    SetError(WG_OK);
    return WG_OK;
}

WG_API int32_t WG_CALL wg_enumerate_modules(uint32_t pid, WG_ModuleInfo* out, int32_t capacity, int32_t* count)
{
    if (count == nullptr)
    {
        SetError(WG_ERR_FAILURE);
        return WG_ERR_FAILURE;
    }

    *count = 0;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process == nullptr)
    {
        SetError(WG_ERR_ACCESS);
        return WG_ERR_ACCESS;
    }

    HMODULE modules[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(process, modules, sizeof(modules), &needed, LIST_MODULES_ALL))
    {
        CloseHandle(process);
        SetError(WG_ERR_FAILURE);
        return WG_ERR_FAILURE;
    }

    const DWORD moduleCount = needed / sizeof(HMODULE);
    int32_t written = 0;

    for (DWORD i = 0; i < moduleCount; ++i)
    {
        MODULEINFO info{};
        if (!GetModuleInformation(process, modules[i], &info, sizeof(info)))
        {
            continue;
        }

        wchar_t path[WG_PATH_CHARS]{};
        GetModuleFileNameExW(process, modules[i], path, WG_PATH_CHARS);

        if (written >= capacity)
        {
            ++written;
            continue;
        }

        WG_ModuleInfo record{};
        record.base_address = reinterpret_cast<uint64_t>(info.lpBaseOfDll);
        record.size = info.SizeOfImage;
        record.signature_status = VerifySignature(path);
        record.flags = 1; // loader-mapped modules are always file backed

        CopyString(record.path, path);

        const wchar_t* name = wcsrchr(path, L'\\');
        CopyString(record.module_name, name != nullptr ? name + 1 : path);

        GetSignerName(path, record.signer_name, WG_NAME_CHARS);

        out[written] = record;
        ++written;
    }

    CloseHandle(process);

    *count = written;
    if (written > capacity)
    {
        SetError(WG_ERR_BUFFER);
        return WG_ERR_BUFFER;
    }

    SetError(WG_OK);
    return WG_OK;
}

WG_API int32_t WG_CALL wg_enumerate_regions(uint32_t pid, WG_RegionInfo* out, int32_t capacity, int32_t* count)
{
    if (count == nullptr)
    {
        SetError(WG_ERR_FAILURE);
        return WG_ERR_FAILURE;
    }

    *count = 0;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process == nullptr)
    {
        SetError(WG_ERR_ACCESS);
        return WG_ERR_ACCESS;
    }

    int32_t written = 0;
    uint64_t address = 0;
    MEMORY_BASIC_INFORMATION mbi{};

    while (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        const uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        const uint64_t size = static_cast<uint64_t>(mbi.RegionSize);

        address = base + size;
        if (address <= base)
        {
            break; // overflow guard
        }

        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_GUARD)
        {
            continue;
        }

        if (written >= capacity)
        {
            ++written;
            continue;
        }

        WG_RegionInfo record{};
        record.base_address = base;
        record.size = size;
        record.protection = mbi.Protect;
        record.region_type = mbi.Type;

        if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)
        {
            wchar_t mapped[WG_PATH_CHARS]{};
            if (GetMappedFileNameW(process, mbi.BaseAddress, mapped, WG_PATH_CHARS) > 0)
            {
                // GetMappedFileName returns a device path (\\?\C:\...); normalise it.
                if (wcsncmp(mapped, L"\\??\\", 4) == 0 || wcsncmp(mapped, L"\\Device\\", 8) == 0)
                {
                    wchar_t driveTarget[WG_PATH_CHARS]{};
                    if (QueryDosDeviceW(mapped + 4, driveTarget, WG_PATH_CHARS) > 0)
                    {
                        std::wstring normalised(driveTarget);
                        normalised += (mapped + 4 + wcslen(driveTarget));
                        CopyString(record.backing_file, normalised.c_str());
                    }
                    else
                    {
                        CopyString(record.backing_file, mapped);
                    }
                }
                else
                {
                    CopyString(record.backing_file, mapped);
                }

                record.has_backing_file = 1;
            }
        }

        out[written] = record;
        ++written;
    }

    CloseHandle(process);

    *count = written;
    if (written > capacity)
    {
        SetError(WG_ERR_BUFFER);
        return WG_ERR_BUFFER;
    }

    SetError(WG_OK);
    return WG_OK;
}

WG_API int32_t WG_CALL wg_read_text_section(uint32_t pid, uint64_t base, uint8_t* out, uint32_t capacity, uint32_t* written)
{
    if (out == nullptr || written == nullptr || capacity == 0)
    {
        SetError(WG_ERR_FAILURE);
        return WG_ERR_FAILURE;
    }

    *written = 0;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process == nullptr)
    {
        SetError(WG_ERR_ACCESS);
        return WG_ERR_ACCESS;
    }

    uint32_t virtualAddress = 0, virtualSize = 0, rawSize = 0;
    if (!FindTextSection(process, base, &virtualAddress, &virtualSize, &rawSize))
    {
        CloseHandle(process);
        SetError(WG_ERR_NOT_FOUND);
        return WG_ERR_NOT_FOUND;
    }

    // Hash the raw (file-aligned) portion of .text so it is comparable with the
    // on-disk hash. Fall back to the virtual size when the raw size is absent.
    const uint32_t length = (rawSize > 0 ? rawSize : virtualSize);
    const uint32_t toRead = std::min(length, capacity);

    SIZE_T read = 0;
    const BOOL ok = ReadProcessMemory(
        process,
        reinterpret_cast<LPCVOID>(base + virtualAddress),
        out,
        toRead,
        &read);

    CloseHandle(process);

    if (!ok)
    {
        SetError(WG_ERR_ACCESS);
        return WG_ERR_ACCESS;
    }

    *written = static_cast<uint32_t>(read);
    SetError(WG_OK);
    return WG_OK;
}

#endif // _WIN32
