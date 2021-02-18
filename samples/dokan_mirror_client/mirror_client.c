
#include "../../dokan/dokan.h"
#include "../../dokan/fileinfo.h"
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <winbase.h>
#include <tchar.h>

#include <trace.h>
#include <mirror_proto.h>
#include <transport.h>
#include <getopt.h>

//#define WIN10_ENABLE_LONG_PATH
#ifdef WIN10_ENABLE_LONG_PATH
//dirty but should be enough
#define DOKAN_MAX_PATH 32768
#else
#define DOKAN_MAX_PATH MAX_PATH
#endif // DEBUG

BOOL g_UseStdErr;
BOOL g_DebugMode;
BOOL g_CaseSensitive;
BOOL g_HasSeSecurityPrivilege;
BOOL g_ImpersonateCallerUser;

static void DbgPrint(LPCWSTR format, ...) {
    if (g_DebugMode) {
        const WCHAR* outputString;
        WCHAR* buffer = NULL;
        size_t length;
        va_list argp;

        va_start(argp, format);
        length = _vscwprintf(format, argp) + 1;
        buffer = _malloca(length * sizeof(WCHAR));
        if (buffer) {
            vswprintf_s(buffer, length, format, argp);
            outputString = buffer;
        }
        else {
            outputString = format;
        }
        if (g_UseStdErr)
            fputws(outputString, stderr);
        else
            OutputDebugStringW(outputString);
        if (buffer)
            _freea(buffer);
        va_end(argp);
        if (g_UseStdErr)
            fflush(stderr);
    }
}

static WCHAR RootDirectory[DOKAN_MAX_PATH] = L"C:";
static WCHAR MountPoint[DOKAN_MAX_PATH] = L"M:\\";
static WCHAR UNCName[DOKAN_MAX_PATH] = L"";
static TCHAR TransportUrl[DOKAN_MAX_PATH] = _T("");
struct transport* tp = NULL;


static void GetFilePath(PWCHAR filePath, ULONG numberOfElements,
    LPCWSTR FileName) {
    wcsncpy_s(filePath, numberOfElements, RootDirectory, wcslen(RootDirectory));
    size_t unclen = wcslen(UNCName);
    if (unclen > 0 && _wcsnicmp(FileName, UNCName, unclen) == 0) {
        if (_wcsnicmp(FileName + unclen, L".", 1) != 0) {
            wcsncat_s(filePath, numberOfElements, FileName + unclen,
                wcslen(FileName) - unclen);
        }
    }
    else {
        wcsncat_s(filePath, numberOfElements, FileName, wcslen(FileName));
    }
}

static void PrintUserName(PDOKAN_FILE_INFO DokanFileInfo) {
    HANDLE handle;
    UCHAR buffer[1024];
    DWORD returnLength;
    WCHAR accountName[256];
    WCHAR domainName[256];
    DWORD accountLength = sizeof(accountName) / sizeof(WCHAR);
    DWORD domainLength = sizeof(domainName) / sizeof(WCHAR);
    PTOKEN_USER tokenUser;
    SID_NAME_USE snu;

    if (!g_DebugMode)
        return;

    handle = DokanOpenRequestorToken(DokanFileInfo);
    if (handle == INVALID_HANDLE_VALUE) {
        DbgPrint(L"  DokanOpenRequestorToken failed\n");
        return;
    }

    if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer),
        &returnLength)) {
        DbgPrint(L"  GetTokenInformaiton failed: %d\n", GetLastError());
        CloseHandle(handle);
        return;
    }

    CloseHandle(handle);

    tokenUser = (PTOKEN_USER)buffer;
    if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName, &accountLength,
        domainName, &domainLength, &snu)) {
        DbgPrint(L"  LookupAccountSid failed: %d\n", GetLastError());
        return;
    }

    DbgPrint(L"  AccountName: %s, DomainName: %s\n", accountName, domainName);
}

static BOOL AddSeSecurityNamePrivilege() {
    HANDLE token = 0;
    DbgPrint(
        L"## Attempting to add SE_SECURITY_NAME privilege to process token ##\n");
    DWORD err;
    LUID luid;
    if (!LookupPrivilegeValue(0, SE_SECURITY_NAME, &luid)) {
        err = GetLastError();
        if (err != ERROR_SUCCESS) {
            DbgPrint(L"  failed: Unable to lookup privilege value. error = %u\n",
                err);
            return FALSE;
        }
    }

    LUID_AND_ATTRIBUTES attr;
    attr.Attributes = SE_PRIVILEGE_ENABLED;
    attr.Luid = luid;

    TOKEN_PRIVILEGES priv;
    priv.PrivilegeCount = 1;
    priv.Privileges[0] = attr;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        err = GetLastError();
        if (err != ERROR_SUCCESS) {
            DbgPrint(L"  failed: Unable obtain process token. error = %u\n", err);
            return FALSE;
        }
    }

    TOKEN_PRIVILEGES oldPriv;
    DWORD retSize;
    AdjustTokenPrivileges(token, FALSE, &priv, sizeof(TOKEN_PRIVILEGES), &oldPriv,
        &retSize);
    err = GetLastError();
    if (err != ERROR_SUCCESS) {
        DbgPrint(L"  failed: Unable to adjust token privileges: %u\n", err);
        CloseHandle(token);
        return FALSE;
    }

    BOOL privAlreadyPresent = FALSE;
    for (unsigned int i = 0; i < oldPriv.PrivilegeCount; i++) {
        if (oldPriv.Privileges[i].Luid.HighPart == luid.HighPart &&
            oldPriv.Privileges[i].Luid.LowPart == luid.LowPart) {
            privAlreadyPresent = TRUE;
            break;
        }
    }
    DbgPrint(privAlreadyPresent ? L"  success: privilege already present\n"
        : L"  success: privilege added\n");
    if (token)
        CloseHandle(token);
    return TRUE;
}

#define MirrorCheckFlag(val, flag)                                             \
  if (val & flag) {                                                            \
    DbgPrint(L"\t" L#flag L"\n");                                              \
  }

static NTSTATUS DOKAN_CALLBACK
MirrorClientCreateFile(
    LPCWSTR FileName, 
    PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
    ACCESS_MASK DesiredAccess, 
    ULONG FileAttributes,
    ULONG ShareAccess, 
    ULONG CreateDisposition,
    ULONG CreateOptions, 
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
    struct mirror_pdu* pdu = NULL;
    struct transport_connection* conn = NULL;
	struct mirror_create_request* req;
    size_t len;
	int ret;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    pr_debug(_T("-> MirrorCreateFile(), FileName(%s)\n"), FileName);

	conn = tp->create(tp, TransportUrl, FALSE);
	if (!conn) {
		pr_err(_T("transport(%s) create conn failed\n"), tp->name);
		goto Cleanup;
	}

    ret = tp->connect(conn);
	if (ret != 0) {
		pr_err(_T("connect failed\n"));
        goto Cleanup;
	}

	len = wcslen(FileName);
	pdu = alloc_mirror_pdu(sizeof(*pdu) + len * sizeof(WCHAR));

    if (!pdu) {
        pr_err(_T("allocate pdu for create_req failed\n"));
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

	pdu->major_function = IRP_MJ_CREATE;
	pdu->minor_function = 0;

	req = &pdu->u.create_req;
	req->security_context = *SecurityContext;
	req->access_mask = DesiredAccess;
	req->file_attributes = FileAttributes;
	req->share_access = ShareAccess;
	req->create_disposition = CreateDisposition;
	req->create_options = CreateOptions;
	memcpy(&req->file_info, DokanFileInfo, sizeof(DOKAN_FILE_INFO));
	wcsncpy(req->filename, FileName, len);

	ret = tp->send(conn, pdu, pdu->length);
	if (ret < 0) {
		pr_err(_T("send pdu failed\n"));
        goto Cleanup;
	}
    
    free_mirror_pdu(&pdu);

    pdu = mirror_recv_pdu(conn);
    if (!pdu) {
        pr_err(_T("recv create_resp failed\n"));
        goto Cleanup;
    }

    pr_info(_T("receive pdu, major(%d) minor(%d)\n"), pdu->major_function, pdu->minor_function);
    if (pdu->major_function != IRP_MJ_CREATE) {
        pr_err(_T("receive invalid create_resp\n"));
        goto Cleanup;
    }

    status = pdu->u.create_resp.status;

    pr_info(_T("create_resp status(0x%08x)\n"), status);

    DokanFileInfo->Context = pdu->u.create_resp.file_info.Context;

Cleanup:
    if (conn) {
        tp->destroy(conn);
    }

    free_mirror_pdu(&pdu);

    return status;
}

#pragma warning(push)
#pragma warning(disable : 4305)

static void DOKAN_CALLBACK MirrorClientCloseFile(
    LPCWSTR FileName,
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
	struct transport_connection* conn = NULL;
	struct mirror_pdu* pdu = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	size_t len;
	int ret;

	pr_debug(_T("-> MirrorCloseFile(), FileName(%s)\n"), FileName);

	len = wcslen(FileName);
	pdu = alloc_mirror_pdu(sizeof(*pdu) + len * sizeof(WCHAR));
	if (!pdu) {
		pr_err(_T("allocate close_req pdu failed\n"));
		status = STATUS_NO_MEMORY;
		goto CLeanup;
	}

	pdu->major_function = IRP_MJ_CLOSE;
	pdu->minor_function = 0;

	wcsncpy(pdu->u.close_req.filename, FileName, len);
	memcpy(&pdu->u.close_req.file_info, DokanFileInfo, sizeof(DOKAN_FILE_INFO));

	conn = tp->create(tp, TransportUrl, FALSE);
	if (!conn) {
		pr_err(_T("transport(%s) create conn failed\n"), tp->name);
		goto CLeanup;
	}

	ret = tp->connect(conn);
	if (ret != 0) {
		pr_err(_T("connect failed\n"));
		goto CLeanup;
	}

	ret = tp->send(conn, pdu, pdu->length);
	if (ret < 0) {
		pr_err(_T("send close_req failed\n"));
		goto CLeanup;
	}

	free_mirror_pdu(&pdu);

	pdu = mirror_recv_pdu(conn);
	if (!pdu) {
		pr_err(_T("receive close_resp failed\n"));
		goto CLeanup;
	}

	if (pdu->major_function != IRP_MJ_CLOSE) {
		pr_err(_T("receive invalid response, major(%d)\n"), pdu->major_function);
		goto CLeanup;
	}

	status = pdu->u.close_resp.status;
	pr_info(_T("close_resp status(0x%08x)\n"), status);
	DokanFileInfo->Context = pdu->u.cleanup_resp.file_info.Context;

CLeanup:

	if (conn) {
		tp->destroy(conn);
	}

	free_mirror_pdu(&pdu);
}

static void DOKAN_CALLBACK MirrorClientCleanup(
    LPCWSTR FileName,
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
	struct transport_connection* conn = NULL;
	struct mirror_pdu* pdu = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	size_t len;
	int ret;

	pr_debug(_T("-> MirrorCleanup(), FileName(%s)\n"), FileName);

	len = wcslen(FileName);
	pdu = alloc_mirror_pdu(sizeof(*pdu) + len * sizeof(WCHAR));
	if (!pdu) {
		pr_err(_T("allocate cleanup_req pdu failed\n"));
		status = STATUS_NO_MEMORY;
		goto CLeanup;
	}

	pdu->major_function = IRP_MJ_CLEANUP;
	pdu->minor_function = 0;

	wcsncpy(pdu->u.cleanup_req.filename, FileName, len);
	memcpy(&pdu->u.cleanup_req.file_info, DokanFileInfo, sizeof(DOKAN_FILE_INFO));

	conn = tp->create(tp, TransportUrl, FALSE);
	if (!conn) {
		pr_err(_T("transport(%s) create conn failed\n"), tp->name);
		goto CLeanup;
	}

	ret = tp->connect(conn);
	if (ret != 0) {
		pr_err(_T("connect failed\n"));
		goto CLeanup;
	}

	ret = tp->send(conn, pdu, pdu->length);
	if (ret < 0) {
		pr_err(_T("send cleanup_req failed\n"));
		goto CLeanup;
	}

	free_mirror_pdu(&pdu);

	pdu = mirror_recv_pdu(conn);
	if (!pdu) {
		pr_err(_T("receive cleanup_resp failed\n"));
		goto CLeanup;
	}

	if (pdu->major_function != IRP_MJ_CLEANUP) {
		pr_err(_T("receive invalid response, major(%d)\n"), pdu->major_function);
		goto CLeanup;
	}

	status = pdu->u.cleanup_resp.status;
	pr_info(_T("cleanup_resp status(0x%08x)\n"), status);
    DokanFileInfo->Context = pdu->u.cleanup_resp.file_info.Context;

CLeanup:

	if (conn) {
		tp->destroy(conn);
	}

	free_mirror_pdu(&pdu);
}

static NTSTATUS DOKAN_CALLBACK MirrorReadFile(LPCWSTR FileName, LPVOID Buffer,
    DWORD BufferLength,
    LPDWORD ReadLength,
    LONGLONG Offset,
    PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    HANDLE handle = (HANDLE)DokanFileInfo->Context;
    ULONG offset = (ULONG)Offset;
    BOOL opened = FALSE;

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"ReadFile : %s\n", filePath);

    if (!handle || handle == INVALID_HANDLE_VALUE) {
        DbgPrint(L"\tinvalid handle, cleanuped?\n");
        handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, 0, NULL);
        if (handle == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            DbgPrint(L"\tCreateFile error : %d\n\n", error);
            return DokanNtStatusFromWin32(error);
        }
        opened = TRUE;
    }

    LARGE_INTEGER distanceToMove;
    distanceToMove.QuadPart = Offset;
    if (!SetFilePointerEx(handle, distanceToMove, NULL, FILE_BEGIN)) {
        DWORD error = GetLastError();
        DbgPrint(L"\tseek error, offset = %d\n\n", offset);
        if (opened)
            CloseHandle(handle);
        return DokanNtStatusFromWin32(error);
    }

    if (!ReadFile(handle, Buffer, BufferLength, ReadLength, NULL)) {
        DWORD error = GetLastError();
        DbgPrint(L"\tread error = %u, buffer length = %d, read length = %d\n\n",
            error, BufferLength, *ReadLength);
        if (opened)
            CloseHandle(handle);
        return DokanNtStatusFromWin32(error);

    }
    else {
        DbgPrint(L"\tByte to read: %d, Byte read %d, offset %d\n\n", BufferLength,
            *ReadLength, offset);
    }

    if (opened)
        CloseHandle(handle);

    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorWriteFile(LPCWSTR FileName, LPCVOID Buffer,
    DWORD NumberOfBytesToWrite,
    LPDWORD NumberOfBytesWritten,
    LONGLONG Offset,
    PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    HANDLE handle = (HANDLE)DokanFileInfo->Context;
    BOOL opened = FALSE;

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"WriteFile : %s, offset %I64d, length %d\n", filePath, Offset,
        NumberOfBytesToWrite);

    // reopen the file
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        DbgPrint(L"\tinvalid handle, cleanuped?\n");
        handle = CreateFile(filePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
            OPEN_EXISTING, 0, NULL);
        if (handle == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            DbgPrint(L"\tCreateFile error : %d\n\n", error);
            return DokanNtStatusFromWin32(error);
        }
        opened = TRUE;
    }

    UINT64 fileSize = 0;
    DWORD fileSizeLow = 0;
    DWORD fileSizeHigh = 0;
    fileSizeLow = GetFileSize(handle, &fileSizeHigh);
    if (fileSizeLow == INVALID_FILE_SIZE) {
        DWORD error = GetLastError();
        DbgPrint(L"\tcan not get a file size error = %d\n", error);
        if (opened)
            CloseHandle(handle);
        return DokanNtStatusFromWin32(error);
    }

    fileSize = ((UINT64)fileSizeHigh << 32) | fileSizeLow;

    LARGE_INTEGER distanceToMove;
    if (DokanFileInfo->WriteToEndOfFile) {
        LARGE_INTEGER z;
        z.QuadPart = 0;
        if (!SetFilePointerEx(handle, z, NULL, FILE_END)) {
            DWORD error = GetLastError();
            DbgPrint(L"\tseek error, offset = EOF, error = %d\n", error);
            if (opened)
                CloseHandle(handle);
            return DokanNtStatusFromWin32(error);
        }
    }
    else {
        // Paging IO cannot write after allocate file size.
        if (DokanFileInfo->PagingIo) {
            if ((UINT64)Offset >= fileSize) {
                *NumberOfBytesWritten = 0;
                if (opened)
                    CloseHandle(handle);
                return STATUS_SUCCESS;
            }

            if (((UINT64)Offset + NumberOfBytesToWrite) > fileSize) {
                UINT64 bytes = fileSize - Offset;
                if (bytes >> 32) {
                    NumberOfBytesToWrite = (DWORD)(bytes & 0xFFFFFFFFUL);
                }
                else {
                    NumberOfBytesToWrite = (DWORD)bytes;
                }
            }
        }

        if ((UINT64)Offset > fileSize) {
            // In the mirror sample helperZeroFileData is not necessary. NTFS will
            // zero a hole.
            // But if user's file system is different from NTFS( or other Windows's
            // file systems ) then  users will have to zero the hole themselves.
        }

        distanceToMove.QuadPart = Offset;
        if (!SetFilePointerEx(handle, distanceToMove, NULL, FILE_BEGIN)) {
            DWORD error = GetLastError();
            DbgPrint(L"\tseek error, offset = %I64d, error = %d\n", Offset, error);
            if (opened)
                CloseHandle(handle);
            return DokanNtStatusFromWin32(error);
        }
    }

    if (!WriteFile(handle, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten,
        NULL)) {
        DWORD error = GetLastError();
        DbgPrint(L"\twrite error = %u, buffer length = %d, write length = %d\n",
            error, NumberOfBytesToWrite, *NumberOfBytesWritten);
        if (opened)
            CloseHandle(handle);
        return DokanNtStatusFromWin32(error);

    }
    else {
        DbgPrint(L"\twrite %d, offset %I64d\n\n", *NumberOfBytesWritten, Offset);
    }

    // close the file when it is reopened
    if (opened)
        CloseHandle(handle);

    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorFlushFileBuffers(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    HANDLE handle = (HANDLE)DokanFileInfo->Context;

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"FlushFileBuffers : %s\n", filePath);

    if (!handle || handle == INVALID_HANDLE_VALUE) {
        DbgPrint(L"\tinvalid handle\n\n");
        return STATUS_SUCCESS;
    }

    if (FlushFileBuffers(handle)) {
        return STATUS_SUCCESS;
    }
    else {
        DWORD error = GetLastError();
        DbgPrint(L"\tflush error code = %d\n", error);
        return DokanNtStatusFromWin32(error);
    }
}

static NTSTATUS DOKAN_CALLBACK MirrorClientGetFileInformation(
    LPCWSTR FileName,
    LPBY_HANDLE_FILE_INFORMATION HandleFileInformation,
    PDOKAN_FILE_INFO DokanFileInfo
)
{
    struct transport_connection* conn = NULL;
    struct mirror_pdu* pdu = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    size_t len;
    int ret;

    pr_debug(_T("-> MirrorGetFileInformation(), FileName(%s)\n"), FileName);

    len = wcslen(FileName);
    pdu = alloc_mirror_pdu(sizeof(*pdu) + len * sizeof(WCHAR));
    if (!pdu) {
        pr_err(_T("allocate queryinfo_req pdu failed\n"));
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    pdu->major_function = IRP_MJ_QUERY_INFORMATION;
    pdu->minor_function = 0;

    wcsncpy(pdu->u.queryinfo_req.file_name, FileName, len);
    memcpy(&pdu->u.queryinfo_req.file_info, DokanFileInfo, sizeof(DOKAN_FILE_INFO));

	conn = tp->create(tp, TransportUrl, FALSE);
	if (!conn) {
		pr_err(_T("transport(%s) create conn failed\n"), tp->name);
        goto Cleanup;
	}

	ret = tp->connect(conn);
	if (ret != 0) {
		pr_err(_T("connect failed\n"));
        goto Cleanup;
	}

    ret = tp->send(conn, pdu, pdu->length);
    if (ret < 0) {
        pr_err(_T("send queryinfo_req failed\n"));
        goto Cleanup;
    }

    free_mirror_pdu(&pdu);

    pdu = mirror_recv_pdu(conn);
    if (!pdu) {
        pr_err(_T("receive queryinfo_resp failed\n"));
        goto Cleanup;
    }

    if (pdu->major_function != IRP_MJ_QUERY_INFORMATION) {
        pr_err(_T("receive invalid response, major(%d)\n"), pdu->major_function);
        goto Cleanup;
    }

    status = pdu->u.queryinfo_resp.status;
    pr_info(_T("queryinfo_resp status(0x%08x)\n"), status);

    if (status == STATUS_SUCCESS) {
        memcpy(
            HandleFileInformation,
            &pdu->u.queryinfo_resp.by_handle_file_info,
            sizeof(BY_HANDLE_FILE_INFORMATION)
        );
    }

Cleanup:
    
    if (conn) {
        tp->destroy(conn);
    }

    free_mirror_pdu(&pdu);

    return status;
}


static NTSTATUS DOKAN_CALLBACK
MirrorClientFindFiles(
    LPCWSTR FileName,
    PFillFindData FillFindData, // function pointer
    PDOKAN_FILE_INFO DokanFileInfo
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    struct transport_connection* conn = NULL;
    struct mirror_pdu* pdu;
    size_t len;
    int ret;
    int count = 0;

    pr_debug(_T("-> MirrorClientFindFiles(), FileName(%s)\n"), FileName);

    len = wcslen(FileName);
    pdu = alloc_mirror_pdu(sizeof(*pdu) + len * sizeof(WCHAR));
    if (!pdu) {
        pr_err(_T("allocate findfiles_req pdu failed\n"));
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    pdu->type = MIRROR_PDU_FIND_FILES_REQUEST;

    wcsncpy(pdu->u.findfiles_req.file_name, FileName, len);
    memcpy(&pdu->u.findfiles_req.file_info, DokanFileInfo, sizeof(DOKAN_FILE_INFO));

    conn = tp->create(tp, TransportUrl, FALSE);
    if (!conn) {
        pr_err(_T("transport(%s) create conn failed\n"), tp->name);
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    ret = tp->connect(conn);
    if (ret != 0) {
        pr_err(_T("connect failed\n"));
        goto Cleanup;
    }

    ret = tp->send(conn, pdu, pdu->length);
    if (ret < 0) {
        pr_err(_T("send queryinfo_req failed\n"));
        goto Cleanup;
    }

    free_mirror_pdu(&pdu);

    while (1) {
        pdu = mirror_recv_pdu(conn);
        if (!pdu) {
            pr_err(_T("receive find-files response failed\n"));
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        if (pdu->type != MIRROR_PDU_FIND_FILES_RESPONSE) {
            pr_err(_T("invalid find-finds response type(%d)\n"), pdu->type);
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        if (pdu->u.findfiles_resp.status == STATUS_NO_MORE_FILES) {
            status = STATUS_SUCCESS;
            break;
        }

        if (pdu->u.findfiles_resp.status != STATUS_SUCCESS) {
            pr_err(_T("receive failed find-files response, status(0x%08x)\n"),
                pdu->u.findfiles_resp.status);
            status = pdu->u.findfiles_resp.status;
            break;
        }

        pr_info(_T("    [%d]: %s\n"), 
            count, pdu->u.findfiles_resp.find_data.cFileName);

        FillFindData(&pdu->u.findfiles_resp.find_data, DokanFileInfo);
        count++;
    }

Cleanup:
    if (conn) {
        tp->destroy(conn);
    }

    if (pdu) {
        free_mirror_pdu(&pdu);
    }

    return status;
}


static NTSTATUS DOKAN_CALLBACK
MirrorDeleteFile(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    HANDLE handle = (HANDLE)DokanFileInfo->Context;

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
    DbgPrint(L"DeleteFile %s - %d\n", filePath, DokanFileInfo->DeleteOnClose);

    DWORD dwAttrib = GetFileAttributes(filePath);

    if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
        (dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
        return STATUS_ACCESS_DENIED;

    if (handle && handle != INVALID_HANDLE_VALUE) {
        FILE_DISPOSITION_INFO fdi;
        fdi.DeleteFile = DokanFileInfo->DeleteOnClose;
        if (!SetFileInformationByHandle(handle, FileDispositionInfo, &fdi,
            sizeof(FILE_DISPOSITION_INFO)))
            return DokanNtStatusFromWin32(GetLastError());
    }

    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorDeleteDirectory(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    // HANDLE	handle = (HANDLE)DokanFileInfo->Context;
    HANDLE hFind;
    WIN32_FIND_DATAW findData;
    size_t fileLen;

    ZeroMemory(filePath, sizeof(filePath));
    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"DeleteDirectory %s - %d\n", filePath,
        DokanFileInfo->DeleteOnClose);

    if (!DokanFileInfo->DeleteOnClose)
        //Dokan notify that the file is requested not to be deleted.
        return STATUS_SUCCESS;

    fileLen = wcslen(filePath);
    if (filePath[fileLen - 1] != L'\\') {
        filePath[fileLen++] = L'\\';
    }
    if (fileLen + 1 >= DOKAN_MAX_PATH)
        return STATUS_BUFFER_OVERFLOW;
    filePath[fileLen] = L'*';
    filePath[fileLen + 1] = L'\0';

    hFind = FindFirstFile(filePath, &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        DbgPrint(L"\tDeleteDirectory error code = %d\n\n", error);
        return DokanNtStatusFromWin32(error);
    }

    do {
        if (wcscmp(findData.cFileName, L"..") != 0 &&
            wcscmp(findData.cFileName, L".") != 0) {
            FindClose(hFind);
            DbgPrint(L"\tDirectory is not empty: %s\n", findData.cFileName);
            return STATUS_DIRECTORY_NOT_EMPTY;
        }
    } while (FindNextFile(hFind, &findData) != 0);

    DWORD error = GetLastError();

    FindClose(hFind);

    if (error != ERROR_NO_MORE_FILES) {
        DbgPrint(L"\tDeleteDirectory error code = %d\n\n", error);
        return DokanNtStatusFromWin32(error);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorMoveFile(LPCWSTR FileName, // existing file name
    LPCWSTR NewFileName, BOOL ReplaceIfExisting,
    PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    WCHAR newFilePath[DOKAN_MAX_PATH];
    HANDLE handle;
    DWORD bufferSize;
    BOOL result;
    size_t newFilePathLen;

    PFILE_RENAME_INFO renameInfo = NULL;

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);
    if (wcslen(NewFileName) && NewFileName[0] != ':') {
        GetFilePath(newFilePath, DOKAN_MAX_PATH, NewFileName);
    }
    else {
        // For a stream rename, FileRenameInfo expect the FileName param without the filename
        // like :<stream name>:<stream type>
        wcsncpy_s(newFilePath, DOKAN_MAX_PATH, NewFileName, wcslen(NewFileName));
    }

    DbgPrint(L"MoveFile %s -> %s\n\n", filePath, newFilePath);
    handle = (HANDLE)DokanFileInfo->Context;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        DbgPrint(L"\tinvalid handle\n\n");
        return STATUS_INVALID_HANDLE;
    }

    newFilePathLen = wcslen(newFilePath);

    // the PFILE_RENAME_INFO struct has space for one WCHAR for the name at
    // the end, so that
    // accounts for the null terminator

    bufferSize = (DWORD)(sizeof(FILE_RENAME_INFO) +
        newFilePathLen * sizeof(newFilePath[0]));

    renameInfo = (PFILE_RENAME_INFO)malloc(bufferSize);
    if (!renameInfo) {
        return STATUS_BUFFER_OVERFLOW;
    }
    ZeroMemory(renameInfo, bufferSize);

    renameInfo->ReplaceIfExists =
        ReplaceIfExisting
        ? TRUE
        : FALSE; // some warning about converting BOOL to BOOLEAN
    renameInfo->RootDirectory = NULL; // hope it is never needed, shouldn't be
    renameInfo->FileNameLength =
        (DWORD)newFilePathLen *
        sizeof(newFilePath[0]); // they want length in bytes

    wcscpy_s(renameInfo->FileName, newFilePathLen + 1, newFilePath);

    result = SetFileInformationByHandle(handle, FileRenameInfo, renameInfo,
        bufferSize);

    free(renameInfo);

    if (result) {
        return STATUS_SUCCESS;
    }
    else {
        DWORD error = GetLastError();
        DbgPrint(L"\tMoveFile error = %u\n", error);
        return DokanNtStatusFromWin32(error);
    }
}

static NTSTATUS DOKAN_CALLBACK MirrorLockFile(LPCWSTR FileName,
    LONGLONG ByteOffset,
    LONGLONG Length,
    PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    HANDLE handle;
    LARGE_INTEGER offset;
    LARGE_INTEGER length;

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"LockFile %s\n", filePath);

    handle = (HANDLE)DokanFileInfo->Context;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        DbgPrint(L"\tinvalid handle\n\n");
        return STATUS_INVALID_HANDLE;
    }

    length.QuadPart = Length;
    offset.QuadPart = ByteOffset;

    if (!LockFile(handle, offset.LowPart, offset.HighPart, length.LowPart,
        length.HighPart)) {
        DWORD error = GetLastError();
        DbgPrint(L"\terror code = %d\n\n", error);
        return DokanNtStatusFromWin32(error);
    }

    DbgPrint(L"\tsuccess\n\n");
    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetEndOfFile(
    LPCWSTR FileName, LONGLONG ByteOffset, PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    HANDLE handle;
    LARGE_INTEGER offset;

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"SetEndOfFile %s, %I64d\n", filePath, ByteOffset);

    handle = (HANDLE)DokanFileInfo->Context;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        DbgPrint(L"\tinvalid handle\n\n");
        return STATUS_INVALID_HANDLE;
    }

    offset.QuadPart = ByteOffset;
    if (!SetFilePointerEx(handle, offset, NULL, FILE_BEGIN)) {
        DWORD error = GetLastError();
        DbgPrint(L"\tSetFilePointer error: %d, offset = %I64d\n\n", error,
            ByteOffset);
        return DokanNtStatusFromWin32(error);
    }

    if (!SetEndOfFile(handle)) {
        DWORD error = GetLastError();
        DbgPrint(L"\tSetEndOfFile error code = %d\n\n", error);
        return DokanNtStatusFromWin32(error);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetAllocationSize(
    LPCWSTR FileName, LONGLONG AllocSize, PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    HANDLE handle;
    LARGE_INTEGER fileSize;

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"SetAllocationSize %s, %I64d\n", filePath, AllocSize);

    handle = (HANDLE)DokanFileInfo->Context;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        DbgPrint(L"\tinvalid handle\n\n");
        return STATUS_INVALID_HANDLE;
    }

    if (GetFileSizeEx(handle, &fileSize)) {
        if (AllocSize < fileSize.QuadPart) {
            fileSize.QuadPart = AllocSize;
            if (!SetFilePointerEx(handle, fileSize, NULL, FILE_BEGIN)) {
                DWORD error = GetLastError();
                DbgPrint(L"\tSetAllocationSize: SetFilePointer eror: %d, "
                    L"offset = %I64d\n\n",
                    error, AllocSize);
                return DokanNtStatusFromWin32(error);
            }
            if (!SetEndOfFile(handle)) {
                DWORD error = GetLastError();
                DbgPrint(L"\tSetEndOfFile error code = %d\n\n", error);
                return DokanNtStatusFromWin32(error);
            }
        }
    }
    else {
        DWORD error = GetLastError();
        DbgPrint(L"\terror code = %d\n\n", error);
        return DokanNtStatusFromWin32(error);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetFileAttributes(
    LPCWSTR FileName, DWORD FileAttributes, PDOKAN_FILE_INFO DokanFileInfo) {
    UNREFERENCED_PARAMETER(DokanFileInfo);

    WCHAR filePath[DOKAN_MAX_PATH];

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"SetFileAttributes %s 0x%x\n", filePath, FileAttributes);

    if (FileAttributes != 0) {
        if (!SetFileAttributes(filePath, FileAttributes)) {
            DWORD error = GetLastError();
            DbgPrint(L"\terror code = %d\n\n", error);
            return DokanNtStatusFromWin32(error);
        }
    }
    else {
        // case FileAttributes == 0 :
        // MS-FSCC 2.6 File Attributes : There is no file attribute with the value 0x00000000
        // because a value of 0x00000000 in the FileAttributes field means that the file attributes for this file MUST NOT be changed when setting basic information for the file
        DbgPrint(L"Set 0 to FileAttributes means MUST NOT be changed. Didn't call "
            L"SetFileAttributes function. \n");
    }

    DbgPrint(L"\n");
    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorSetFileTime(LPCWSTR FileName, CONST FILETIME* CreationTime,
    CONST FILETIME* LastAccessTime, CONST FILETIME* LastWriteTime,
    PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    HANDLE handle;

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"SetFileTime %s\n", filePath);

    handle = (HANDLE)DokanFileInfo->Context;

    if (!handle || handle == INVALID_HANDLE_VALUE) {
        DbgPrint(L"\tinvalid handle\n\n");
        return STATUS_INVALID_HANDLE;
    }

    if (!SetFileTime(handle, CreationTime, LastAccessTime, LastWriteTime)) {
        DWORD error = GetLastError();
        DbgPrint(L"\terror code = %d\n\n", error);
        return DokanNtStatusFromWin32(error);
    }

    DbgPrint(L"\n");
    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
MirrorUnlockFile(LPCWSTR FileName, LONGLONG ByteOffset, LONGLONG Length,
    PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    HANDLE handle;
    LARGE_INTEGER length;
    LARGE_INTEGER offset;

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"UnlockFile %s\n", filePath);

    handle = (HANDLE)DokanFileInfo->Context;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        DbgPrint(L"\tinvalid handle\n\n");
        return STATUS_INVALID_HANDLE;
    }

    length.QuadPart = Length;
    offset.QuadPart = ByteOffset;

    if (!UnlockFile(handle, offset.LowPart, offset.HighPart, length.LowPart,
        length.HighPart)) {
        DWORD error = GetLastError();
        DbgPrint(L"\terror code = %d\n\n", error);
        return DokanNtStatusFromWin32(error);
    }

    DbgPrint(L"\tsuccess\n\n");
    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorGetFileSecurity(
    LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG BufferLength,
    PULONG LengthNeeded, PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    BOOLEAN requestingSaclInfo;

    UNREFERENCED_PARAMETER(DokanFileInfo);

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"GetFileSecurity %s\n", filePath);

    MirrorCheckFlag(*SecurityInformation, FILE_SHARE_READ);
    MirrorCheckFlag(*SecurityInformation, OWNER_SECURITY_INFORMATION);
    MirrorCheckFlag(*SecurityInformation, GROUP_SECURITY_INFORMATION);
    MirrorCheckFlag(*SecurityInformation, DACL_SECURITY_INFORMATION);
    MirrorCheckFlag(*SecurityInformation, SACL_SECURITY_INFORMATION);
    MirrorCheckFlag(*SecurityInformation, LABEL_SECURITY_INFORMATION);
    MirrorCheckFlag(*SecurityInformation, ATTRIBUTE_SECURITY_INFORMATION);
    MirrorCheckFlag(*SecurityInformation, SCOPE_SECURITY_INFORMATION);
    MirrorCheckFlag(*SecurityInformation,
        PROCESS_TRUST_LABEL_SECURITY_INFORMATION);
    MirrorCheckFlag(*SecurityInformation, BACKUP_SECURITY_INFORMATION);
    MirrorCheckFlag(*SecurityInformation, PROTECTED_DACL_SECURITY_INFORMATION);
    MirrorCheckFlag(*SecurityInformation, PROTECTED_SACL_SECURITY_INFORMATION);
    MirrorCheckFlag(*SecurityInformation, UNPROTECTED_DACL_SECURITY_INFORMATION);
    MirrorCheckFlag(*SecurityInformation, UNPROTECTED_SACL_SECURITY_INFORMATION);

    requestingSaclInfo = ((*SecurityInformation & SACL_SECURITY_INFORMATION) ||
        (*SecurityInformation & BACKUP_SECURITY_INFORMATION));

    if (!g_HasSeSecurityPrivilege) {
        *SecurityInformation &= ~SACL_SECURITY_INFORMATION;
        *SecurityInformation &= ~BACKUP_SECURITY_INFORMATION;
    }

    DbgPrint(L"  Opening new handle with READ_CONTROL access\n");
    HANDLE handle = CreateFile(
        filePath,
        READ_CONTROL | ((requestingSaclInfo && g_HasSeSecurityPrivilege)
            ? ACCESS_SYSTEM_SECURITY
            : 0),
        FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
        NULL, // security attribute
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, // |FILE_FLAG_NO_BUFFERING,
        NULL);

    if (!handle || handle == INVALID_HANDLE_VALUE) {
        DbgPrint(L"\tinvalid handle\n\n");
        int error = GetLastError();
        return DokanNtStatusFromWin32(error);
    }

    if (!GetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor,
        BufferLength, LengthNeeded)) {
        int error = GetLastError();
        if (error == ERROR_INSUFFICIENT_BUFFER) {
            DbgPrint(L"  GetUserObjectSecurity error: ERROR_INSUFFICIENT_BUFFER\n");
            CloseHandle(handle);
            return STATUS_BUFFER_OVERFLOW;
        }
        else {
            DbgPrint(L"  GetUserObjectSecurity error: %d\n", error);
            CloseHandle(handle);
            return DokanNtStatusFromWin32(error);
        }
    }

    // Ensure the Security Descriptor Length is set
    DWORD securityDescriptorLength =
        GetSecurityDescriptorLength(SecurityDescriptor);
    DbgPrint(L"  GetUserObjectSecurity return true,  *LengthNeeded = "
        L"securityDescriptorLength \n");
    *LengthNeeded = securityDescriptorLength;

    CloseHandle(handle);

    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetFileSecurity(
    LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG SecurityDescriptorLength,
    PDOKAN_FILE_INFO DokanFileInfo) {
    HANDLE handle;
    WCHAR filePath[DOKAN_MAX_PATH];

    UNREFERENCED_PARAMETER(SecurityDescriptorLength);

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"SetFileSecurity %s\n", filePath);

    handle = (HANDLE)DokanFileInfo->Context;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        DbgPrint(L"\tinvalid handle\n\n");
        return STATUS_INVALID_HANDLE;
    }

    if (!SetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor)) {
        int error = GetLastError();
        DbgPrint(L"  SetUserObjectSecurity error: %d\n", error);
        return DokanNtStatusFromWin32(error);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorGetVolumeInformation(
    LPWSTR VolumeNameBuffer, DWORD VolumeNameSize, LPDWORD VolumeSerialNumber,
    LPDWORD MaximumComponentLength, LPDWORD FileSystemFlags,
    LPWSTR FileSystemNameBuffer, DWORD FileSystemNameSize,
    PDOKAN_FILE_INFO DokanFileInfo) {
    UNREFERENCED_PARAMETER(DokanFileInfo);

    WCHAR volumeRoot[4];
    DWORD fsFlags = 0;

    wcscpy_s(VolumeNameBuffer, VolumeNameSize, L"DOKAN");

    if (VolumeSerialNumber)
        *VolumeSerialNumber = 0x19831116;
    if (MaximumComponentLength)
        *MaximumComponentLength = 255;
    if (FileSystemFlags) {
        *FileSystemFlags = FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK |
            FILE_PERSISTENT_ACLS | FILE_NAMED_STREAMS;
        if (g_CaseSensitive)
            *FileSystemFlags = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;
    }

    volumeRoot[0] = RootDirectory[0];
    volumeRoot[1] = ':';
    volumeRoot[2] = '\\';
    volumeRoot[3] = '\0';

    if (GetVolumeInformation(volumeRoot, NULL, 0, NULL, MaximumComponentLength,
        &fsFlags, FileSystemNameBuffer,
        FileSystemNameSize)) {

        if (FileSystemFlags)
            *FileSystemFlags &= fsFlags;

        if (MaximumComponentLength) {
            DbgPrint(L"GetVolumeInformation: max component length %u\n",
                *MaximumComponentLength);
        }
        if (FileSystemNameBuffer) {
            DbgPrint(L"GetVolumeInformation: file system name %s\n",
                FileSystemNameBuffer);
        }
        if (FileSystemFlags) {
            DbgPrint(L"GetVolumeInformation: got file system flags 0x%08x,"
                L" returning 0x%08x\n",
                fsFlags, *FileSystemFlags);
        }
    }
    else {

        DbgPrint(L"GetVolumeInformation: unable to query underlying fs,"
            L" using defaults.  Last error = %u\n",
            GetLastError());

        // File system name could be anything up to 10 characters.
        // But Windows check few feature availability based on file system name.
        // For this, it is recommended to set NTFS or FAT here.
        wcscpy_s(FileSystemNameBuffer, FileSystemNameSize, L"NTFS");
    }

    return STATUS_SUCCESS;
}

// Uncomment the function and set dokanOperations.GetDiskFreeSpace to personalize disk space
/*
static NTSTATUS DOKAN_CALLBACK MirrorDokanGetDiskFreeSpace(
    PULONGLONG FreeBytesAvailable, PULONGLONG TotalNumberOfBytes,
    PULONGLONG TotalNumberOfFreeBytes, PDOKAN_FILE_INFO DokanFileInfo) {
  UNREFERENCED_PARAMETER(DokanFileInfo);

  *FreeBytesAvailable = (ULONGLONG)(512 * 1024 * 1024);
  *TotalNumberOfBytes = 9223372036854775807;
  *TotalNumberOfFreeBytes = 9223372036854775807;

  return STATUS_SUCCESS;
}
*/

static NTSTATUS DOKAN_CALLBACK MirrorDokanGetDiskFreeSpace(
    PULONGLONG FreeBytesAvailable, PULONGLONG TotalNumberOfBytes,
    PULONGLONG TotalNumberOfFreeBytes, PDOKAN_FILE_INFO DokanFileInfo) {
    UNREFERENCED_PARAMETER(DokanFileInfo);

    DWORD SectorsPerCluster;
    DWORD BytesPerSector;
    DWORD NumberOfFreeClusters;
    DWORD TotalNumberOfClusters;
    WCHAR DriveLetter[3] = { 'C', ':', 0 };
    PWCHAR RootPathName;

    if (RootDirectory[0] == L'\\') { // UNC as Root
        RootPathName = RootDirectory;
    }
    else {
        DriveLetter[0] = RootDirectory[0];
        RootPathName = DriveLetter;
    }

    GetDiskFreeSpace(RootPathName, &SectorsPerCluster, &BytesPerSector,
        &NumberOfFreeClusters, &TotalNumberOfClusters);
    *FreeBytesAvailable =
        ((ULONGLONG)SectorsPerCluster) * BytesPerSector * NumberOfFreeClusters;
    *TotalNumberOfFreeBytes =
        ((ULONGLONG)SectorsPerCluster) * BytesPerSector * NumberOfFreeClusters;
    *TotalNumberOfBytes =
        ((ULONGLONG)SectorsPerCluster) * BytesPerSector * TotalNumberOfClusters;
    return STATUS_SUCCESS;
}

/**
 * Avoid #include <winternl.h> which as conflict with FILE_INFORMATION_CLASS
 * definition.
 * This only for MirrorFindStreams. Link with ntdll.lib still required.
 *
 * Not needed if you're not using NtQueryInformationFile!
 *
 * BEGIN
 */
#pragma warning(push)
#pragma warning(disable : 4201)
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
#pragma warning(pop)

NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationFile(
    _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass);
/**
 * END
 */

NTSTATUS DOKAN_CALLBACK
MirrorFindStreams(LPCWSTR FileName, PFillFindStreamData FillFindStreamData,
    PDOKAN_FILE_INFO DokanFileInfo) {
    WCHAR filePath[DOKAN_MAX_PATH];
    HANDLE hFind;
    WIN32_FIND_STREAM_DATA findData;
    DWORD error;
    int count = 0;

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    DbgPrint(L"FindStreams :%s\n", filePath);

    hFind = FindFirstStreamW(filePath, FindStreamInfoStandard, &findData, 0);

    if (hFind == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        DbgPrint(L"\tinvalid file handle. Error is %u\n\n", error);
        return DokanNtStatusFromWin32(error);
    }

    FillFindStreamData(&findData, DokanFileInfo);
    count++;

    while (FindNextStreamW(hFind, &findData) != 0) {
        FillFindStreamData(&findData, DokanFileInfo);
        count++;
    }

    error = GetLastError();
    FindClose(hFind);

    if (error != ERROR_HANDLE_EOF) {
        DbgPrint(L"\tFindNextStreamW error. Error is %u\n\n", error);
        return DokanNtStatusFromWin32(error);
    }

    DbgPrint(L"\tFindStreams return %d entries in %s\n\n", count, filePath);

    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorMounted(PDOKAN_FILE_INFO DokanFileInfo) {
    UNREFERENCED_PARAMETER(DokanFileInfo);

    DbgPrint(L"Mounted\n");
    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorUnmounted(PDOKAN_FILE_INFO DokanFileInfo) {
    UNREFERENCED_PARAMETER(DokanFileInfo);

    DbgPrint(L"Unmounted\n");
    return STATUS_SUCCESS;
}

#pragma warning(pop)

BOOL WINAPI CtrlHandler(DWORD dwCtrlType) {
    switch (dwCtrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        SetConsoleCtrlHandler(CtrlHandler, FALSE);
        DokanRemoveMountPoint(MountPoint);
        return TRUE;
    default:
        return FALSE;
    }
}

void ShowUsage() {
    // clang-format off
    fprintf(stderr, "mirror.exe - Mirror a local device or folder to secondary device, an NTFS folder or a network device.\n"
        "  /r RootDirectory (ex. /r c:\\test)\t\t Directory source to mirror.\n"
        "  /l MountPoint (ex. /l m)\t\t\t Mount point. Can be M:\\ (drive letter) or empty NTFS folder C:\\mount\\dokan .\n"
        "  /t ThreadCount (ex. /t 5)\t\t\t Number of threads to be used internally by Dokan library.\n\t\t\t\t\t\t More threads will handle more event at the same time.\n"
        "  /d (enable debug output)\t\t\t Enable debug output to an attached debugger.\n"
        "  /s (use stderr for output)\t\t\t Enable debug output to stderr.\n"
        "  /n (use network drive)\t\t\t Show device as network device.\n"
        "  /m (use removable drive)\t\t\t Show device as removable media.\n"
        "  /w (write-protect drive)\t\t\t Read only filesystem.\n"
        "  /b (case sensitive drive)\t\t\t Supports case-sensitive file names.\n"
        "  /o (use mount manager)\t\t\t Register device to Windows mount manager.\n\t\t\t\t\t\t This enables advanced Windows features like recycle bin and more...\n"
        "  /c (mount for current session only)\t\t Device only visible for current user session.\n"
        "  /u (UNC provider name ex. \\localhost\\myfs)\t UNC name used for network volume.\n"
        "  /p (Impersonate Caller User)\t\t\t Impersonate Caller User when getting the handle in CreateFile for operations.\n\t\t\t\t\t\t This option requires administrator right to work properly.\n"
        "  /a Allocation unit size (ex. /a 512)\t\t Allocation Unit Size of the volume. This will behave on the disk file size.\n"
        "  /k Sector size (ex. /k 512)\t\t\t Sector Size of the volume. This will behave on the disk file size.\n"
        "  /f User mode Lock\t\t\t\t Enable Lockfile/Unlockfile operations. Otherwise Dokan will take care of it.\n"
        "  /e Disable OpLocks\t\t\t\t Disable OpLocks kernel operations. Otherwise Dokan will take care of it.\n"
        "  /i (Timeout in Milliseconds ex. /i 30000)\t Timeout until a running operation is aborted and the device is unmounted.\n"
        "  /z Enabled FCB GC. Might speed up on env with filter drivers (Anti-virus) slowing down the system.\n\n"
        "Examples:\n"
        "\tmirror.exe /r C:\\Users /l M:\t\t\t# Mirror C:\\Users as RootDirectory into a drive of letter M:\\.\n"
        "\tmirror.exe /r C:\\Users /l C:\\mount\\dokan\t# Mirror C:\\Users as RootDirectory into NTFS folder C:\\mount\\dokan.\n"
        "\tmirror.exe /r C:\\Users /l M: /n /u \\myfs\\myfs1\t# Mirror C:\\Users as RootDirectory into a network drive M:\\. with UNC \\\\myfs\\myfs1\n\n"
        "Unmount the drive with CTRL + C in the console or alternatively via \"dokanctl /u MountPoint\".\n");
    // clang-format on
}

#define CHECK_CMD_ARG(commad, argc)                                            \
  {                                                                            \
    if (++command == argc) {                                                   \
      fwprintf(stderr, L"Option is missing an argument.\n");                   \
      return EXIT_FAILURE;                                                     \
    }                                                                          \
  }

int __cdecl _tmain(ULONG argc, TCHAR* argv[])
{
    int status;
    DOKAN_OPERATIONS dokanOperations;
    DOKAN_OPTIONS dokanOptions;
    int ch;

    if (argc < 3) {
        ShowUsage();
        return EXIT_FAILURE;
    }

    g_DebugMode = FALSE;
    g_UseStdErr = FALSE;
    g_CaseSensitive = FALSE;

    ZeroMemory(&dokanOptions, sizeof(DOKAN_OPTIONS));
    dokanOptions.Version = DOKAN_VERSION;
    dokanOptions.ThreadCount = 0; // use default

    while ((ch = getopt(argc, argv, _T("r:l:t:dvsnmwocfezbu:pi:a:k:P:"))) != -1)
    {
        switch (ch) {
        case _T('r'):
            _tcsncpy(RootDirectory, optarg, ARRAYSIZE(RootDirectory));
            pr_err(_T("RootDirectory: %s\n"), RootDirectory);
            break;

        case _T('l'):
            _tcsncpy(MountPoint, optarg, ARRAYSIZE(MountPoint));
            pr_err(_T("MountPoint: %s\n"), MountPoint);
            dokanOptions.MountPoint = MountPoint;
            break;

        case _T('t'):
            dokanOptions.ThreadCount = (USHORT)_tcstoul(optarg, NULL, 0);
            pr_err(_T("ThreadCount: %d\n"), dokanOptions.ThreadCount);
            break;

        case _T('d'):
            g_DebugMode = TRUE;
            break;

        case _T('v'):
            if (trace_level < LOG_LEVEL_TRACE)
                trace_level++;
            break;

        case _T('s'):
            g_UseStdErr = TRUE;
            break;

        case _T('n'):
            dokanOptions.Options |= DOKAN_OPTION_NETWORK;
            break;

        case _T('m'):
            dokanOptions.Options |= DOKAN_OPTION_REMOVABLE;
            break;

        case _T('w'):
            dokanOptions.Options |= DOKAN_OPTION_WRITE_PROTECT;
            break;

        case _T('o'):
            dokanOptions.Options |= DOKAN_OPTION_MOUNT_MANAGER;
            break;

        case _T('c'):
            dokanOptions.Options |= DOKAN_OPTION_CURRENT_SESSION;
            break;

        case _T('f'):
            dokanOptions.Options |= DOKAN_OPTION_FILELOCK_USER_MODE;
            break;

        case _T('e'):
            dokanOptions.Options |= DOKAN_OPTION_DISABLE_OPLOCKS;
            break;

        case _T('z'):
            dokanOptions.Options |= DOKAN_OPTION_ENABLE_FCB_GARBAGE_COLLECTION;
            break;

        case _T('b'):
            // Only work when mirroring a folder with setCaseSensitiveInfo option enabled on win10
            dokanOptions.Options |= DOKAN_OPTION_CASE_SENSITIVE;
            g_CaseSensitive = TRUE;
            break;

        case _T('u'):
            _tcsncpy(UNCName, optarg, ARRAYSIZE(UNCName));
            dokanOptions.UNCName = UNCName;
            pr_err(_T("UNCName: %s\n"), UNCName);
            break;

        case _T('p'):
            g_ImpersonateCallerUser = TRUE;
            break;

        case _T('i'):
            dokanOptions.Timeout = _tcstoul(optarg, NULL, 0);
            break;

        case _T('a'):
            dokanOptions.AllocationUnitSize = _tcstoul(optarg, NULL, 0);
            pr_err(_T("AllocationUnitSize: %d\n"), dokanOptions.AllocationUnitSize);
            break;

        case _T('k'):
            dokanOptions.SectorSize = _tcstoul(optarg, NULL, 0);
            break;

        case _T('P'):
            _tcsncpy(TransportUrl, optarg, ARRAYSIZE(TransportUrl));
            pr_err(_T("TransportUrl: %s\n"), TransportUrl);
            break;

        case _T('?'):
        default:
            ShowUsage();
            return EXIT_FAILURE;
        }
    }

    tp = GetTransport(TransportUrl);
    if (!tp) {
        return EXIT_FAILURE;
    }

    if (wcscmp(UNCName, L"") != 0 &&
        !(dokanOptions.Options & DOKAN_OPTION_NETWORK)) {
        fwprintf(
            stderr,
            L"  Warning: UNC provider name should be set on network drive only.\n");
    }

    if (dokanOptions.Options & DOKAN_OPTION_NETWORK &&
        dokanOptions.Options & DOKAN_OPTION_MOUNT_MANAGER) {
        fwprintf(stderr, L"Mount manager cannot be used on network drive.\n");
        return EXIT_FAILURE;
    }

    if (!(dokanOptions.Options & DOKAN_OPTION_MOUNT_MANAGER) &&
        wcscmp(MountPoint, L"") == 0) {
        fwprintf(stderr, L"Mount Point required.\n");
        return EXIT_FAILURE;
    }

    if ((dokanOptions.Options & DOKAN_OPTION_MOUNT_MANAGER) &&
        (dokanOptions.Options & DOKAN_OPTION_CURRENT_SESSION)) {
        fwprintf(stderr,
            L"Mount Manager always mount the drive for all user sessions.\n");
        return EXIT_FAILURE;
    }

    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        fwprintf(stderr, L"Control Handler is not set.\n");
    }

    // Add security name privilege. Required here to handle GetFileSecurity
    // properly.
    g_HasSeSecurityPrivilege = AddSeSecurityNamePrivilege();
    if (!g_HasSeSecurityPrivilege) {
        fwprintf(stderr,
            L"[Mirror] Failed to add security privilege to process\n"
            L"\t=> GetFileSecurity/SetFileSecurity may not work properly\n"
            L"\t=> Please restart mirror sample with administrator rights to fix it\n");
    }

    if (g_ImpersonateCallerUser && !g_HasSeSecurityPrivilege) {
        fwprintf(
            stderr,
            L"[Mirror] Impersonate Caller User requires administrator right to work properly\n"
            L"\t=> Other users may not use the drive properly\n"
            L"\t=> Please restart mirror sample with administrator rights to fix it\n");
    }

    if (g_DebugMode) {
        dokanOptions.Options |= DOKAN_OPTION_DEBUG;
    }
    if (g_UseStdErr) {
        dokanOptions.Options |= DOKAN_OPTION_STDERR;
    }

    dokanOptions.Options |= DOKAN_OPTION_ALT_STREAM;

    ZeroMemory(&dokanOperations, sizeof(DOKAN_OPERATIONS));
    dokanOperations.ZwCreateFile = MirrorClientCreateFile;
    dokanOperations.Cleanup = MirrorClientCleanup;
    dokanOperations.CloseFile = MirrorClientCloseFile;
    dokanOperations.ReadFile = MirrorReadFile;
    dokanOperations.WriteFile = MirrorWriteFile;
    dokanOperations.FlushFileBuffers = MirrorFlushFileBuffers;
    dokanOperations.GetFileInformation = MirrorClientGetFileInformation;
    dokanOperations.FindFiles = MirrorClientFindFiles;
    dokanOperations.FindFilesWithPattern = NULL;
    dokanOperations.SetFileAttributes = MirrorSetFileAttributes;
    dokanOperations.SetFileTime = MirrorSetFileTime;
    dokanOperations.DeleteFile = MirrorDeleteFile;
    dokanOperations.DeleteDirectory = MirrorDeleteDirectory;
    dokanOperations.MoveFile = MirrorMoveFile;
    dokanOperations.SetEndOfFile = MirrorSetEndOfFile;
    dokanOperations.SetAllocationSize = MirrorSetAllocationSize;
    dokanOperations.LockFile = MirrorLockFile;
    dokanOperations.UnlockFile = MirrorUnlockFile;
    dokanOperations.GetFileSecurity = MirrorGetFileSecurity;
    dokanOperations.SetFileSecurity = MirrorSetFileSecurity;
    dokanOperations.GetDiskFreeSpace = MirrorDokanGetDiskFreeSpace;
    dokanOperations.GetVolumeInformation = MirrorGetVolumeInformation;
    dokanOperations.Unmounted = MirrorUnmounted;
    dokanOperations.FindStreams = MirrorFindStreams;
    dokanOperations.Mounted = MirrorMounted;

    status = DokanMain(&dokanOptions, &dokanOperations);
    switch (status) {
    case DOKAN_SUCCESS:
        fprintf(stderr, "Success\n");
        break;
    case DOKAN_ERROR:
        fprintf(stderr, "Error\n");
        break;
    case DOKAN_DRIVE_LETTER_ERROR:
        fprintf(stderr, "Bad Drive letter\n");
        break;
    case DOKAN_DRIVER_INSTALL_ERROR:
        fprintf(stderr, "Can't install driver\n");
        break;
    case DOKAN_START_ERROR:
        fprintf(stderr, "Driver something wrong\n");
        break;
    case DOKAN_MOUNT_ERROR:
        fprintf(stderr, "Can't assign a drive letter\n");
        break;
    case DOKAN_MOUNT_POINT_ERROR:
        fprintf(stderr, "Mount point error\n");
        break;
    case DOKAN_VERSION_ERROR:
        fprintf(stderr, "Version error\n");
        break;
    default:
        fprintf(stderr, "Unknown error: %d\n", status);
        break;
    }
    return EXIT_SUCCESS;
}
