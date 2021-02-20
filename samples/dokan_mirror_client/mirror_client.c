
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

struct mirror_pdu* MirrorClientTransaction(
    struct mirror_pdu* req,
    const TCHAR* name,
    uint32_t type,
    BOOL freereq
)
{
	struct transport_connection* conn = NULL;
    struct mirror_pdu* resp = NULL;
    int ret;

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

    ret = tp->send(conn, req, req->length);
    if (ret < 0) {
        pr_err(_T("send %s-req failed\n"), name);
        goto Cleanup;
    }

    resp = mirror_recv_pdu(conn);
    if (!resp) {
        pr_err(_T("receive %s-resp failed\n"), name);
        goto Cleanup;
    }

    if (resp->type != type) {
        pr_err(_T("receive invalid response type(%d)\n"), resp->type);
        free_mirror_pdu(&resp);
        goto Cleanup;
    }

Cleanup:
    if (freereq) {
        free_mirror_pdu(&req);
    }

    return resp;
}

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

static NTSTATUS DOKAN_CALLBACK MirrorClientReadFile(
    LPCWSTR FileName, 
    LPVOID Buffer,
    DWORD BufferLength,
    LPDWORD ReadLength,
    LONGLONG Offset,
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
    struct transport_connection* conn;
    struct mirror_pdu* pdu;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    size_t namelen;
    int ret;

    pr_debug(_T("-> MirrorClientReadFile()\n"));

    namelen = wcslen(FileName);

    pdu = alloc_mirror_pdu(sizeof(*pdu) + namelen);
    if (!pdu) {
        pr_err(_T("allocate read_req failed\n"));
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    pdu->type = MIRROR_PDU_STANDARD_REQUEST;
    pdu->major_function = IRP_MJ_READ;
    pdu->minor_function = 0;

    memcpy(&pdu->u.read_req.file_info, DokanFileInfo, sizeof(*DokanFileInfo));
    wcsncpy(pdu->u.read_req.file_name, FileName, namelen);
    pdu->u.read_req.read_length = BufferLength;
    pdu->u.read_req.read_offset.QuadPart = Offset;

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
		pr_err(_T("send read_req failed\n"));
		goto Cleanup;
	}

	free_mirror_pdu(&pdu);

	pdu = mirror_recv_pdu(conn);
	if (!pdu) {
		pr_err(_T("receive read_resp failed\n"));
		goto Cleanup;
	}

	if (pdu->major_function != IRP_MJ_READ) {
		pr_err(_T("receive invalid response, major(%d)\n"), pdu->major_function);
		goto Cleanup;
	}

    status = pdu->u.read_resp.status;
    if (status != STATUS_SUCCESS) {
        pr_err(_T("read failed, status(0x%08x)\n"), status);
        goto Cleanup;
    }
    
    pr_info(_T("  read succeeded, actual(%d)\n"), pdu->u.read_resp.actual_length);

    *ReadLength = pdu->u.read_resp.actual_length;
    memcpy(Buffer, pdu->u.read_resp.buffer, pdu->u.read_resp.actual_length);

Cleanup:

    if (pdu) {
        free_mirror_pdu(&pdu);
    }

    pr_debug(_T("<- MirrorClientReadFile(), status(0x%08x)\n"), status);

    return status;
}

static NTSTATUS DOKAN_CALLBACK MirrorClientWriteFile(
    LPCWSTR FileName, 
    LPCVOID Buffer,
    DWORD NumberOfBytesToWrite,
    LPDWORD NumberOfBytesWritten,
    LONGLONG Offset,
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
    struct transport_connection* conn;
    struct mirror_pdu* pdu;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    int ret;

    pr_debug(_T("-> MirrorClientWriteFile(), offset(%i64d), length(%d)\n"), 
        Offset, NumberOfBytesToWrite);

    pdu = alloc_mirror_pdu(sizeof(*pdu) + NumberOfBytesToWrite);
    if (!pdu) {
        pr_err(_T("allocate write-req failed\n"));
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    pdu->type = MIRROR_PDU_STANDARD_REQUEST;
    pdu->major_function = IRP_MJ_WRITE;
    pdu->minor_function = 0;

    wcsncpy(pdu->u.write_req.file_name, FileName, ARRAYSIZE(pdu->u.write_req.file_name));
    memcpy(&pdu->u.write_req.file_info, DokanFileInfo, sizeof(*DokanFileInfo));
    pdu->u.write_req.length = NumberOfBytesToWrite;
    pdu->u.write_req.offset.QuadPart = Offset;
    memcpy(&pdu->u.write_req.buffer[0], Buffer, NumberOfBytesToWrite);

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
		pr_err(_T("send read_req failed\n"));
		goto Cleanup;
	}

	free_mirror_pdu(&pdu);

	pdu = mirror_recv_pdu(conn);
	if (!pdu) {
		pr_err(_T("receive write_resp failed\n"));
		goto Cleanup;
	}

	if (pdu->major_function != IRP_MJ_WRITE) {
		pr_err(_T("receive invalid response, major(%d)\n"), pdu->major_function);
		goto Cleanup;
	}

    status = pdu->u.write_resp.status;
	if (status != STATUS_SUCCESS) {
		pr_err(_T("write failed, status(0x%08x)\n"), status);
		goto Cleanup;
	}

	pr_info(_T("  write succeeded, actual(%d)\n"), pdu->u.write_resp.actual_length);

    *NumberOfBytesWritten = pdu->u.write_resp.actual_length;
    status = STATUS_SUCCESS;

Cleanup:
    if (pdu) {
        free_mirror_pdu(&pdu);
    }

    pr_debug(_T("<- MirrorClientWriteFile(), status(0x%08x)"), status);

    return status;
}


static NTSTATUS DOKAN_CALLBACK
MirrorClientFlushFileBuffers(
    LPCWSTR FileName, 
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
	struct transport_connection* conn = NULL;
	struct mirror_pdu* pdu = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int ret;

	pr_debug(_T("-> MirrorClientFlushFileBuffers(), FileName(%s)\n"),
		FileName);

	pdu = alloc_mirror_pdu(sizeof(*pdu));
	if (!pdu) {
		pr_err(_T("allocate fileattributes-req failed\n"));
		status = STATUS_NO_MEMORY;
		goto Cleanup;
	}

	pdu->type = MIRROR_PDU_STANDARD_REQUEST;
	wcscpy(pdu->u.flushbuffers_req.file_name, FileName);
	memcpy(&pdu->u.flushbuffers_req.file_info, DokanFileInfo, sizeof(*DokanFileInfo));

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
		pr_err(_T("send flushbuffers-req failed\n"));
		goto Cleanup;
	}

	free_mirror_pdu(&pdu);

	pdu = mirror_recv_pdu(conn);
	if (!pdu) {
		pr_err(_T("receive flushbuffers-resp failed\n"));
		goto Cleanup;
	}

	if (pdu->type != MIRROR_PDU_STANDARD_RESPONSE ||
        pdu->major_function != IRP_MJ_FLUSH_BUFFERS) 
    {
		pr_err(_T("receive invalid response, type(%d), major(%d)\n"), 
            pdu->type, pdu->major_function);
		goto Cleanup;
	}

	status = pdu->u.flushbuffers_resp.status;

	if (status != STATUS_SUCCESS) {
		pr_err(_T("flush buffers failed, status(0x%08x)\n"), status);
		goto Cleanup;
	}

Cleanup:
	if (conn) {
		tp->destroy(conn);
	}

	if (pdu) {
		free_mirror_pdu(&pdu);
	}

	pr_debug(_T("<- MirrorClientSetFileAttributes(), status(0x%08x)\n"), status);

	return status;
}

static NTSTATUS DOKAN_CALLBACK 
MirrorClientGetFileInformation(
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
        pr_err(_T("send findfiles_req failed\n"));
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
MirrorClientDeleteFile(
    LPCWSTR FileName, 
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
	struct transport_connection* conn = NULL;
	struct mirror_pdu* pdu = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int ret;

	pr_debug(_T("-> MirrorClientDeleteFile(), FileName(%s)\n"),
		FileName);

	pdu = alloc_mirror_pdu(sizeof(*pdu));
	if (!pdu) {
		pr_err(_T("allocate deletefile-req failed\n"));
		status = STATUS_NO_MEMORY;
		goto Cleanup;
	}

	pdu->type = MIRROR_PDU_DELETE_FILE_REQUEST;
	wcscpy(pdu->u.deletefile_req.file_name, FileName);
	memcpy(&pdu->u.deletefile_req.file_info, DokanFileInfo, sizeof(*DokanFileInfo));

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
		pr_err(_T("send deletefile-req failed\n"));
		goto Cleanup;
	}

	free_mirror_pdu(&pdu);

	pdu = mirror_recv_pdu(conn);
	if (!pdu) {
		pr_err(_T("receive deletefile-resp failed\n"));
		goto Cleanup;
	}

	if (pdu->type != MIRROR_PDU_DELETE_FILE_RESPONSE) {
		pr_err(_T("receive invalid response(%d)\n"), pdu->type);
		goto Cleanup;
	}

	status = pdu->u.deletefile_resp.status;

	if (status != STATUS_SUCCESS) {
		pr_err(_T("deletefile failed, status(0x%08x)\n"), status);
		goto Cleanup;
	}

Cleanup:
	if (conn) {
		tp->destroy(conn);
	}

	if (pdu) {
		free_mirror_pdu(&pdu);
	}

	pr_debug(_T("<- MirrorClientDeleteFile(), status(0x%08x)\n"), status);

	return status;
}

static NTSTATUS DOKAN_CALLBACK
MirrorClientDeleteDirectory(
    LPCWSTR FileName, 
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
	struct transport_connection* conn = NULL;
	struct mirror_pdu* pdu = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int ret;

	pr_debug(_T("-> MirrorClientDeleteDirectory(), FileName(%s)\n"),
		FileName);

	pdu = alloc_mirror_pdu(sizeof(*pdu));
	if (!pdu) {
		pr_err(_T("allocate deletedirectory-req failed\n"));
		status = STATUS_NO_MEMORY;
		goto Cleanup;
	}

	pdu->type = MIRROR_PDU_DELETE_DIRECTORY_REQUEST;
	wcscpy(pdu->u.deletefile_req.file_name, FileName);
	memcpy(&pdu->u.deletefile_req.file_info, DokanFileInfo, sizeof(*DokanFileInfo));

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
		pr_err(_T("send deletedirectory-req failed\n"));
		goto Cleanup;
	}

	free_mirror_pdu(&pdu);

	pdu = mirror_recv_pdu(conn);
	if (!pdu) {
		pr_err(_T("receive deletedirectory-resp failed\n"));
		goto Cleanup;
	}

	if (pdu->type != MIRROR_PDU_DELETE_DIRECTORY_RESPONSE) {
		pr_err(_T("receive invalid response(%d)\n"), pdu->type);
		goto Cleanup;
	}

	status = pdu->u.deletedirectory_resp.status;

	if (status != STATUS_SUCCESS) {
		pr_err(_T("deletedirectory failed, status(0x%08x)\n"), status);
		goto Cleanup;
	}

Cleanup:
	if (conn) {
		tp->destroy(conn);
	}

	if (pdu) {
		free_mirror_pdu(&pdu);
	}

	pr_debug(_T("<- MirrorClientDeleteDirectory(), status(0x%08x)\n"), status);

	return status;
}

static NTSTATUS DOKAN_CALLBACK
MirrorClientMoveFile(
    LPCWSTR FileName, // existing file name
    LPCWSTR NewFileName, 
    BOOL ReplaceIfExisting,
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
	struct transport_connection* conn = NULL;
	struct mirror_pdu* pdu = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int ret;

	pr_debug(_T("-> MirrorClientMoveFile(), FileName(%s), NewFileName(%s)\n"),
		FileName, NewFileName);

	pdu = alloc_mirror_pdu(sizeof(*pdu));
	if (!pdu) {
		pr_err(_T("allocate movefile-req failed\n"));
		status = STATUS_NO_MEMORY;
		goto Cleanup;
	}

	pdu->type = MIRROR_PDU_MOVE_FILE_REQUEST;
	memcpy(&pdu->u.movefile_req.FileInfo, DokanFileInfo, sizeof(*DokanFileInfo));
	wcscpy(pdu->u.movefile_req.ExistingFileName, FileName);
    wcscpy(pdu->u.movefile_req.NewFileName, NewFileName);

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
		pr_err(_T("send movefile-req failed\n"));
		goto Cleanup;
	}

	free_mirror_pdu(&pdu);

	pdu = mirror_recv_pdu(conn);
	if (!pdu) {
		pr_err(_T("receive movefile-resp failed\n"));
		goto Cleanup;
	}

	if (pdu->type != MIRROR_PDU_MOVE_FILE_RESPONSE) {
		pr_err(_T("receive invalid response(%d)\n"), pdu->type);
		goto Cleanup;
	}

	status = pdu->u.movefile_resp.status;

	if (status != STATUS_SUCCESS) {
		pr_err(_T("movefile failed, status(0x%08x)\n"), status);
		goto Cleanup;
	}

Cleanup:
	if (conn) {
		tp->destroy(conn);
	}

	if (pdu) {
		free_mirror_pdu(&pdu);
	}

	pr_debug(_T("<- MirrorClientMoveFile(), status(0x%08x)\n"), status);

    return status;
}

static NTSTATUS DOKAN_CALLBACK MirrorClientLockFile(
    LPCWSTR FileName,
    LONGLONG ByteOffset,
    LONGLONG Length,
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
    struct mirror_pdu req;
    struct mirror_pdu* resp = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    pr_debug(_T("-> MirrorClientLockFile(), FileName(%s)\n"), FileName);

    bzero(&req, sizeof(req));
    
    req.length = sizeof(req);
    req.type = MIRROR_PDU_LOCK_FILE_REQUEST;
    memcpy(&req.u.lockfile_req.FileInfo, DokanFileInfo, sizeof(*DokanFileInfo));
    wcscpy(req.u.lockfile_req.FileName, FileName);
    req.u.lockfile_req.ByteOffset = ByteOffset;
    req.u.lockfile_req.Length = Length;

    resp = MirrorClientTransaction(
        &req, 
        _T("lockfile"), 
        MIRROR_PDU_LOCK_FILE_RESPONSE, 
        FALSE
    );
    if (!resp) {
        goto Cleanup;
    }

    status = resp->u.lockfile_resp.Status;

    if (status != STATUS_SUCCESS) {
        pr_err(_T("lockfile failed, status(0x%08x)\n"), status);
        goto Cleanup;
    }

Cleanup:
    if (resp) {
        free_mirror_pdu(&resp);
    }

    return status;
}

static NTSTATUS DOKAN_CALLBACK 
MirrorClientSetEndOfFile(
    LPCWSTR FileName, 
    LONGLONG ByteOffset, 
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
	struct transport_connection* conn = NULL;
	struct mirror_pdu* pdu = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int ret;

    pr_debug(_T("-> MirrorClientSetEndOfFile(), offset(%i64x)\n"), ByteOffset);

	pdu = alloc_mirror_pdu(sizeof(*pdu));
	if (!pdu) {
		pr_err(_T("allocate endoffile-req failed\n"));
		status = STATUS_NO_MEMORY;
		goto Cleanup;
	}

	pdu->type = MIRROR_PDU_SET_END_OF_FILE_REQUEST;

	memcpy(&pdu->u.endoffile_req.file_info, DokanFileInfo, sizeof(*DokanFileInfo));
	wcscpy(pdu->u.endoffile_req.file_name, FileName);
    pdu->u.endoffile_req.offset.QuadPart = ByteOffset;

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
		pr_err(_T("send endoffile-req failed\n"));
		goto Cleanup;
	}

	free_mirror_pdu(&pdu);

	pdu = mirror_recv_pdu(conn);
	if (!pdu) {
		pr_err(_T("receive endoffile-resp failed\n"));
		goto Cleanup;
	}

	if (pdu->type != MIRROR_PDU_SET_END_OF_FILE_RESPONSE) {
		pr_err(_T("receive invalid response(%d)\n"), pdu->type);
		goto Cleanup;
	}

	status = pdu->u.endoffile_resp.status;

	if (status != STATUS_SUCCESS) {
		pr_err(_T("set endoffile failed, status(0x%08x)\n"), status);
		goto Cleanup;
	}

Cleanup:
	if (pdu) {
		free_mirror_pdu(&pdu);
	}

	if (conn) {
		tp->destroy(conn);
	}

	return status;
}

static NTSTATUS DOKAN_CALLBACK 
MirrorClientSetAllocationSize(
    LPCWSTR FileName, 
    LONGLONG AllocSize, 
    PDOKAN_FILE_INFO DokanFileInfo
) 
{	
	struct mirror_pdu req;
    struct mirror_pdu* resp = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	pr_debug(_T("-> MirrorClientSetAllocationSize(), offset(%i64x)\n"), AllocSize);

    req.length = sizeof(req);
	req.type = MIRROR_PDU_SET_ALLOCATION_SIZE_REQUEST;

	memcpy(&req.u.allocsize_req.FileInfo, DokanFileInfo, sizeof(*DokanFileInfo));
	wcscpy(req.u.allocsize_req.FileName, FileName);
	req.u.allocsize_req.AllocSize = AllocSize;

    resp = MirrorClientTransaction(
        &req, 
        _T("allocsize"), 
        MIRROR_PDU_SET_ALLOCATION_SIZE_RESPONSE,
        FALSE
    );
    if (!resp) {
        goto Cleanup;
    }

	status = resp->u.allocsize_resp.Status;

	if (status != STATUS_SUCCESS) {
		pr_err(_T("set allocation size failed, status(0x%08x)\n"), status);
		goto Cleanup;
	}

Cleanup:
    if (resp) {
        free_mirror_pdu(&resp);
    }
	
	return status;
}

static NTSTATUS DOKAN_CALLBACK MirrorClientSetFileAttributes(
    LPCWSTR FileName, 
    DWORD FileAttributes, 
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
    struct transport_connection* conn = NULL;
    struct mirror_pdu* pdu = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    int ret;

    pr_debug(_T("-> MirrorClientSetFileAttributes(), FileName(%s), FileAttributes(0x%08x)\n"),
        FileName, FileAttributes);

    pdu = alloc_mirror_pdu(sizeof(*pdu));
    if (!pdu) {
        pr_err(_T("allocate fileattributes-req failed\n"));
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    pdu->type = MIRROR_PDU_SET_FILE_ATTRIBUTES_REQUEST;
    wcscpy(pdu->u.fileattributes_req.file_name, FileName);
    memcpy(&pdu->u.fileattributes_req.file_info, DokanFileInfo, sizeof(*DokanFileInfo));
    pdu->u.fileattributes_req.file_attributes = FileAttributes;

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
		pr_err(_T("send fileattributes-req failed\n"));
		goto Cleanup;
	}

	free_mirror_pdu(&pdu);

    pdu = mirror_recv_pdu(conn);
    if (!pdu) {
        pr_err(_T("receive fileattributes-resp failed\n"));
        goto Cleanup;
    }

    if (pdu->type != MIRROR_PDU_SET_FILE_ATTRIBUTES_RESPONSE) {
        pr_err(_T("receive invalid response(%d)\n"), pdu->type);
        goto Cleanup;
    }

    status = pdu->u.fileattributes_resp.status;

    if (status != STATUS_SUCCESS) {
        pr_err(_T("set fileattributes failed, status(0x%08x)\n"), status);
        goto Cleanup;
    }

Cleanup:
    if (conn) {
        tp->destroy(conn);
    }

    if (pdu) {
        free_mirror_pdu(&pdu);
    }

    pr_debug(_T("<- MirrorClientSetFileAttributes(), status(0x%08x)\n"), status);

    return status;
}

static NTSTATUS DOKAN_CALLBACK
MirrorClientSetFileTime(
    LPCWSTR FileName, 
    CONST FILETIME* CreationTime,
    CONST FILETIME* LastAccessTime, 
    CONST FILETIME* LastWriteTime,
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
    struct transport_connection* conn = NULL;
    struct mirror_pdu* pdu = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    int ret;

    pr_debug(_T("-> MirrorClientSetFileTime()\n"));

    pdu = alloc_mirror_pdu(sizeof(*pdu));
    if (!pdu) {
        pr_err(_T("allocate filetime-req failed\n"));
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    pdu->type = MIRROR_PDU_SET_FILE_TIME_REQUEST;

    memcpy(&pdu->u.filetime_req.file_info, DokanFileInfo, sizeof(*DokanFileInfo));
    wcscpy(pdu->u.filetime_req.file_name, FileName);
    
    if (CreationTime) {
        pdu->u.filetime_req.fSetCreationTime = TRUE;
        memcpy(&pdu->u.filetime_req.CreationTime, CreationTime, sizeof(*CreationTime));
    }
    if (LastAccessTime) {
        pdu->u.filetime_req.fSetLastAccessTime = TRUE;
        memcpy(&pdu->u.filetime_req.LastAccessTime, LastAccessTime, sizeof(*LastAccessTime));
    }
    if (LastWriteTime) {
        pdu->u.filetime_req.fSetLastWriteTime = TRUE;
        memcpy(&pdu->u.filetime_req.LastWriteTime, LastWriteTime, sizeof(*LastWriteTime));
    }
     
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
		pr_err(_T("send fileattributes-req failed\n"));
		goto Cleanup;
	}

	free_mirror_pdu(&pdu);

	pdu = mirror_recv_pdu(conn);
	if (!pdu) {
		pr_err(_T("receive filetime-resp failed\n"));
		goto Cleanup;
	}

	if (pdu->type != MIRROR_PDU_SET_FILE_TIME_RESPONSE) {
		pr_err(_T("receive invalid response(%d)\n"), pdu->type);
		goto Cleanup;
	}

	status = pdu->u.filetime_resp.status;

	if (status != STATUS_SUCCESS) {
		pr_err(_T("set filetime failed, status(0x%08x)\n"), status);
		goto Cleanup;
	}

Cleanup:
    if (pdu) {
        free_mirror_pdu(&pdu);
    }

    if (conn) {
        tp->destroy(conn);
    }

    return status;
}

static NTSTATUS DOKAN_CALLBACK
MirrorClientUnlockFile(
    LPCWSTR FileName, 
    LONGLONG ByteOffset, 
    LONGLONG Length,
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
	struct mirror_pdu req;
	struct mirror_pdu* resp = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	pr_debug(_T("-> MirrorClientUnlockFile(), FileName(%s)\n"), FileName);

	bzero(&req, sizeof(req));

	req.length = sizeof(req);
	req.type = MIRROR_PDU_UNLOCK_FILE_REQUEST;
	memcpy(&req.u.unlockfile_req.FileInfo, DokanFileInfo, sizeof(*DokanFileInfo));
	wcscpy(req.u.unlockfile_req.FileName, FileName);
	req.u.unlockfile_req.ByteOffset = ByteOffset;
	req.u.unlockfile_req.Length = Length;

	resp = MirrorClientTransaction(
		&req,
		_T("unlockfile"),
		MIRROR_PDU_UNLOCK_FILE_RESPONSE,
		FALSE
	);
	if (!resp) {
		goto Cleanup;
	}

	status = resp->u.unlockfile_resp.Status;

	if (status != STATUS_SUCCESS) {
		pr_err(_T("unlockfile failed, status(0x%08x)\n"), status);
		goto Cleanup;
	}

Cleanup:
	if (resp) {
		free_mirror_pdu(&resp);
	}

	return status;
}

static NTSTATUS DOKAN_CALLBACK 
MirrorClientGetFileSecurity(
    LPCWSTR FileName, 
    PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor, 
    ULONG BufferLength,
    PULONG LengthNeeded, 
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
	struct mirror_pdu* pdu;	
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	pr_debug(_T("-> MirrorClientGetFileSecurity(), FileName(%s)\n"), FileName);

    pdu = alloc_mirror_pdu(sizeof(*pdu) + BufferLength);
    if (!pdu) {
        pr_err(_T("alloc getfilesecurity-req failed\n"));
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    pdu->type = MIRROR_PDU_GET_FILE_SECURITY_REQUEST;

	memcpy(&pdu->u.getfilesecurity_req.FileInfo, DokanFileInfo, sizeof(*DokanFileInfo));
	wcscpy(pdu->u.getfilesecurity_req.FileName, FileName);
    pdu->u.getfilesecurity_req.SecurityInfomration = *SecurityInformation;
    pdu->u.getfilesecurity_req.BufferLength = BufferLength;
    pdu->u.getfilesecurity_req.LengthNeeded = *LengthNeeded;
    memcpy(
        &pdu->u.getfilesecurity_req.SecurityDescriptor, 
        SecurityDescriptor, 
        BufferLength
    );

	pdu = MirrorClientTransaction(
		pdu,
		_T("getfilesecurity"),
		MIRROR_PDU_GET_FILE_SECURITY_RESPONSE,
		TRUE
	);
	if (!pdu) {
		goto Cleanup;
	}

	status = pdu->u.getfilesecurity_resp.Status;

	if (status != STATUS_SUCCESS) {
		pr_err(_T("getfilesecurity failed, status(0x%08x)\n"), status);
		goto Cleanup;
	}

    *SecurityInformation = pdu->u.getfilesecurity_resp.SecurityInformation;
    *LengthNeeded = pdu->u.getfilesecurity_resp.LengthNeeded;
    memcpy(
        SecurityDescriptor,
        pdu->u.getfilesecurity_resp.SecurityDescriptor,
        pdu->u.getfilesecurity_resp.BufferLength
    );

Cleanup:
	if (pdu) {
		free_mirror_pdu(&pdu);
	}

	return status;
}

static NTSTATUS DOKAN_CALLBACK 
MirrorClientSetFileSecurity(
    LPCWSTR FileName, 
    PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor, 
    ULONG SecurityDescriptorLength,
    PDOKAN_FILE_INFO DokanFileInfo
)
{
	struct mirror_pdu* pdu;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	pr_debug(_T("-> MirrorClientSetFileSecurity(), FileName(%s)\n"), FileName);

	pdu = alloc_mirror_pdu(sizeof(*pdu) + SecurityDescriptorLength);
	if (!pdu) {
		pr_err(_T("alloc setfilesecurity-req failed\n"));
		status = STATUS_NO_MEMORY;
		goto Cleanup;
	}

	pdu->type = MIRROR_PDU_SET_FILE_SECURITY_REQUEST;

	memcpy(&pdu->u.setfilesecurity_req.FileInfo, DokanFileInfo, sizeof(*DokanFileInfo));
	wcscpy(pdu->u.setfilesecurity_req.FileName, FileName);
	pdu->u.setfilesecurity_req.SecurityInformation = *SecurityInformation;
	pdu->u.setfilesecurity_req.SecurityDescriptorLength = SecurityDescriptorLength;
	memcpy(
		&pdu->u.setfilesecurity_req.SecurityDescriptor,
		SecurityDescriptor,
        SecurityDescriptorLength
	);

	pdu = MirrorClientTransaction(
		pdu,
		_T("setfilesecurity"),
		MIRROR_PDU_GET_FILE_SECURITY_RESPONSE,
		TRUE
	);
	if (!pdu) {
		goto Cleanup;
	}

	status = pdu->u.setfilesecurity_resp.Status;

	if (status != STATUS_SUCCESS) {
		pr_err(_T("setfilesecurity failed, status(0x%08x)\n"), status);
		goto Cleanup;
	}

	*SecurityInformation = pdu->u.setfilesecurity_resp.SecurityInformation;
	
	memcpy(
		SecurityDescriptor,
		pdu->u.setfilesecurity_resp.SecurityDescriptor,
		pdu->u.setfilesecurity_resp.SecurityDescriptorLength
	);

Cleanup:
	if (pdu) {
		free_mirror_pdu(&pdu);
	}

	return status;
}

static NTSTATUS DOKAN_CALLBACK 
MirrorClientGetVolumeInformation(
    LPWSTR VolumeNameBuffer, 
    DWORD VolumeNameSize, 
    LPDWORD VolumeSerialNumber,
    LPDWORD MaximumComponentLength, 
    LPDWORD FileSystemFlags,
    LPWSTR FileSystemNameBuffer, 
    DWORD FileSystemNameSize,
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
    struct mirror_pdu req;
    struct mirror_pdu* resp = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    pr_debug(_T("-> MirrorClientGetVolumeInformation()\n"));

    bzero(&req, sizeof(req));

    req.length = sizeof(req);
    req.type = MIRROR_PDU_GET_VOLUME_INFO_REQUEST;

    memcpy(&req.u.getvolumeinfo_req.FileInfo, DokanFileInfo, sizeof(*DokanFileInfo));

    resp = MirrorClientTransaction(
        &req, 
        _T("getvolumeinfo"),
        MIRROR_PDU_GET_VOLUME_INFO_RESPONSE, 
        FALSE
    );
    if (!resp) {
        goto Cleanup;
    }

    if (VolumeNameBuffer) {
        wcscpy_s(VolumeNameBuffer, VolumeNameSize, resp->u.getvolumeinfo_resp.VolumeName);
    }
    if (VolumeSerialNumber) {
        *VolumeSerialNumber = resp->u.getvolumeinfo_resp.VolumeSerialNumber;
    }
    if (MaximumComponentLength) {
        *MaximumComponentLength = resp->u.getvolumeinfo_resp.MaximumComponentLength;
    }
    if (FileSystemFlags) {
        *FileSystemFlags = resp->u.getvolumeinfo_resp.FileSystemFlags;
    }
    if (FileSystemNameBuffer) {
        wcscpy_s(FileSystemNameBuffer, FileSystemNameSize, resp->u.getvolumeinfo_resp.FileSystemName);
    }

    status = STATUS_SUCCESS;

Cleanup:

    return status;
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

static NTSTATUS DOKAN_CALLBACK 
MirrorClientGetDiskFreeSpace(
    PULONGLONG FreeBytesAvailable, 
    PULONGLONG TotalNumberOfBytes,
    PULONGLONG TotalNumberOfFreeBytes, 
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
	struct mirror_pdu req;
	struct mirror_pdu* resp = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	pr_debug(_T("-> MirrorClientGetDiskFreeSpace()\n"));

	bzero(&req, sizeof(req));

	req.length = sizeof(req);
	req.type = MIRROR_PDU_GET_DISK_FREE_SPACE_REQUEST;

	memcpy(&req.u.getdiskfreespace_req.FileInfo, DokanFileInfo, sizeof(*DokanFileInfo));

	resp = MirrorClientTransaction(
		&req,
		_T("getdiskfreespace"),
		MIRROR_PDU_GET_DISK_FREE_SPACE_RESPONSE,
		FALSE
	);
	if (!resp) {
		goto Cleanup;
	}

    status = resp->u.getdiskfreespace_resp.Status;

	if (status != STATUS_SUCCESS) {
		pr_err(_T("getdiskfreespace failed, status(0x%08x)\n"), status);
		goto Cleanup;
	}

    *FreeBytesAvailable = resp->u.getdiskfreespace_resp.FreeBytesAvailable;
    *TotalNumberOfBytes = resp->u.getdiskfreespace_resp.TotalNumberOfBytes;
    *TotalNumberOfFreeBytes = resp->u.getdiskfreespace_resp.TotalNumberOfBytes;

Cleanup:
	if (resp) {
		free_mirror_pdu(&resp);
	}

    return status;
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
MirrorClientFindStreams(
    LPCWSTR FileName, 
    PFillFindStreamData FillFindStreamData,
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
    struct transport_connection* conn = NULL;
    struct mirror_pdu req;
    struct mirror_pdu* resp = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    int ret;
    int count = 0;

    pr_debug(_T("-> MirrorFindStreams()\n"));

    bzero(&req, sizeof(req));

    req.length = sizeof(req);
    req.type = MIRROR_PDU_FIND_STREAMS_REQUEST;

    memcpy(&req.u.findstreams_req.FileInfo, DokanFileInfo, sizeof(*DokanFileInfo));
    wcscpy(req.u.findstreams_req.FileName, FileName);

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

	ret = tp->send(conn, &req, req.length);
	if (ret < 0) {
		pr_err(_T("send findstreams_req failed\n"));
		goto Cleanup;
	}

	while (1) {
		resp = mirror_recv_pdu(conn);
		if (!resp) {
			pr_err(_T("receive find-files response failed\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (resp->type != MIRROR_PDU_FIND_STREAMS_RESPONSE) {
			pr_err(_T("invalid findstreams response type(%d)\n"), resp->type);
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (resp->u.findstreams_resp.Status == STATUS_NO_MORE_ENTRIES) {
			status = STATUS_SUCCESS;
			break;
		}

		if (resp->u.findstreams_resp.Status != STATUS_SUCCESS) {
			pr_err(_T("receive failed findstreams-resp, status(0x%08x)\n"),
				resp->u.findstreams_resp.Status);

			status = resp->u.findstreams_resp.Status;
			break;
		}

		pr_info(_T("    [%d]: %s\n"),
			count, resp->u.findstreams_resp.FindStreamData.cStreamName);

        FillFindStreamData(&resp->u.findstreams_resp.FindStreamData, DokanFileInfo);
		count++;
	}

Cleanup:
	if (conn) {
		tp->destroy(conn);
	}

    if (resp) {
        free_mirror_pdu(&resp);
    }

    pr_debug(_T("<- MirrorFindStreams(), status(0x%08x)\n"), status);

    return status;
}


static NTSTATUS DOKAN_CALLBACK 
MirrorClientMounted(
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
    UNREFERENCED_PARAMETER(DokanFileInfo);

    DbgPrint(L"Mounted\n");
    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK 
MirrorClientUnmounted(
    PDOKAN_FILE_INFO DokanFileInfo
) 
{
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
    dokanOperations.ReadFile = MirrorClientReadFile;
    dokanOperations.WriteFile = MirrorClientWriteFile;
    dokanOperations.FlushFileBuffers = MirrorClientFlushFileBuffers;
    dokanOperations.GetFileInformation = MirrorClientGetFileInformation;
    dokanOperations.FindFiles = MirrorClientFindFiles;
    dokanOperations.FindFilesWithPattern = NULL;
    dokanOperations.SetFileAttributes = MirrorClientSetFileAttributes;
    dokanOperations.SetFileTime = MirrorClientSetFileTime;
    dokanOperations.DeleteFile = MirrorClientDeleteFile;
    dokanOperations.DeleteDirectory = MirrorClientDeleteDirectory;
    dokanOperations.MoveFile = MirrorClientMoveFile;
    dokanOperations.SetEndOfFile = MirrorClientSetEndOfFile;
    dokanOperations.SetAllocationSize = MirrorClientSetAllocationSize;
    dokanOperations.LockFile = MirrorClientLockFile;
    dokanOperations.UnlockFile = MirrorClientUnlockFile;
    dokanOperations.GetFileSecurity = MirrorClientGetFileSecurity;
    dokanOperations.SetFileSecurity = MirrorClientSetFileSecurity;
    dokanOperations.GetDiskFreeSpace = MirrorClientGetDiskFreeSpace;
    dokanOperations.GetVolumeInformation = MirrorClientGetVolumeInformation;
    dokanOperations.Unmounted = MirrorClientUnmounted;
    dokanOperations.FindStreams = MirrorClientFindStreams;
    dokanOperations.Mounted = MirrorClientMounted;

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
