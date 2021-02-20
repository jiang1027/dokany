#include "../../dokan/dokan.h"
#include "../../dokan/fileinfo.h"

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <winbase.h>

#include <transport.h>
#include <getopt.h>
#include <trace.h>
#include <mirror_proto.h>

//#define WIN10_ENABLE_LONG_PATH
#ifdef WIN10_ENABLE_LONG_PATH
//dirty but should be enough
#define DOKAN_MAX_PATH 32768
#else
#define DOKAN_MAX_PATH MAX_PATH
#endif // DEBUG

static TCHAR TransportUrl[MAX_PATH] = { 0 };
static TCHAR RootDirectory[DOKAN_MAX_PATH] = { 0 };
static TCHAR UNCName[DOKAN_MAX_PATH] = { 0 };

void ShowUsage() 
{ 
	fprintf(stderr,
		"mirror_server.exe - Mirror a local device or folder to remove\n"
		"  /r RootDirectory (ex. /r c:\\test)\t\tDirectory source to mirror\n"
		"  /v (enable debug output)\t\t\t Enable debug output to an attached debugger.\n"
		"  /p Port (set listen port)\tSpecify TCP listen port\n"
		""
	); 
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

	handle = DokanOpenRequestorToken(DokanFileInfo);
	if (handle == INVALID_HANDLE_VALUE) {
        pr_info(_T("  DokanOpenRequestorToken failed\n"));
		return;
	}

	if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer),
		&returnLength)) {
        pr_info(_T("  GetTokenInformaiton failed: %d\n"), GetLastError());
		CloseHandle(handle);
		return;
	}

	CloseHandle(handle);

	tokenUser = (PTOKEN_USER)buffer;
	if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName, &accountLength,
		domainName, &domainLength, &snu)) {
        pr_info(_T("  LookupAccountSid failed: %d\n"), GetLastError());
		return;
	}

    pr_info(_T("  AccountName: %s, DomainName: %s\n"), accountName, domainName);
}

#define MirrorCheckFlag(val, flag)                                             \
  if (val & flag) {                                                            \
    pr_info(_T("\t" L#flag L"\n"));                                              \
  }

static NTSTATUS 
MirrorServerCreateFile(
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
    WCHAR filePath[DOKAN_MAX_PATH];
    HANDLE handle;
    DWORD fileAttr;
    NTSTATUS status = STATUS_SUCCESS;
    DWORD creationDisposition;
    DWORD fileAttributesAndFlags;
    DWORD error = 0;
    SECURITY_ATTRIBUTES securityAttrib;
    ACCESS_MASK genericDesiredAccess;
    // userTokenHandle is for Impersonate Caller User Option
    HANDLE userTokenHandle = INVALID_HANDLE_VALUE;

#if 0
    securityAttrib.nLength = sizeof(securityAttrib);
    securityAttrib.lpSecurityDescriptor =
        SecurityContext->AccessState.SecurityDescriptor;
    securityAttrib.bInheritHandle = FALSE;
#endif 

    securityAttrib.nLength = sizeof(securityAttrib);
    securityAttrib.lpSecurityDescriptor = NULL;
    securityAttrib.bInheritHandle = FALSE;

    DokanMapKernelToUserCreateFileFlags(
        DesiredAccess, FileAttributes, CreateOptions, CreateDisposition,
        &genericDesiredAccess, &fileAttributesAndFlags, &creationDisposition);

    GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

    pr_info(_T("CreateFile : %s\n"), filePath);

    // PrintUserName(DokanFileInfo);

    /*
    if (ShareMode == 0 && AccessMode & FILE_WRITE_DATA)
            ShareMode = FILE_SHARE_WRITE;
    else if (ShareMode == 0)
            ShareMode = FILE_SHARE_READ;
    */

    pr_info(_T("\tShareMode = 0x%x\n"), ShareAccess);

    MirrorCheckFlag(ShareAccess, FILE_SHARE_READ);
    MirrorCheckFlag(ShareAccess, FILE_SHARE_WRITE);
    MirrorCheckFlag(ShareAccess, FILE_SHARE_DELETE);

    pr_info(_T("\tDesiredAccess = 0x%x\n"), DesiredAccess);

    MirrorCheckFlag(DesiredAccess, GENERIC_READ);
    MirrorCheckFlag(DesiredAccess, GENERIC_WRITE);
    MirrorCheckFlag(DesiredAccess, GENERIC_EXECUTE);

    MirrorCheckFlag(DesiredAccess, DELETE);
    MirrorCheckFlag(DesiredAccess, FILE_READ_DATA);
    MirrorCheckFlag(DesiredAccess, FILE_READ_ATTRIBUTES);
    MirrorCheckFlag(DesiredAccess, FILE_READ_EA);
    MirrorCheckFlag(DesiredAccess, READ_CONTROL);
    MirrorCheckFlag(DesiredAccess, FILE_WRITE_DATA);
    MirrorCheckFlag(DesiredAccess, FILE_WRITE_ATTRIBUTES);
    MirrorCheckFlag(DesiredAccess, FILE_WRITE_EA);
    MirrorCheckFlag(DesiredAccess, FILE_APPEND_DATA);
    MirrorCheckFlag(DesiredAccess, WRITE_DAC);
    MirrorCheckFlag(DesiredAccess, WRITE_OWNER);
    MirrorCheckFlag(DesiredAccess, SYNCHRONIZE);
    MirrorCheckFlag(DesiredAccess, FILE_EXECUTE);
    MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_READ);
    MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_WRITE);
    MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_EXECUTE);

    // When filePath is a directory, needs to change the flag so that the file can
    // be opened.
    fileAttr = GetFileAttributes(filePath);

    if (fileAttr != INVALID_FILE_ATTRIBUTES
        && fileAttr & FILE_ATTRIBUTE_DIRECTORY) {
        if (!(CreateOptions & FILE_NON_DIRECTORY_FILE)) {
            DokanFileInfo->IsDirectory = TRUE;
            // Needed by FindFirstFile to list files in it
            // TODO: use ReOpenFile in MirrorFindFiles to set share read temporary
            ShareAccess |= FILE_SHARE_READ;
        }
        else { // FILE_NON_DIRECTORY_FILE - Cannot open a dir as a file
            pr_info(_T("\tCannot open a dir as a file\n"));
            return STATUS_FILE_IS_A_DIRECTORY;
        }
    }

    pr_info(_T("\tFlagsAndAttributes = 0x%x\n"), fileAttributesAndFlags);

    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ARCHIVE);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_COMPRESSED);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_DEVICE);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_DIRECTORY);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ENCRYPTED);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_HIDDEN);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_INTEGRITY_STREAM);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NORMAL);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NO_SCRUB_DATA);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_OFFLINE);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_READONLY);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_REPARSE_POINT);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_SPARSE_FILE);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_SYSTEM);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_TEMPORARY);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_VIRTUAL);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_WRITE_THROUGH);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OVERLAPPED);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_NO_BUFFERING);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_RANDOM_ACCESS);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_SEQUENTIAL_SCAN);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_DELETE_ON_CLOSE);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_BACKUP_SEMANTICS);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_POSIX_SEMANTICS);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_REPARSE_POINT);
    MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_NO_RECALL);
    MirrorCheckFlag(fileAttributesAndFlags, SECURITY_ANONYMOUS);
    MirrorCheckFlag(fileAttributesAndFlags, SECURITY_IDENTIFICATION);
    MirrorCheckFlag(fileAttributesAndFlags, SECURITY_IMPERSONATION);
    MirrorCheckFlag(fileAttributesAndFlags, SECURITY_DELEGATION);
    MirrorCheckFlag(fileAttributesAndFlags, SECURITY_CONTEXT_TRACKING);
    MirrorCheckFlag(fileAttributesAndFlags, SECURITY_EFFECTIVE_ONLY);
    MirrorCheckFlag(fileAttributesAndFlags, SECURITY_SQOS_PRESENT);

#if 0
    if (g_CaseSensitive)
        fileAttributesAndFlags |= FILE_FLAG_POSIX_SEMANTICS;
#endif 

    if (creationDisposition == CREATE_NEW) {
        pr_info(_T("\tCREATE_NEW\n"));
    }
    else if (creationDisposition == OPEN_ALWAYS) {
        pr_info(_T("\tOPEN_ALWAYS\n"));
    }
    else if (creationDisposition == CREATE_ALWAYS) {
        pr_info(_T("\tCREATE_ALWAYS\n"));
    }
    else if (creationDisposition == OPEN_EXISTING) {
        pr_info(_T("\tOPEN_EXISTING\n"));
    }
    else if (creationDisposition == TRUNCATE_EXISTING) {
        pr_info(_T("\tTRUNCATE_EXISTING\n"));
    }
    else {
        pr_info(_T("\tUNKNOWN creationDisposition!\n"));
    }

#if 0
    if (g_ImpersonateCallerUser) {
        userTokenHandle = DokanOpenRequestorToken(DokanFileInfo);

        if (userTokenHandle == INVALID_HANDLE_VALUE) {
            pr_info(_T("  DokanOpenRequestorToken failed\n"));
            // Should we return some error?
        }
    }
#endif 

    if (DokanFileInfo->IsDirectory) {
        // It is a create directory request

        if (creationDisposition == CREATE_NEW ||
            creationDisposition == OPEN_ALWAYS) {
#if 0
            if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
                // if g_ImpersonateCallerUser option is on, call the ImpersonateLoggedOnUser function.
                if (!ImpersonateLoggedOnUser(userTokenHandle)) {
                    // handle the error if failed to impersonate
                    pr_info(_T("\tImpersonateLoggedOnUser failed.\n"));
                }
            }
#endif
            //We create folder
            if (!CreateDirectory(filePath, &securityAttrib)) {
                error = GetLastError();
                // Fail to create folder for OPEN_ALWAYS is not an error
                if (error != ERROR_ALREADY_EXISTS ||
                    creationDisposition == CREATE_NEW) {
                    pr_info(_T("\terror code = %d\n\n"), error);
                    status = DokanNtStatusFromWin32(error);
                }
            }

#if 0
            if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
                // Clean Up operation for impersonate
                DWORD lastError = GetLastError();
                if (status != STATUS_SUCCESS) //Keep the handle open for CreateFile
                    CloseHandle(userTokenHandle);
                RevertToSelf();
                SetLastError(lastError);
            }
#endif 
        }

        if (status == STATUS_SUCCESS) {

            //Check first if we're trying to open a file as a directory.
            if (fileAttr != INVALID_FILE_ATTRIBUTES &&
                !(fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
                (CreateOptions & FILE_DIRECTORY_FILE)) {
                return STATUS_NOT_A_DIRECTORY;
            }
#if 0
            if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
                // if g_ImpersonateCallerUser option is on, call the ImpersonateLoggedOnUser function.
                if (!ImpersonateLoggedOnUser(userTokenHandle)) {
                    // handle the error if failed to impersonate
                    pr_info(_T("\tImpersonateLoggedOnUser failed.\n"));
                }
            }
#endif 
            // FILE_FLAG_BACKUP_SEMANTICS is required for opening directory handles
            handle =
                CreateFile(filePath, genericDesiredAccess, ShareAccess,
                    &securityAttrib, OPEN_EXISTING,
                    fileAttributesAndFlags | FILE_FLAG_BACKUP_SEMANTICS, NULL);
#if 0
            if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
                // Clean Up operation for impersonate
                DWORD lastError = GetLastError();
                CloseHandle(userTokenHandle);
                RevertToSelf();
                SetLastError(lastError);
            }
#endif
            if (handle == INVALID_HANDLE_VALUE) {
                error = GetLastError();
                pr_info(_T("\terror code = %d\n\n"), error);

                status = DokanNtStatusFromWin32(error);
            }
            else {
                DokanFileInfo->Context =
                    (ULONG64)handle; // save the file handle in Context

                  // Open succeed but we need to inform the driver
                  // that the dir open and not created by returning STATUS_OBJECT_NAME_COLLISION
                if (creationDisposition == OPEN_ALWAYS &&
                    fileAttr != INVALID_FILE_ATTRIBUTES)
                    return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }
    else {
        // It is a create file request

        // Cannot overwrite a hidden or system file if flag not set
        if (fileAttr != INVALID_FILE_ATTRIBUTES &&
            ((!(fileAttributesAndFlags & FILE_ATTRIBUTE_HIDDEN) &&
                (fileAttr & FILE_ATTRIBUTE_HIDDEN)) ||
                (!(fileAttributesAndFlags & FILE_ATTRIBUTE_SYSTEM) &&
                    (fileAttr & FILE_ATTRIBUTE_SYSTEM))) &&
            (creationDisposition == TRUNCATE_EXISTING ||
                creationDisposition == CREATE_ALWAYS))
            return STATUS_ACCESS_DENIED;

        // Cannot delete a read only file
        if ((fileAttr != INVALID_FILE_ATTRIBUTES &&
            (fileAttr & FILE_ATTRIBUTE_READONLY) ||
            (fileAttributesAndFlags & FILE_ATTRIBUTE_READONLY)) &&
            (fileAttributesAndFlags & FILE_FLAG_DELETE_ON_CLOSE))
            return STATUS_CANNOT_DELETE;

        // Truncate should always be used with write access
        if (creationDisposition == TRUNCATE_EXISTING)
            genericDesiredAccess |= GENERIC_WRITE;

#if 0
        if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
            // if g_ImpersonateCallerUser option is on, call the ImpersonateLoggedOnUser function.
            if (!ImpersonateLoggedOnUser(userTokenHandle)) {
                // handle the error if failed to impersonate
                pr_info(_T("\tImpersonateLoggedOnUser failed.\n"));
            }
        }
#endif 

        handle = CreateFile(filePath,
            genericDesiredAccess, // GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
            ShareAccess,
            &securityAttrib, // security attribute
            creationDisposition,
            fileAttributesAndFlags, // |FILE_FLAG_NO_BUFFERING,
            NULL);                  // template file handle

#if 0
        if (g_ImpersonateCallerUser && userTokenHandle != INVALID_HANDLE_VALUE) {
            // Clean Up operation for impersonate
            DWORD lastError = GetLastError();
            CloseHandle(userTokenHandle);
            RevertToSelf();
            SetLastError(lastError);
        }
#endif 

        if (handle == INVALID_HANDLE_VALUE) {
            error = GetLastError();
            pr_info(_T("\terror code = %d\n\n"), error);

            status = DokanNtStatusFromWin32(error);
        }
        else {

            //Need to update FileAttributes with previous when Overwrite file
            if (fileAttr != INVALID_FILE_ATTRIBUTES &&
                creationDisposition == TRUNCATE_EXISTING) {
                SetFileAttributes(filePath, fileAttributesAndFlags | fileAttr);
            }

            DokanFileInfo->Context =
                (ULONG64)handle; // save the file handle in Context

            if (creationDisposition == OPEN_ALWAYS ||
                creationDisposition == CREATE_ALWAYS) {
                error = GetLastError();
                if (error == ERROR_ALREADY_EXISTS) {
                    pr_info(_T("\tOpen an already existing file\n"));
                    // Open succeed but we need to inform the driver
                    // that the file open and not created by returning STATUS_OBJECT_NAME_COLLISION
                    status = STATUS_OBJECT_NAME_COLLISION;
                }
            }
        }
    }

    pr_info(_T("\n"));

    return status;
}

void mirror_process_create_request(
	struct transport_connection* conn,
	struct mirror_create_request* req
)
{
	struct mirror_pdu* pdu;
    NTSTATUS status;
    int ret;

    status = MirrorServerCreateFile(
        req->filename,
        &req->security_context,
        req->access_mask,
        req->file_attributes,
        req->share_access,
        req->create_disposition,
        req->create_options,
        &req->file_info
    );

    pr_info(_T("MirrorServerCreateFile() return 0x%08x\n"), status);

    pdu = alloc_mirror_pdu(sizeof(*pdu));
    if (!pdu)
        return;

    pdu->major_function = IRP_MJ_CREATE;
    pdu->minor_function = 0;

    pdu->u.create_resp.status = status;
    memcpy(&pdu->u.create_resp.file_info, &req->file_info, sizeof(DOKAN_FILE_INFO));

    ret = conn->transport->send(conn, pdu, pdu->length);
    if (ret < 0) {
        pr_err(_T("send create_resp failed\n"));
    }
}



static NTSTATUS MirrorServerGetFileInformation(
	LPCWSTR FileName, 
    LPBY_HANDLE_FILE_INFORMATION HandleFileInformation,
	PDOKAN_FILE_INFO DokanFileInfo
) 
{
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	BOOL opened = FALSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	pr_info(_T("GetFileInfo : %s\n"), filePath);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		pr_info(_T("\tinvalid handle, cleanuped?\n"));
		handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			pr_info(_T("\tCreateFile error : %d\n\n"), error);
			return DokanNtStatusFromWin32(error);
		}
		opened = TRUE;
	}

	if (!GetFileInformationByHandle(handle, HandleFileInformation)) {
		pr_err(_T("\terror code = %d\n"), GetLastError());

		// FileName is a root directory
		// in this case, FindFirstFile can't get directory information
		if (wcslen(FileName) == 1) {
			pr_info(_T("  root dir\n"));
			HandleFileInformation->dwFileAttributes = GetFileAttributes(filePath);

		}
		else {
			WIN32_FIND_DATAW find;
			ZeroMemory(&find, sizeof(WIN32_FIND_DATAW));
			HANDLE findHandle = FindFirstFile(filePath, &find);
			if (findHandle == INVALID_HANDLE_VALUE) {
				DWORD error = GetLastError();
				pr_err(_T("\tFindFirstFile error code = %d\n\n"), error);
				if (opened)
					CloseHandle(handle);
				return DokanNtStatusFromWin32(error);
			}
			HandleFileInformation->dwFileAttributes = find.dwFileAttributes;
			HandleFileInformation->ftCreationTime = find.ftCreationTime;
			HandleFileInformation->ftLastAccessTime = find.ftLastAccessTime;
			HandleFileInformation->ftLastWriteTime = find.ftLastWriteTime;
			HandleFileInformation->nFileSizeHigh = find.nFileSizeHigh;
			HandleFileInformation->nFileSizeLow = find.nFileSizeLow;
			pr_info(_T("\tFindFiles OK, file size = %d\n"), find.nFileSizeLow);
			FindClose(findHandle);
		}
	}
	else {
		pr_info(_T("\tGetFileInformationByHandle success, file size = %d\n"),
			HandleFileInformation->nFileSizeLow);
	}

	pr_info(_T("FILE ATTRIBUTE  = %d\n"), HandleFileInformation->dwFileAttributes);

	if (opened)
		CloseHandle(handle);

	return STATUS_SUCCESS;
}


void mirror_process_query_information(
    struct transport_connection* conn,
    struct mirror_query_information_request* req
)
{
    struct mirror_pdu* pdu;
    NTSTATUS status;
    int ret;

    pdu = alloc_mirror_pdu(sizeof(*pdu));
    if (!pdu) {
        pr_err(_T("allocate pdu for query_info failed\n"));
        return;
    }

    pdu->major_function = IRP_MJ_QUERY_INFORMATION;
    pdu->minor_function = 0;

    status = MirrorServerGetFileInformation(
        req->file_name,
        &pdu->u.queryinfo_resp.by_handle_file_info,
        &req->file_info
    );
    
    pdu->u.queryinfo_resp.status = status;

	ret = conn->transport->send(conn, pdu, pdu->length);
	if (ret < 0) {
		pr_err(_T("send queryinfo_resp failed\n"));
	}
}

void mirror_process_read(
    struct transport_connection* conn, 
    struct mirror_read_request* req
)
{
    struct mirror_pdu* pdu;
	WCHAR filePath[DOKAN_MAX_PATH];
    HANDLE handle;
	BOOL opened = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    int ret;

    pr_debug(_T("-> mirror_process_read(), offset(%i64d), length(%d)\n"), 
        req->read_offset.QuadPart, req->read_length);

    pdu = alloc_mirror_pdu(sizeof(*pdu) + req->read_length);
    if (!pdu) {
        pr_err(_T("allocate read_resp pdu failed\n"));
        goto Cleanup;
    }

    pdu->type = MIRROR_PDU_STANDARD_REQUEST;
    pdu->major_function = IRP_MJ_READ;
    pdu->minor_function = 0;

    handle = (HANDLE)req->file_info.Context;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->file_name);

	pr_debug(_T("ReadFile : %s\n"), filePath);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		pr_info(_T("\tinvalid handle, cleanuped?\n"));
		handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			pr_err(_T("\tCreateFile error(%d)\n"), error);
			pdu->u.read_resp.status = DokanNtStatusFromWin32(error);
            pdu->length = sizeof(*pdu);
            goto Cleanup;
		}
		opened = TRUE;
	}

	if (!SetFilePointerEx(handle, req->read_offset, NULL, FILE_BEGIN)) {
		DWORD error = GetLastError();
		pr_err(_T("\tseek failed, error(%d)\n"), error);
		if (opened)
			CloseHandle(handle);
		pdu->u.read_resp.status = DokanNtStatusFromWin32(error);
        pdu->length = sizeof(*pdu);
	}

    BOOL bret = ReadFile(
        handle,
        &pdu->u.read_resp.buffer,
        req->read_length,
        &pdu->u.read_resp.actual_length,
        NULL
    );
    if (!bret) {
		DWORD error = GetLastError();
		pr_err(_T("\tread failed, error(%d)\n"), error);
		if (opened)
			CloseHandle(handle);
		pdu->u.read_resp.status = DokanNtStatusFromWin32(error);
        pdu->length = sizeof(*pdu);
        goto Cleanup;
	}
	
    pr_info(_T("read succeeded, actual(%d)"), pdu->u.read_resp.actual_length);

	if (opened)
		CloseHandle(handle);

Cleanup:
    if (pdu) {
		ret = conn->transport->send(conn, pdu, pdu->length);
		if (ret < 0) {
            pr_err(_T("send read-resp failed\n"));
		}

        free_mirror_pdu(&pdu);
    }
}

void mirror_process_write(
    struct transport_connection* conn, 
    struct mirror_write_request* req
)
{
	struct mirror_pdu write_resp;
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	BOOL opened = FALSE;
	int ret;
	DWORD writeLength = req->length;

	bzero(&write_resp, sizeof(write_resp));
	
	write_resp.length = sizeof(write_resp);
	write_resp.type = MIRROR_PDU_STANDARD_RESPONSE;
	write_resp.major_function = IRP_MJ_WRITE;
	write_resp.minor_function = 0;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->file_name);

	pr_info(_T("WriteFile(%s), offset(%I64d), length(%d)\n"), 
		filePath, req->offset.QuadPart, req->length);

	handle = (HANDLE)req->file_info.Context;

	// reopen the file
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		pr_err(_T("\tinvalid handle, cleanuped?\n"));
		handle = CreateFile(filePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			pr_err(_T("\tCreateFile error : %d\n"), error);
			write_resp.u.write_resp.status = DokanNtStatusFromWin32(error);
			goto Cleanup;
		}
		opened = TRUE;
	}

	UINT64 fileSize = 0;
	DWORD fileSizeLow = 0;
	DWORD fileSizeHigh = 0;
	fileSizeLow = GetFileSize(handle, &fileSizeHigh);
	if (fileSizeLow == INVALID_FILE_SIZE) {
		DWORD error = GetLastError();
		pr_err(_T("\tcan not get a file size error = %d\n"), error);
		if (opened)
			CloseHandle(handle);
		write_resp.u.write_resp.status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	fileSize = ((UINT64)fileSizeHigh << 32) | fileSizeLow;

	LARGE_INTEGER distanceToMove;
	if (req->file_info.WriteToEndOfFile) {
		LARGE_INTEGER z;
		z.QuadPart = 0;
		if (!SetFilePointerEx(handle, z, NULL, FILE_END)) {
			DWORD error = GetLastError();
			pr_err(_T("\tseek error, offset = EOF, error = %d\n"), error);
			if (opened)
				CloseHandle(handle);
			write_resp.u.write_resp.status = DokanNtStatusFromWin32(error);
			goto Cleanup;
		}
	}
	else {
		// Paging IO cannot write after allocate file size.
		if (req->file_info.PagingIo) {
			if (req->offset.QuadPart >= fileSize) {
				write_resp.u.write_resp.status= STATUS_SUCCESS;
				write_resp.u.write_resp.actual_length = 0;
				
				if (opened)
					CloseHandle(handle);
				goto Cleanup;
			}

			if ((req->offset.QuadPart + req->length) > fileSize) {
				UINT64 bytes = fileSize - req->offset.QuadPart;
				if (bytes >> 32) {
					writeLength = (DWORD)(bytes & 0xFFFFFFFFUL);
				}
				else {
					writeLength = (DWORD)bytes;
				}
			}
		}

		if (req->offset.QuadPart > fileSize) {
			// In the mirror sample helperZeroFileData is not necessary. NTFS will
			// zero a hole.
			// But if user's file system is different from NTFS( or other Windows's
			// file systems ) then  users will have to zero the hole themselves.
		}

		distanceToMove.QuadPart = req->offset.QuadPart;
		if (!SetFilePointerEx(handle, distanceToMove, NULL, FILE_BEGIN)) {
			DWORD error = GetLastError();
			pr_err(_T("\tseek error, offset(%I64d), error(%d)\n"), 
				req->offset.QuadPart, error);
			if (opened)
				CloseHandle(handle);
			write_resp.u.write_resp.status = DokanNtStatusFromWin32(error);
			goto Cleanup;
		}
	}

	BOOL bret = WriteFile(
		handle,
		&req->buffer[0],
		writeLength,
		&write_resp.u.write_resp.actual_length,
		NULL
	);
	if (!bret) {
		DWORD error = GetLastError();
		pr_err(_T("\twrite failed, error(%u), length(%d), actual(%d)\n"),
			error, writeLength, write_resp.u.write_resp.actual_length);
		if (opened)
			CloseHandle(handle);
		write_resp.u.write_resp.status = DokanNtStatusFromWin32(error);
		goto Cleanup;

	}
	
	pr_info(_T("\twrite succeeded, length(%d), offset(%I64d)\n"), 
		write_resp.u.write_resp.actual_length, req->offset.QuadPart);
	
	write_resp.u.write_resp.status = STATUS_SUCCESS;

	// close the file when it is reopened
	if (opened)
		CloseHandle(handle);

Cleanup:
	ret = conn->transport->send(conn, &write_resp, write_resp.length);
	if (ret < 0) {
		pr_err(_T("send write-resp failed, ret(%d)\n"), ret);
	}
}

void mirror_process_flush_buffers(
	struct transport_connection* conn,
	struct mirror_flush_buffers_request* req
)
{
	struct mirror_pdu resp;
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	int ret;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	bzero(&resp, sizeof(resp));

	resp.length = sizeof(resp);
	resp.type = MIRROR_PDU_STANDARD_RESPONSE;
	resp.major_function = IRP_MJ_FLUSH_BUFFERS;
	resp.minor_function = 0;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->file_name);

	pr_debug(_T("-> mirror_process_flush_buffers(), file(%s)\n"),
		filePath);
	
	handle = (HANDLE)req->file_info.Context;

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		pr_err(_T("\tinvalid handle\n"));
		status = STATUS_SUCCESS;
		goto Cleanup;
	}

	if (!FlushFileBuffers(handle)) {
		DWORD error = GetLastError();
		pr_err(_T("\tflush failed, error(%d)\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	status = STATUS_SUCCESS;
	goto Cleanup;

Cleanup:
	resp.u.flushbuffers_resp.status = status;

	ret = conn->transport->send(conn, &resp, sizeof(resp));
	if (ret < 0) {
		pr_err(_T("send flushbuffers-resp failed, ret(%d)\n"), ret);
	}
}

static void MirrorServerCleanup(
	LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo
)
{
	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	if (DokanFileInfo->Context) {
		pr_info(_T("Cleanup: %s\n"), filePath);
		CloseHandle((HANDLE)(DokanFileInfo->Context));
		DokanFileInfo->Context = 0;
	}
	else {
		pr_info(_T("Cleanup: %s\n\tinvalid handle\n"), filePath);
	}

	if (DokanFileInfo->DeleteOnClose) {
		// Should already be deleted by CloseHandle
		// if open with FILE_FLAG_DELETE_ON_CLOSE
		pr_info(_T("\tDeleteOnClose\n"));
		if (DokanFileInfo->IsDirectory) {
			pr_info(_T("  DeleteDirectory "));
			if (!RemoveDirectory(filePath)) {
				pr_err(_T("error code = %d\n\n"), GetLastError());
			}
			else {
				pr_info(_T("success\n\n"));
			}
		}
		else {
			pr_info(_T("  DeleteFile "));
			if (DeleteFile(filePath) == 0) {
				pr_err(_T(" error code = %d\n\n"), GetLastError());
			}
			else {
				pr_info(_T("success\n\n"));
			}
		}
	}
}

void mirror_process_cleanup(
    struct transport_connection* conn,
    struct mirror_cleanup_request* req
)
{
    struct mirror_pdu* pdu = NULL;
    int ret;

    MirrorServerCleanup(
        req->filename,
        &req->file_info
    );

    pdu = alloc_mirror_pdu(sizeof(*pdu));
    if (!pdu) {
        pr_err(_T("allocate pdu for cleanup_resp failed\n"));
        goto Cleanup;
    }

    pdu->major_function = IRP_MJ_CLEANUP;
    pdu->minor_function = 0;

    pdu->u.cleanup_resp.status = STATUS_SUCCESS;
    memcpy(&pdu->u.cleanup_resp.file_info, &req->file_info, sizeof(DOKAN_FILE_INFO));

    ret = conn->transport->send(conn, pdu, pdu->length);
    if (ret < 0) {
        pr_err(_T("send cleanup_resp failed\n"));
        goto Cleanup;
    }

Cleanup:
    free_mirror_pdu(&pdu);
}



static void MirrorServerCloseFile(
	LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo
)
{
	WCHAR filePath[DOKAN_MAX_PATH];
	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	if (DokanFileInfo->Context) {
		pr_info(_T("CloseFile: %s\n"), filePath);
		pr_info(_T("\terror : not cleanuped file\n\n"));
		CloseHandle((HANDLE)DokanFileInfo->Context);
		DokanFileInfo->Context = 0;
	}
	else {
		pr_info(_T("Close: %s\n\n"), filePath);
	}
}


void mirror_process_close(
    struct transport_connection* conn,
    struct mirror_close_request* req
)
{
	struct mirror_pdu* pdu = NULL;
	int ret;

	MirrorServerCloseFile(
		req->filename,
		&req->file_info
	);

	pdu = alloc_mirror_pdu(sizeof(*pdu));
	if (!pdu) {
		pr_err(_T("allocate pdu for close_resp failed\n"));
		goto Cleanup;
	}

	pdu->major_function = IRP_MJ_CLOSE;
	pdu->minor_function = 0;

	pdu->u.close_resp.status = STATUS_SUCCESS;
	memcpy(&pdu->u.close_resp.file_info, &req->file_info, sizeof(DOKAN_FILE_INFO));

	ret = conn->transport->send(conn, pdu, pdu->length);
	if (ret < 0) {
		pr_err(_T("send close_resp failed\n"));
		goto Cleanup;
	}

Cleanup:
	free_mirror_pdu(&pdu);
}

void mirror_server_process_standard_reqeust(
    struct transport_connection* conn,
    struct mirror_pdu* pdu
)
{
	switch (pdu->major_function) {
	case IRP_MJ_CREATE:
		mirror_process_create_request(conn, &pdu->u.create_req);
		break;

	case IRP_MJ_CLEANUP:
		mirror_process_cleanup(conn, &pdu->u.cleanup_req);
		break;

	case IRP_MJ_CLOSE:
		mirror_process_close(conn, &pdu->u.close_req);
		break;

	case IRP_MJ_QUERY_INFORMATION:
		mirror_process_query_information(conn, &pdu->u.queryinfo_req);
		break;

    case IRP_MJ_READ:
        mirror_process_read(conn, &pdu->u.read_req);
        break;

    case IRP_MJ_WRITE:
        mirror_process_write(conn, &pdu->u.write_req);
        break;

	case IRP_MJ_FLUSH_BUFFERS:
		mirror_process_flush_buffers(conn, &pdu->u.flushbuffers_req);
		break;

	default:
		break;
	}
}

void mirror_server_find_files(
	struct transport_connection* conn,
	struct mirror_pdu* pdu
)
{
    const WCHAR* FileName = pdu->u.findfiles_req.file_name;
	struct mirror_pdu response_pdu;
    WIN32_FIND_DATAW* findData = &response_pdu.u.findfiles_resp.find_data;
	NTSTATUS status;
	WCHAR filePath[DOKAN_MAX_PATH];
	size_t fileLen;
	HANDLE hFind;
	DWORD error;
	int count = 0;
    int ret = 0;

    bzero(&response_pdu, sizeof(response_pdu));
    response_pdu.length = sizeof(response_pdu);
    response_pdu.type = MIRROR_PDU_FIND_FILES_RESPONSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, pdu->u.findfiles_req.file_name);

	pr_info(_T("FindFiles: %s -> %s\n"), FileName, filePath);

	fileLen = wcslen(filePath);
	if (filePath[fileLen - 1] != L'\\') {
		filePath[fileLen++] = L'\\';
	}
    if (fileLen + 1 >= DOKAN_MAX_PATH) {
        status = STATUS_BUFFER_OVERFLOW;
        goto Cleanup;
    }

	filePath[fileLen] = L'*';
	filePath[fileLen + 1] = L'\0';

	hFind = FindFirstFile(filePath, findData);

	if (hFind == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		pr_err(_T("\tinvalid file handle. Error is %u\n\n"), error);
		status = DokanNtStatusFromWin32(error);
        goto Cleanup;
	}

	// Root folder does not have . and .. folder - we remove them
	BOOLEAN rootFolder = (wcscmp(FileName, L"\\") == 0);
	do {
        pr_info(_T("    [%d]: %s\n"), count, findData->cFileName);

        if (!rootFolder || (wcscmp(findData->cFileName, L".") != 0 &&
            wcscmp(findData->cFileName, L"..") != 0))
        {
            response_pdu.u.findfiles_resp.status = STATUS_SUCCESS;

            ret = conn->transport->send(conn, &response_pdu, sizeof(response_pdu));
            if (ret < 0) {
                pr_err(_T("send find-files data failed, ret(%d)\n"), ret);
                break;
            }
        }
		count++;
	} while (FindNextFile(hFind, findData) != 0);

    if (ret < 0) {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

	error = GetLastError();
	FindClose(hFind);

	if (error != ERROR_NO_MORE_FILES) {
		pr_err(_T("\tFindNextFile error. Error is %u\n"), error);
		status = DokanNtStatusFromWin32(error);
        goto Cleanup;
	}

	pr_info(_T("\tFindFiles return %d entries in %s\n\n"), count, filePath);

    status = STATUS_NO_MORE_FILES;

Cleanup:
    response_pdu.type = MIRROR_PDU_FIND_FILES_RESPONSE;
    response_pdu.u.findfiles_resp.status = status;

    ret = conn->transport->send(conn, &response_pdu, sizeof(response_pdu));
    if (ret < 0) {
        pr_err(_T("send find-files response failed, ret(%d)\n"), ret);
    }
}

void mirror_server_set_file_attributes(
	struct transport_connection* conn, 
	struct mirror_file_attributes_request* req
)
{
	struct mirror_pdu resp;
	WCHAR filePath[DOKAN_MAX_PATH];
	int ret;

	bzero(&resp, sizeof(resp));
	
	resp.length = sizeof(resp);
	resp.type = MIRROR_PDU_SET_FILE_ATTRIBUTES_RESPONSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->file_name);

	pr_debug(_T("-> mirror_server_set_file_attributes(), file(%s) attributes(0x%08x)\n"), 
		filePath, req->file_attributes);

	if (req->file_attributes != 0) {
		if (!SetFileAttributes(filePath, req->file_attributes)) {
			DWORD error = GetLastError();
			pr_err(_T("\terror code = %d\n"), error);
			resp.u.fileattributes_resp.status = DokanNtStatusFromWin32(error);
		}
		else {
			resp.u.fileattributes_resp.status = STATUS_SUCCESS;
		}
	}
	else {
		// case FileAttributes == 0 :
		// MS-FSCC 2.6 File Attributes : There is no file attribute with the value 0x00000000
		// because a value of 0x00000000 in the FileAttributes field means that the file attributes for this file MUST NOT be changed when setting basic information for the file
		pr_info(_T("Set 0 to FileAttributes means MUST NOT be changed. Didn't call ")
			L"SetFileAttributes function. \n");
		resp.u.fileattributes_resp.status = STATUS_SUCCESS;
	}

	ret = conn->transport->send(conn, &resp, sizeof(resp));
	if (ret < 0) {
		pr_err(_T("send fileattributes-resp failed, ret(%d)\n"), ret);
	}
}

void mirror_server_set_file_time(
	struct transport_connection* conn, 
	struct mirror_file_time_request* req
)
{
	struct mirror_pdu resp;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	int ret;
	const FILETIME* createtime = NULL;
	const FILETIME* lastAccessTime = NULL;
	const FILETIME* lastWriteTime = NULL;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->file_name);

	pr_debug(L"-> mirror_server_set_file_time(), file(%s)\n", filePath);

	bzero(&resp, sizeof(resp));

	resp.length = sizeof(resp);
	resp.type = MIRROR_PDU_SET_FILE_TIME_RESPONSE;

	handle = (HANDLE)req->file_info.Context;

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		pr_err(_T("\tinvalid handle\n"));
		status = STATUS_INVALID_HANDLE;
		goto Cleanup;
	}

	if (req->fSetCreationTime) {
		createtime = &req->CreationTime;
	}
	if (req->fSetLastAccessTime) {
		lastAccessTime = &req->LastAccessTime;
	}
	if (req->fSetLastWriteTime) {
		lastWriteTime = &req->LastWriteTime;
	}

	if (!SetFileTime(handle, createtime, lastAccessTime, lastWriteTime)) {
		DWORD error = GetLastError();
		pr_err(_T("  set filetime failed, error(%d)\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	status = STATUS_SUCCESS;

Cleanup:
	resp.u.filetime_resp.status = status;
	ret = conn->transport->send(conn, &resp, sizeof(resp));
	if (ret < 0) {
		pr_err(_T("send filetime-resp failed, ret(%d)\n"), ret);
	}
}


void mirror_server_set_end_of_file(
	struct transport_connection* conn,
	struct mirror_set_end_of_file_request* req
	)
{
	struct mirror_pdu resp;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	int ret;

	bzero(&resp, sizeof(resp));

	resp.length = sizeof(resp);
	resp.type = MIRROR_PDU_SET_END_OF_FILE_RESPONSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->file_name);

	pr_debug(_T("-> mirror_server_set_end_of_file(), file(%s), offset(%I64d)\n"),
		filePath, req->offset.QuadPart);

	handle = (HANDLE)req->file_info.Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		pr_err(_T("\tinvalid handle\n"));
		status = STATUS_INVALID_HANDLE;
		goto Cleanup;
	}

	if (!SetFilePointerEx(handle, req->offset, NULL, FILE_BEGIN)) {
		DWORD error = GetLastError();
		pr_err(_T("  SetFilePointer failed, error(%d)\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	if (!SetEndOfFile(handle)) {
		DWORD error = GetLastError();
		pr_err(_T("SetEndOfFile failed, error(%d)\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	status = STATUS_SUCCESS;

Cleanup:
	resp.u.endoffile_resp.status = status;
	ret = conn->transport->send(conn, &resp, sizeof(resp));
	if (ret < 0) {
		pr_err(_T("send endoffile-resp failed, ret(%d)\n"), ret);
	}
}


void mirror_server_delete_file(
	struct transport_connection* conn,
	struct mirror_delete_file_request* req
)
{
	struct mirror_pdu resp;
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	DWORD dwAttributes;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int ret;

	bzero(&resp, sizeof(resp));

	resp.length = sizeof(resp);
	resp.type = MIRROR_PDU_DELETE_FILE_RESPONSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->file_name);

	pr_debug(_T("-> mirror_server_delete_file(), file(%s)\n"), filePath);

	handle = (HANDLE)req->file_info.Context;
	
	dwAttributes = GetFileAttributes(filePath);

	if (dwAttributes != INVALID_FILE_ATTRIBUTES &&
		(dwAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		status = STATUS_ACCESS_DENIED;
		goto Cleanup;
	}

	if (handle && handle != INVALID_HANDLE_VALUE) {
		FILE_DISPOSITION_INFO fdi;
		BOOL bret;
		
		fdi.DeleteFile = req->file_info.DeleteOnClose;
		
		bret = SetFileInformationByHandle(
			handle,
			FileDispositionInfo,
			&fdi,
			sizeof(FILE_DISPOSITION_INFO)
		);
		if (!bret) {
			DWORD dwErrCode = GetLastError();
			pr_err(_T("set DeleteOnClose failed, error(%d)\n"), dwErrCode);
			status = DokanNtStatusFromWin32(GetLastError());
			goto Cleanup;
		}
	}

	status = STATUS_SUCCESS;

Cleanup:

	resp.u.deletefile_resp.status = status;

	ret = conn->transport->send(conn, &resp, resp.length);
	if (ret < 0) {
		pr_err(_T("send deletefile-resp failed, ret(%d)\n"), ret);
	}
}


void mirror_server_delete_directory(
	struct transport_connection* conn,
	struct mirror_delete_directory_request* req
)
{
	struct mirror_pdu resp;
	WCHAR filePath[DOKAN_MAX_PATH];
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hFind;
	WIN32_FIND_DATAW findData;
	size_t fileLen;
	int ret;

	bzero(&resp, sizeof(resp));

	resp.length = sizeof(resp);
	resp.type = MIRROR_PDU_DELETE_DIRECTORY_RESPONSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->file_name);

	pr_debug(_T("-> mirror_server_delete_directory(), file(%s)\n"), filePath);

	if (!req->file_info.DeleteOnClose) {
		//Dokan notify that the file is requested not to be deleted.
		status = STATUS_SUCCESS;
		goto Cleanup;
	}

	fileLen = wcslen(filePath);
	if (filePath[fileLen - 1] != L'\\') {
		filePath[fileLen++] = L'\\';
	}
	if (fileLen + 1 >= DOKAN_MAX_PATH) {
		status = STATUS_BUFFER_OVERFLOW;
		goto Cleanup;
	}

	filePath[fileLen] = L'*';
	filePath[fileLen + 1] = L'\0';

	hFind = FindFirstFile(filePath, &findData);

	if (hFind == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		pr_err(_T("\tDeleteDirectory error code = %d\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	do {
		if (wcscmp(findData.cFileName, L"..") != 0 &&
			wcscmp(findData.cFileName, L".") != 0) 
		{
			FindClose(hFind);
			pr_err(_T("\tDirectory is not empty: %s\n"), findData.cFileName);
			status = STATUS_DIRECTORY_NOT_EMPTY;
			goto Cleanup;
		}
	} while (FindNextFile(hFind, &findData) != 0);

	DWORD error = GetLastError();

	FindClose(hFind);

	if (error != ERROR_NO_MORE_FILES) {
		pr_err(_T("\tDeleteDirectory error code = %d\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	status = STATUS_SUCCESS;

Cleanup:

	resp.u.deletedirectory_resp.status = status;

	ret = conn->transport->send(conn, &resp, resp.length);
	if (ret < 0) {
		pr_err(_T("send deletedirectory-resp failed, ret(%d)\n"), ret);
	}
}

void mirror_server_move_file(
	struct transport_connection* conn,
	struct mirror_move_file_request* req
)
{
	struct mirror_pdu resp;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	WCHAR filePath[DOKAN_MAX_PATH];
	WCHAR newFilePath[DOKAN_MAX_PATH];
	HANDLE handle;
	DWORD bufferSize;
	BOOL bret;
	size_t newFilePathLen;
	int ret;
	PFILE_RENAME_INFO renameInfo = NULL;

	bzero(&resp, sizeof(resp));

	resp.length = sizeof(resp);
	resp.type = MIRROR_PDU_MOVE_FILE_RESPONSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->ExistingFileName);
	if (wcslen(req->NewFileName) && req->NewFileName[0] != ':') {
		GetFilePath(newFilePath, DOKAN_MAX_PATH, req->NewFileName);
	}
	else {
		// For a stream rename, FileRenameInfo expect the FileName param without the filename
		// like :<stream name>:<stream type>
		wcsncpy_s(newFilePath, DOKAN_MAX_PATH, req->NewFileName, wcslen(req->NewFileName));
	}

	pr_debug(_T("-> mirror_server_move_file(), %s -> %s\n"), filePath, newFilePath);

	handle = (HANDLE)req->FileInfo.Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		pr_err(_T("\tinvalid handle\n"));
		status = STATUS_INVALID_HANDLE;
		goto Cleanup;
	}

	newFilePathLen = wcslen(newFilePath);

	// the PFILE_RENAME_INFO struct has space for one WCHAR for the name at
	// the end, so that
	// accounts for the null terminator

	bufferSize = (DWORD)(sizeof(FILE_RENAME_INFO) +
		newFilePathLen * sizeof(newFilePath[0]));

	renameInfo = (PFILE_RENAME_INFO)malloc(bufferSize);
	if (!renameInfo) {
		pr_err(_T("allocate FILE_RENAME_INFO failed\n"));
		status = STATUS_BUFFER_OVERFLOW;
		goto Cleanup;
	}
	ZeroMemory(renameInfo, bufferSize);

	renameInfo->ReplaceIfExists =
		req->ReplaceIfExisting
		? TRUE
		: FALSE; 
	renameInfo->RootDirectory = NULL; // hope it is never needed, shouldn't be
	renameInfo->FileNameLength =
		(DWORD)newFilePathLen *
		sizeof(newFilePath[0]); // they want length in bytes

	wcscpy_s(renameInfo->FileName, newFilePathLen + 1, newFilePath);

	bret = SetFileInformationByHandle(
		handle, FileRenameInfo, renameInfo, bufferSize
	);

	free(renameInfo);

	if (!bret) {
		DWORD error = GetLastError();
		pr_err(_T("\tMoveFile failed, error(%u)\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	status = STATUS_SUCCESS;

Cleanup:
	resp.u.movefile_resp.status = status;

	ret = conn->transport->send(conn, &resp, resp.length);
	if (ret < 0) {
		pr_err(_T("send movefile-resp failed, ret(%d)\n"), ret);
	}
}

void mirror_server_set_allocation_size(
	struct transport_connection* conn,
	struct mirror_set_allocation_size_request* req
)
{
	struct mirror_pdu resp;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int ret;

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	LARGE_INTEGER fileSize;
	
	bzero(&resp, sizeof(resp));

	resp.length = sizeof(resp);
	resp.type = MIRROR_PDU_SET_ALLOCATION_SIZE_RESPONSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->FileName);

	pr_debug(_T("SetAllocationSize %s, %I64d\n"), filePath, req->AllocSize);

	handle = (HANDLE)req->FileInfo.Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		pr_err(_T("\tinvalid handle\n"));
		status = STATUS_INVALID_HANDLE;
		goto Cleanup;
	}

	if (GetFileSizeEx(handle, &fileSize)) {
		if (req->AllocSize < fileSize.QuadPart) {
			fileSize.QuadPart = req->AllocSize;
			if (!SetFilePointerEx(handle, fileSize, NULL, FILE_BEGIN)) {
				DWORD error = GetLastError();
				pr_err(_T("SetFilePointer failed, error(%d), offset(%I64d)\n"),
					error, req->AllocSize);
				status = DokanNtStatusFromWin32(error);
				goto Cleanup;
			}

			if (!SetEndOfFile(handle)) {
				DWORD error = GetLastError();
				pr_err(_T("\tSetEndOfFile failed, error(%d)\n"), error);
				status = DokanNtStatusFromWin32(error);
				goto Cleanup;
			}
		}
	}
	else {
		DWORD error = GetLastError();
		pr_err(_T("\terror code = %d\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}
	
	status = STATUS_SUCCESS;

Cleanup:
	resp.u.allocsize_resp.Status = status;
	ret = conn->transport->send(conn, &resp, resp.length);
	if (ret < 0) {
		pr_err(_T("send allocsize-resp failed, ret(%d)\n"), ret);
	}
}


void mirror_server_lock_file(
	struct transport_connection* conn,
	struct mirror_lock_file_request* req
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	LARGE_INTEGER offset;
	LARGE_INTEGER length;
	BOOL bret;
	struct mirror_pdu resp;
	int ret;

	bzero(&resp, sizeof(resp));

	resp.length = sizeof(resp);
	resp.type = MIRROR_PDU_UNLOCK_FILE_RESPONSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->FileName);

	pr_err(_T("LockFile %s\n"), filePath);

	handle = (HANDLE)req->FileInfo.Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		pr_err(_T("\tinvalid handle\n"));
		status = STATUS_INVALID_HANDLE;
		goto Cleanup;
	}

	length.QuadPart = req->Length;
	offset.QuadPart = req->ByteOffset;

	bret = LockFile(
		handle,
		offset.LowPart,
		offset.HighPart,
		length.LowPart,
		length.HighPart
	);
	if (!bret) {
		DWORD error = GetLastError();
		pr_err(_T("LockFile failed, error(%d)\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	status = STATUS_SUCCESS;

Cleanup:
	resp.u.lockfile_resp.Status = status;
	ret = conn->transport->send(conn, &resp, resp.length);
	if (ret < 0) {
		pr_err(_T("send lockfile-req failed, ret(%d)\n"), ret);
	}
}

void mirror_server_unlock_file(
	struct transport_connection* conn,
	struct mirror_unlock_file_request* req
)
{
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	LARGE_INTEGER length;
	LARGE_INTEGER offset;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	struct mirror_pdu resp;
	int ret;
	BOOL bret;

	bzero(&resp, sizeof(resp));

	resp.length = sizeof(resp);
	resp.type = MIRROR_PDU_UNLOCK_FILE_RESPONSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->FileName);

	pr_debug(_T("UnlockFile %s\n"), filePath);

	handle = (HANDLE)req->FileInfo.Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		pr_err(_T("\tinvalid handle\n"));
		status = STATUS_INVALID_HANDLE;
		goto Cleanup;
	}

	length.QuadPart = req->Length;
	offset.QuadPart = req->ByteOffset;

	bret = UnlockFile(
		handle,
		offset.LowPart,
		offset.HighPart,
		length.LowPart,
		length.HighPart
	);
	if (!bret) {
		DWORD error = GetLastError();
		pr_err(_T("UnlockFile failed, error(%d)\n\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	status = STATUS_SUCCESS;

Cleanup:
	resp.u.unlockfile_resp.Status = status;

	ret = conn->transport->send(conn, &resp, resp.length);
	if (ret < 0) {
		pr_err(_T("send unlockfile-resp failed, ret(%d)\n"), ret);
	}
}


void mirror_server_get_file_security(
	struct transport_connection* conn,
	struct mirror_get_file_security_request* req
)
{
	WCHAR filePath[DOKAN_MAX_PATH];
	BOOLEAN requestingSaclInfo;
	struct mirror_pdu* resp = NULL;
	struct mirror_pdu pdu_buffer;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int ret;
	HANDLE handle = INVALID_HANDLE_VALUE;
	SECURITY_INFORMATION* SecurityInformation = &req->SecurityInfomration;
	SECURITY_DESCRIPTOR* SecurityDescriptor = (SECURITY_DESCRIPTOR *)&req->SecurityDescriptor[0];
	ULONG* LengthNeeded = &req->LengthNeeded;
	BOOL fHasSeSecurityPrivilege = FALSE;
	BOOL bret;

	bzero(&pdu_buffer, sizeof(pdu_buffer));
	
	pdu_buffer.length = sizeof(pdu_buffer);
	pdu_buffer.type = MIRROR_PDU_GET_FILE_SECURITY_RESPONSE;

	resp = alloc_mirror_pdu(sizeof(*resp) + req->BufferLength);
	if (!resp) {
		pr_err(_T("allocate getfilesecurity-resp failed\n"));
		resp = &pdu_buffer;
		status = STATUS_NO_MEMORY;
		goto Cleanup;
	}

	GetFilePath(filePath, DOKAN_MAX_PATH, req->FileName);

	pr_info(_T("GetFileSecurity %s\n"), filePath);

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

	if (fHasSeSecurityPrivilege) {
		*SecurityInformation &= ~SACL_SECURITY_INFORMATION;
		*SecurityInformation &= ~BACKUP_SECURITY_INFORMATION;
	}

	pr_info(_T("  Opening new handle with READ_CONTROL access\n"));
	handle = CreateFile(
		filePath,
		READ_CONTROL | ((requestingSaclInfo && fHasSeSecurityPrivilege)
			? ACCESS_SYSTEM_SECURITY
			: 0),
		FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
		NULL, // security attribute
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS, // |FILE_FLAG_NO_BUFFERING,
		NULL);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		pr_err(_T("\tinvalid handle\n"));
		int error = GetLastError();
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	bret = GetUserObjectSecurity(
		handle, 
		SecurityInformation, 
		SecurityDescriptor,
		req->BufferLength, 
		LengthNeeded
	);
	
	if (!bret) {
		int error = GetLastError();
		if (error == ERROR_INSUFFICIENT_BUFFER) {
			pr_err(_T("  GetUserObjectSecurity error: ERROR_INSUFFICIENT_BUFFER\n"));
			status = STATUS_BUFFER_OVERFLOW;
			goto Cleanup;
		}
		else {
			pr_err(_T("  GetUserObjectSecurity failed, error(%d)\n"), error);
			status = DokanNtStatusFromWin32(error);
			goto Cleanup;
		}
	}

	// Ensure the Security Descriptor Length is set
	DWORD securityDescriptorLength =
		GetSecurityDescriptorLength(SecurityDescriptor);
	pr_info(_T("  GetUserObjectSecurity return true,  *LengthNeeded = %d\n"),
		securityDescriptorLength);

	*LengthNeeded = securityDescriptorLength;
	
	resp->u.getfilesecurity_resp.SecurityInformation = *SecurityInformation;
	resp->u.getfilesecurity_resp.BufferLength = req->BufferLength;
	resp->u.getfilesecurity_resp.LengthNeeded = *LengthNeeded;
	memcpy(
		resp->u.getfilesecurity_resp.SecurityDescriptor,
		SecurityDescriptor,
		req->BufferLength
	);

	status = STATUS_SUCCESS;

Cleanup:
	if (!handle && handle != INVALID_HANDLE_VALUE) {
		CloseHandle(handle);
	}

	ret = conn->transport->send(conn, resp, resp->length);
	if (ret < 0) {
		pr_err(_T("send getfilesecurity-resp failed, ret(%d)\n"), ret);
	}

	if (resp != &pdu_buffer) {
		free_mirror_pdu(&resp);
	}
}

void mirror_server_set_file_security(
	struct transport_connection* conn,
	struct mirror_set_file_security_request* req
)
{
	struct mirror_pdu* resp = NULL;
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	NTSTATUS status;
	BOOL bret;
	int ret;

	resp = alloc_mirror_pdu(sizeof(*resp) + req->SecurityDescriptorLength);
	if (!resp) {
		pr_err(_T("alloc setfilesecurity-resp failed\n"));
		goto Cleanup;
	}

	resp->type = MIRROR_PDU_SET_FILE_SECURITY_RESPONSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->FileName);

	pr_debug(_T("SetFileSecurity %s\n"), filePath);

	handle = (HANDLE)req->FileInfo.Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		pr_err(_T("\tinvalid handle\n"));
		status = STATUS_INVALID_HANDLE;
		goto Cleanup;
	}

	bret = SetUserObjectSecurity(
		handle, 
		&req->SecurityInformation, 
		(PSECURITY_DESCRIPTOR)&req->SecurityDescriptor[0]
	);
	if (!bret) {
		int error = GetLastError();
		pr_err(_T("  SetUserObjectSecurity error: %d\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}
	
	resp->u.setfilesecurity_resp.SecurityInformation =
		req->SecurityInformation;
	resp->u.setfilesecurity_resp.SecurityDescriptorLength =
		req->SecurityDescriptorLength;
	memcpy(
		&resp->u.setfilesecurity_resp.SecurityDescriptor[0],
		&req->SecurityDescriptor[0],
		req->SecurityDescriptorLength
	);

	status = STATUS_SUCCESS;

Cleanup:
	if (resp) {
		ret = conn->transport->send(conn, resp, resp->length);
		if (ret < 0) {
			pr_err(_T("send setfilesecurity-resp failed, ret(%d)\n"), ret);
		}
	}

	if (resp) {
		free_mirror_pdu(&resp);
	}
}


void mirror_server_get_disk_free_space(
	struct transport_connection* conn,
	struct mirror_get_disk_free_space_request* req
)
{
	struct mirror_pdu resp;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int ret;
	DWORD SectorsPerCluster;
	DWORD BytesPerSector;
	DWORD NumberOfFreeClusters;
	DWORD TotalNumberOfClusters;
	WCHAR DriveLetter[3] = { 'C', ':', 0 };
	PWCHAR RootPathName;

	bzero(&resp, sizeof(resp));

	resp.length = sizeof(resp);
	resp.type = MIRROR_PDU_GET_DISK_FREE_SPACE_RESPONSE;

	if (RootDirectory[0] == L'\\') { // UNC as Root
		RootPathName = RootDirectory;
	}
	else {
		DriveLetter[0] = RootDirectory[0];
		RootPathName = DriveLetter;
	}

	GetDiskFreeSpace(
		RootPathName, 
		&SectorsPerCluster, 
		&BytesPerSector,
		&NumberOfFreeClusters, 
		&TotalNumberOfClusters
	);
	resp.u.getdiskfreespace_resp.FreeBytesAvailable =
		((ULONGLONG)SectorsPerCluster) * BytesPerSector * NumberOfFreeClusters;
	resp.u.getdiskfreespace_resp.TotalNumberOfFreeBytes =
		((ULONGLONG)SectorsPerCluster) * BytesPerSector * NumberOfFreeClusters;
	resp.u.getdiskfreespace_resp.TotalNumberOfBytes =
		((ULONGLONG)SectorsPerCluster) * BytesPerSector * TotalNumberOfClusters;

	status = STATUS_SUCCESS;

	resp.u.getdiskfreespace_resp.Status = status;

	ret = conn->transport->send(conn, &resp, resp.length);
	if (ret < 0) {
		pr_err(_T("send getdiskfreespace-resp failed, ret(%d)\n"), ret);
	}
}


void mirror_server_get_volume_info(
	struct transport_connection* conn,
	struct mirror_get_volume_info_request* req
)
{
	BOOL CaseSensitive = FALSE;
	struct mirror_pdu pdu;
	struct mirror_get_volume_info_response* resp;
	WCHAR volumeRoot[4];
	DWORD fsFlags = 0;
	BOOL bret;
	int ret;

	bzero(&pdu, sizeof(pdu));

	pdu.length = sizeof(pdu);
	pdu.type = MIRROR_PDU_GET_VOLUME_INFO_RESPONSE;

	resp = &pdu.u.getvolumeinfo_resp;

	wcscpy_s(resp->VolumeName, ARRAYSIZE(resp->VolumeName), L"DOKAN");

	resp->VolumeSerialNumber = 0x19831116;
	resp->MaximumComponentLength = 255;
	resp->FileSystemFlags = 
		FILE_SUPPORTS_REMOTE_STORAGE | 
		FILE_UNICODE_ON_DISK |
		FILE_PERSISTENT_ACLS | 
		FILE_NAMED_STREAMS;

	if (CaseSensitive) {
		resp->FileSystemFlags |=
			FILE_CASE_SENSITIVE_SEARCH |
			FILE_CASE_PRESERVED_NAMES;
	}

	volumeRoot[0] = RootDirectory[0];
	volumeRoot[1] = ':';
	volumeRoot[2] = '\\';
	volumeRoot[3] = '\0';
	
	bret = GetVolumeInformation(
		volumeRoot, 
		NULL, 
		0, 
		NULL, 
		&resp->MaximumComponentLength,
		&fsFlags, 
		resp->FileSystemName,
		ARRAYSIZE(resp->FileSystemName)
	);
	
	if (bret) {
		resp->FileSystemFlags &= fsFlags;

		pr_info(_T("  MaximumComponentLength: %u\n"),
			resp->MaximumComponentLength);
		
		pr_info(_T("FileSystemName: %s\n"),
				resp->FileSystemName);
		
		pr_info(_T("FileSystemFlags(0x%08x), fsFlags(0x%08x)\n"),
			resp->FileSystemFlags, fsFlags);
	}
	else {

		pr_err(_T("GetVolumeInformation failed, error(%d)\n"), GetLastError());

		// File system name could be anything up to 10 characters.
		// But Windows check few feature availability based on file system name.
		// For this, it is recommended to set NTFS or FAT here.
		wcscpy_s(resp->FileSystemName, ARRAYSIZE(resp->FileSystemName), L"NTFS");
	}

	ret = conn->transport->send(conn, &pdu, pdu.length);
	if (ret < 0) {
		pr_err(_T("send getvolumeinfo-resp failed, ret(%d)\n"), ret);
	}
}


void mirror_server_find_streams(
	struct transport_connection* conn,
	struct mirror_pdu_find_streams_request* req
)
{
	struct mirror_pdu resp;
	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE hFind = INVALID_HANDLE_VALUE;
	int ret;
	DWORD error;
	int count = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	bzero(&resp, sizeof(resp));
	
	resp.length = sizeof(resp);
	resp.type = MIRROR_PDU_FIND_STREAMS_RESPONSE;

	GetFilePath(filePath, DOKAN_MAX_PATH, req->FileName);

	pr_debug(_T("FindStreams :%s\n"), filePath);

	hFind = FindFirstStreamW(
		filePath, 
		FindStreamInfoStandard, 
		&resp.u.findstreams_resp.FindStreamData, 
		0
	);
	if (hFind == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		pr_err(_T("FindFirstStreamW() failed, error(%d)\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	resp.u.findstreams_resp.Status = STATUS_SUCCESS;

	do {
		ret = conn->transport->send(conn, &resp, resp.length);
		if (ret < 0) {
			pr_err(_T("send findstreams-resp failed, ret(%d)\n"), ret);
			break;
		}

		count++;

	} while (FindNextStreamW(hFind, &resp.u.findstreams_resp.FindStreamData) != 0);

	error = GetLastError();
	FindClose(hFind);

	if (error != ERROR_HANDLE_EOF) {
		pr_err(_T("FindNextStreamW failed, error(%d)\n"), error);
		status = DokanNtStatusFromWin32(error);
		goto Cleanup;
	}

	status = STATUS_NO_MORE_ENTRIES;

Cleanup:
	resp.u.findstreams_resp.Status = status;

	ret = conn->transport->send(conn, &resp, resp.length);
	if (ret < 0) {
		pr_err(_T("send findstreams-resp failed, ret(%d)\n"), ret);
	}
}


void mirror_process_request(
	struct transport_connection* conn,
	struct mirror_pdu* pdu
)
{
    switch (pdu->type) {
    case MIRROR_PDU_STANDARD_REQUEST:
        mirror_server_process_standard_reqeust(conn, pdu);
        break;

    case MIRROR_PDU_FIND_FILES_REQUEST:
        mirror_server_find_files(conn, pdu);
        break;

	case MIRROR_PDU_SET_FILE_ATTRIBUTES_REQUEST:
		mirror_server_set_file_attributes(conn, &pdu->u.fileattributes_req);
		break;

	case MIRROR_PDU_SET_FILE_TIME_REQUEST:
		mirror_server_set_file_time(conn, &pdu->u.filetime_req);
		break;

	case MIRROR_PDU_SET_END_OF_FILE_REQUEST:
		mirror_server_set_end_of_file(conn, &pdu->u.endoffile_req);
		break;

	case MIRROR_PDU_DELETE_FILE_REQUEST:
		mirror_server_delete_file(conn, &pdu->u.deletefile_req);
		break;

	case MIRROR_PDU_DELETE_DIRECTORY_RESPONSE:
		mirror_server_delete_directory(conn, &pdu->u.deletedirectory_req);
		break;

	case MIRROR_PDU_MOVE_FILE_REQUEST:
		mirror_server_move_file(conn, &pdu->u.movefile_req);
		break;

	case MIRROR_PDU_SET_ALLOCATION_SIZE_REQUEST:
		mirror_server_set_allocation_size(conn, &pdu->u.allocsize_req);
		break;

	case MIRROR_PDU_LOCK_FILE_REQUEST:
		mirror_server_lock_file(conn, &pdu->u.lockfile_req);
		break;

	case MIRROR_PDU_UNLOCK_FILE_REQUEST:
		mirror_server_unlock_file(conn, &pdu->u.unlockfile_req);
		break;

	case MIRROR_PDU_GET_FILE_SECURITY_REQUEST:
		mirror_server_get_file_security(conn, &pdu->u.getfilesecurity_req);
		break;

	case MIRROR_PDU_SET_FILE_SECURITY_REQUEST:
		mirror_server_set_file_security(conn, &pdu->u.setfilesecurity_req);
		break;

	case MIRROR_PDU_GET_DISK_FREE_SPACE_REQUEST:
		mirror_server_get_disk_free_space(conn, &pdu->u.getdiskfreespace_req);
		break;

	case MIRROR_PDU_GET_VOLUME_INFO_REQUEST:
		mirror_server_get_volume_info(conn, &pdu->u.getvolumeinfo_req);
		break;

	case MIRROR_PDU_FIND_STREAMS_REQUEST:
		mirror_server_find_streams(conn, &pdu->u.findstreams_req);
		break;

    default:
        pr_err(_T("unknown pdu->type(%d)\n"), pdu->type);
        break;
    }
}

void mirror_server_loop(
	__inout      PTP_CALLBACK_INSTANCE Instance,
	__inout_opt  PVOID Context,
	__inout      PTP_WORK Work
)
{
	struct transport_connection* conn = (struct transport_connection*)Context;
	struct transport* tp = conn->transport;
	struct mirror_pdu* pdu;
	
	while (1) {
		pdu = mirror_recv_pdu(conn);
		if (!pdu)
			break;

		pr_info(_T("receive pdu length(%d) major(%d) minor(%d)\n"),
			pdu->length, pdu->major_function, pdu->minor_function);

		mirror_process_request(conn, pdu);

		free_mirror_pdu(&pdu);
	}

	tp->destroy(conn);
}


void mirror_server_mainloop(
	struct transport_connection* conn
)
{
	struct transport* tp = conn->transport;
	struct transport_connection* newconn;
	PTP_WORK work;

	while (1) {
		newconn = tp->accept(conn);
		if (newconn) {
			work = CreateThreadpoolWork(mirror_server_loop, newconn, NULL);
			if (!work) {
				pr_err(_T("create server loop work failed, error(%d)\n"),
					GetLastError());
				tp->destroy(newconn);
			}
			else {
				SubmitThreadpoolWork(work);
			}
		}
	}
}

int parse_argument(int argc, TCHAR* argv[])
{
	int opterror = 0;
	int ch;

	while ((ch = getopt(argc, argv, _T("r:p:v"))) != -1) {
		switch (ch) {
		case _T('r'):
			_tcsncpy(RootDirectory, optarg, ARRAYSIZE(RootDirectory));
			break;

		case _T('p'):
			_tcsncpy(TransportUrl, optarg, ARRAYSIZE(TransportUrl));
			break;

		case _T('v'):
			if (trace_level < LOG_LEVEL_TRACE) {
				trace_level++;
			}
			break;
			
		case _T('?'):
		default:
			opterror = 1;
			break;
		}
	}

	if (opterror) {
		ShowUsage();
		exit(EXIT_FAILURE);
	}

	if (_tcslen(RootDirectory) == 0 ||
		_tcslen(TransportUrl) == 0) {
		ShowUsage();
		return -1;
	}

	return 0;
}

int _tmain(int argc, TCHAR* argv[]) 
{
	struct transport* tp;
	struct transport_connection* conn;
	int ret;

	ret = parse_argument(argc, argv);
	if (ret < 0)
		return ret;

	tp = GetTransport(TransportUrl);
	if (!tp) {
		return -1;
	}

	conn = tp->create(tp, TransportUrl, TRUE);
	if (!conn) {
		pr_err(_T("create server connection failed\n"));
	}
	else {
		mirror_server_mainloop(conn);
		tp->destroy(conn);
	}
	
	return 0; 
}
