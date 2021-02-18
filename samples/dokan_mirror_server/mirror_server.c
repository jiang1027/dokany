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
