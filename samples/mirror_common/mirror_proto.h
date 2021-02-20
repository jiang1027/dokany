#ifndef mirror_proto_h__
#define mirror_proto_h__

#include <stdint.h>
#include <memory.h>

#include <dokan.h>
#include <public.h>

#include "transport.h"

struct mirror_create_request
{
	DOKAN_IO_SECURITY_CONTEXT security_context;
	ACCESS_MASK access_mask;
	ULONG file_attributes;
	ULONG share_access;
	ULONG create_disposition;
	ULONG create_options;
	DOKAN_FILE_INFO file_info;
	WCHAR filename[1];
};


struct mirror_create_response
{
	NTSTATUS status;
	DOKAN_FILE_INFO file_info;
};


struct mirror_cleanup_request
{
	DOKAN_FILE_INFO file_info;
	WCHAR filename[1];
};

struct mirror_cleanup_response
{
	DOKAN_FILE_INFO file_info;
	NTSTATUS status;
};


struct mirror_query_information_request
{
	DOKAN_FILE_INFO file_info;
	WCHAR file_name[1];
};

struct mirror_query_information_response
{
	NTSTATUS status;
	BY_HANDLE_FILE_INFORMATION by_handle_file_info;
};


struct mirror_close_request
{
	DOKAN_FILE_INFO file_info;
	WCHAR filename[1];
};

struct mirror_close_response
{
	NTSTATUS status;
	DOKAN_FILE_INFO file_info;
};

struct mirror_find_files_request
{
	DOKAN_FILE_INFO file_info;
	WCHAR file_name[1];
};

struct mirror_find_files_response
{
	NTSTATUS status;
	DOKAN_FILE_INFO file_info;
	WIN32_FIND_DATAW find_data;
};

struct mirror_read_request
{
	DOKAN_FILE_INFO file_info;
	LARGE_INTEGER read_offset;
	DWORD read_length;
	WCHAR file_name[1];
};

struct mirror_read_response
{
	NTSTATUS status;
	DWORD actual_length;
	BYTE buffer[0];
};

struct mirror_write_request
{
	DOKAN_FILE_INFO file_info;
	WCHAR file_name[MAX_PATH];
	DWORD length;
	LARGE_INTEGER offset;
	BYTE buffer[0];
};

struct mirror_write_response
{
	NTSTATUS status;
	DWORD actual_length;
};

struct mirror_file_attributes_request
{
	DOKAN_FILE_INFO file_info;
	DWORD file_attributes;
	WCHAR file_name[MAX_PATH];
};

struct mirror_file_attributes_response
{
	NTSTATUS status;
};

struct mirror_file_time_request
{
	DOKAN_FILE_INFO file_info;
	FILETIME CreationTime;
	FILETIME LastAccessTime;
	FILETIME LastWriteTime;
	BOOL fSetCreationTime;
	BOOL fSetLastAccessTime;
	BOOL fSetLastWriteTime;
	WCHAR file_name[MAX_PATH];
};

struct mirror_file_time_response
{
	NTSTATUS status;
};

struct mirror_set_end_of_file_request
{
	DOKAN_FILE_INFO file_info;
	LARGE_INTEGER offset;
	WCHAR file_name[MAX_PATH];
};

struct mirror_set_end_of_file_response
{
	NTSTATUS status;
};


struct mirror_flush_buffers_request
{
	DOKAN_FILE_INFO file_info;
	WCHAR file_name[MAX_PATH];
};

struct mirror_flush_buffers_response 
{
	NTSTATUS status;
};

struct mirror_delete_file_request
{
	DOKAN_FILE_INFO file_info;
	WCHAR file_name[MAX_PATH];
};

struct mirror_delete_file_response
{
	NTSTATUS status;
};


struct mirror_delete_directory_request
{
	DOKAN_FILE_INFO file_info;
	WCHAR file_name[MAX_PATH];
};

struct mirror_delete_directory_response 
{
	NTSTATUS status;
};

struct mirror_move_file_request
{
	DOKAN_FILE_INFO FileInfo;
	WCHAR ExistingFileName[MAX_PATH];
	WCHAR NewFileName[MAX_PATH];
	BOOL ReplaceIfExisting;
};

struct mirror_move_file_response
{
	NTSTATUS status;
};

struct mirror_set_allocation_size_request
{
	DOKAN_FILE_INFO FileInfo;
	WCHAR FileName[MAX_PATH];
	LONGLONG AllocSize;
};

struct mirror_set_allocation_size_response
{
	NTSTATUS Status;
};

struct mirror_lock_file_request
{
	DOKAN_FILE_INFO FileInfo;
	WCHAR FileName[MAX_PATH];
	LONGLONG ByteOffset;
	LONGLONG Length;
};

struct mirror_lock_file_response
{
	NTSTATUS Status;
};


struct mirror_unlock_file_request
{
	DOKAN_FILE_INFO FileInfo;
	WCHAR FileName[MAX_PATH];
	LONGLONG ByteOffset;
	LONGLONG Length;
};

struct mirror_unlock_file_response
{
	NTSTATUS Status;
};


struct mirror_get_file_security_request
{
	DOKAN_FILE_INFO FileInfo;
	WCHAR FileName[MAX_PATH];
	SECURITY_INFORMATION SecurityInfomration;
	ULONG BufferLength; // length of SecurityDescriptor
	ULONG LengthNeeded;
	BYTE SecurityDescriptor[0];
};

struct mirror_get_file_security_response
{
	NTSTATUS Status;
	SECURITY_INFORMATION SecurityInformation;
	ULONG BufferLength;
	ULONG LengthNeeded;
	BYTE SecurityDescriptor[0];
};

struct mirror_set_file_security_request
{
	DOKAN_FILE_INFO FileInfo;
	WCHAR FileName[MAX_PATH];
	SECURITY_INFORMATION SecurityInformation;
	ULONG SecurityDescriptorLength;
	BYTE SecurityDescriptor[0];
};


struct mirror_set_file_security_response
{
	NTSTATUS Status;
	SECURITY_INFORMATION SecurityInformation;
	ULONG SecurityDescriptorLength;
	BYTE SecurityDescriptor[0];
};


struct mirror_get_disk_free_space_request
{
	DOKAN_FILE_INFO FileInfo;
};

struct mirror_get_disk_free_space_response
{
	NTSTATUS Status;
	ULONGLONG FreeBytesAvailable;
	ULONGLONG TotalNumberOfBytes;
	ULONGLONG TotalNumberOfFreeBytes;
};


struct mirror_get_volume_info_request
{
	DOKAN_FILE_INFO FileInfo;
};

struct mirror_get_volume_info_response
{
	NTSTATUS Status;
	WCHAR VolumeName[MAX_PATH];
	WCHAR FileSystemName[MAX_PATH];
	DWORD VolumeSerialNumber;
	DWORD MaximumComponentLength;
	DWORD FileSystemFlags;
};

struct mirror_pdu_find_streams_request
{
	DOKAN_FILE_INFO FileInfo;
	WCHAR FileName[MAX_PATH];
};

struct mirror_pdu_find_streams_response
{
	NTSTATUS Status;
	WIN32_FIND_STREAM_DATA FindStreamData;
};



enum {
	MIRROR_PDU_STANDARD_REQUEST = 0,
	MIRROR_PDU_STANDARD_RESPONSE = 0,
	MIRROR_PDU_FIND_FILES_REQUEST,
	MIRROR_PDU_FIND_FILES_RESPONSE,
	MIRROR_PDU_SET_FILE_ATTRIBUTES_REQUEST,
	MIRROR_PDU_SET_FILE_ATTRIBUTES_RESPONSE,
	MIRROR_PDU_SET_FILE_TIME_REQUEST,
	MIRROR_PDU_SET_FILE_TIME_RESPONSE,
	MIRROR_PDU_SET_END_OF_FILE_REQUEST,
	MIRROR_PDU_SET_END_OF_FILE_RESPONSE,
	MIRROR_PDU_DELETE_FILE_REQUEST,
	MIRROR_PDU_DELETE_FILE_RESPONSE,
	MIRROR_PDU_DELETE_DIRECTORY_REQUEST,
	MIRROR_PDU_DELETE_DIRECTORY_RESPONSE,
	MIRROR_PDU_MOVE_FILE_REQUEST,
	MIRROR_PDU_MOVE_FILE_RESPONSE,
	MIRROR_PDU_SET_ALLOCATION_SIZE_REQUEST,
	MIRROR_PDU_SET_ALLOCATION_SIZE_RESPONSE,
	MIRROR_PDU_LOCK_FILE_REQUEST,
	MIRROR_PDU_LOCK_FILE_RESPONSE,
	MIRROR_PDU_UNLOCK_FILE_REQUEST,
	MIRROR_PDU_UNLOCK_FILE_RESPONSE,
	MIRROR_PDU_GET_FILE_SECURITY_REQUEST,
	MIRROR_PDU_GET_FILE_SECURITY_RESPONSE,
	MIRROR_PDU_SET_FILE_SECURITY_REQUEST,
	MIRROR_PDU_SET_FILE_SECURITY_RESPONSE,
	MIRROR_PDU_GET_DISK_FREE_SPACE_REQUEST,
	MIRROR_PDU_GET_DISK_FREE_SPACE_RESPONSE,
	MIRROR_PDU_GET_VOLUME_INFO_REQUEST,
	MIRROR_PDU_GET_VOLUME_INFO_RESPONSE,
	MIRROR_PDU_FIND_STREAMS_REQUEST,
	MIRROR_PDU_FIND_STREAMS_RESPONSE,
};

struct mirror_pdu
{
	// total length of this structure, including trailing buffer
	//
	uint32_t length; 

	// MIRROR_PDU_xxx value
	// if MIRROR_PDU_STANDARD_REQUEST/RESPONSE specified, see 
	// major_function/minor_function for more details
	//
	uint32_t type;

	// WDM major/minor functions
	uint8_t major_function;
	uint8_t minor_function;

	// parameters for functions
	union {
		struct mirror_create_request create_req;
		struct mirror_create_response create_resp;

		struct mirror_cleanup_request cleanup_req;
		struct mirror_cleanup_response cleanup_resp;

		struct mirror_close_request close_req;
		struct mirror_close_response close_resp;

		struct mirror_query_information_request queryinfo_req;
		struct mirror_query_information_response queryinfo_resp;

		struct mirror_find_files_request findfiles_req;
		struct mirror_find_files_response findfiles_resp;

		struct mirror_read_request read_req;
		struct mirror_read_response read_resp;

		struct mirror_write_request write_req;
		struct mirror_write_response write_resp;

		struct mirror_flush_buffers_request flushbuffers_req;
		struct mirror_flush_buffers_response flushbuffers_resp;

		struct mirror_file_attributes_request fileattributes_req;
		struct mirror_file_attributes_response fileattributes_resp;

		struct mirror_file_time_request filetime_req;
		struct mirror_file_time_response filetime_resp;

		struct mirror_set_end_of_file_request endoffile_req;
		struct mirror_set_end_of_file_response endoffile_resp;

		struct mirror_delete_file_request deletefile_req;
		struct mirror_delete_file_response deletefile_resp;

		struct mirror_delete_directory_request deletedirectory_req;
		struct mirror_delete_directory_response deletedirectory_resp;

		struct mirror_move_file_request movefile_req;
		struct mirror_move_file_response movefile_resp;

		struct mirror_set_allocation_size_request allocsize_req;
		struct mirror_set_allocation_size_response allocsize_resp;

		struct mirror_lock_file_request lockfile_req;
		struct mirror_lock_file_response lockfile_resp;

		struct mirror_unlock_file_request unlockfile_req;
		struct mirror_unlock_file_response unlockfile_resp;

		struct mirror_get_file_security_request getfilesecurity_req;
		struct mirror_get_file_security_response getfilesecurity_resp;

		struct mirror_set_file_security_request setfilesecurity_req;
		struct mirror_set_file_security_response setfilesecurity_resp;

		struct mirror_get_disk_free_space_request getdiskfreespace_req;
		struct mirror_get_disk_free_space_response getdiskfreespace_resp;

		struct mirror_get_volume_info_request getvolumeinfo_req;
		struct mirror_get_volume_info_response getvolumeinfo_resp;

		struct mirror_pdu_find_streams_request findstreams_req;
		struct mirror_pdu_find_streams_response findstreams_resp;
	} u;
};


struct mirror_pdu* alloc_mirror_pdu(size_t length);
void free_mirror_pdu(struct mirror_pdu** pdu);

struct mirror_pdu* mirror_recv_pdu(struct transport_connection* conn);

#endif // mirror_proto_h__
