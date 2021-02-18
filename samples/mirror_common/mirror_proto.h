#ifndef mirror_proto_h__
#define mirror_proto_h__

#include <stdint.h>

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

enum {
	MIRROR_PDU_STANDARD_REQUEST = 0,
	MIRROR_PDU_STANDARD_RESPONSE = 0,
	MIRROR_PDU_FIND_FILES_REQUEST,
	MIRROR_PDU_FIND_FILES_RESPONSE,
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
	} u;
};


struct mirror_pdu* alloc_mirror_pdu(size_t length);
void free_mirror_pdu(struct mirror_pdu** pdu);

struct mirror_pdu* mirror_recv_pdu(struct transport_connection* conn);

#endif // mirror_proto_h__
