#include "../../dokan/dokan.h"
#include "../../dokan/fileinfo.h"

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <winbase.h>

#include "trace.h"
#include "transport.h"

//#define WIN10_ENABLE_LONG_PATH
#ifdef WIN10_ENABLE_LONG_PATH
//dirty but should be enough
#define DOKAN_MAX_PATH 32768
#else
#define DOKAN_MAX_PATH MAX_PATH
#endif // DEBUG

static char TransportUrl[MAX_PATH] = { 0 };
static char RootDirectory[DOKAN_MAX_PATH] = { 0 };

void ShowUsage() 
{ 
	fprintf(stderr,
		"mirror_server.exe - Mirror a local device or folder to remove\n"
		"  /r RootDirectory (ex. /r c:\\test)\t\tDirectory source to mirror\n"
		"  /d (enable debug output)\t\t\t Enable debug output to an attached debugger.\n"
		"  /p Port (set listen port)\tSpecify TCP listen port\n"
		""
	); 
}

void mirror_server_loop(
	__inout      PTP_CALLBACK_INSTANCE Instance,
	__inout_opt  PVOID Context,
	__inout      PTP_WORK Work
)
{
	struct transport_connection* conn = (struct transport_connection*)Context;
	struct transport* tp = conn->transport;

	tp->destroy(tp, conn);
}


void mirror_server_mainloop(
	struct transport* tp, 
	struct transport_connection* conn
)
{
	struct transport_connection* newconn;
	PTP_WORK work;

	while (1) {
		newconn = tp->accept(tp, conn);
		if (newconn) {
			work = CreateThreadpoolWork(mirror_server_loop, newconn, NULL);
			if (!work) {
				pr_err("create server loop work failed, error(%d)\n",
					GetLastError());
				tp->destroy(tp, newconn);
			}
			else {
				SubmitThreadpoolWork(work);
			}
		}
	}
}


int main(int argc, char* argv[]) 
{
	int i;
	struct transport* tp;
	struct transport_connection* conn;

	for (i = 1; i < argc; ++i) {
		if (argv[i][0] != '-' &&
			argv[i][0] != '/') 
		{
			pr_err("unknown parameter %s\n", argv[i]);
			return -1;
		}

		switch (argv[i][1]) {
		case 'r':
			if (i >= argc - 1) {
				pr_err("Option '%s' is missing an argument\n", argv[i]);
				return -1;
			}

			i++;

			strncpy(RootDirectory, argv[i], ARRAYSIZE(RootDirectory));
			if (!strlen(RootDirectory)) {
				pr_err("Invalid RootDirectory\n");
				return EXIT_FAILURE;
			}

			pr_info("RootDirectory: %ls\n", RootDirectory);
			break;

		case 'd':
			trace_level++;
			break;

		case 'p':
			if (i >= argc - 1) {
				pr_err("Option '%s' is missing an argument\n", argv[i]);
				return -1;
			}

			i++;

			strncpy(TransportUrl, argv[i], ARRAYSIZE(TransportUrl));
			if (!strlen(TransportUrl)) {
				pr_err("Invalid TransportUrl\n");
				return EXIT_FAILURE;
			}

			pr_info("TransportUrl: %s\n", TransportUrl);

			break;

		default:
			pr_err("unknown parameter %s\n", argv[i]);
			return -1;
		}
	}

	if (strlen(RootDirectory) == 0 ||
		strlen(TransportUrl) == 0)
	{
		ShowUsage();
		return -1;
	}

	tp = GetTransport(TransportUrl);
	if (!tp) {
		return -1;
	}

	conn = tp->create(tp, TransportUrl, TRUE);
	if (!conn) {
		pr_err("create server connection failed\n");
	}
	else {
		mirror_server_mainloop(tp, conn);
		tp->destroy(tp, conn);
	}
	
	return 0; 
}
