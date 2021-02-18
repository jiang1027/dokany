#ifndef transport_h__
#define transport_h__

#include <stdio.h>
#include <stdint.h>
#include <tchar.h>

struct transport;

#define TRANSPORT_CONNECTION_NAME_LENGTH	50

struct transport_connection
{
	int type;
	struct transport* transport;
	TCHAR name[TRANSPORT_CONNECTION_NAME_LENGTH];
};

struct transport
{
	const TCHAR* name;

	int (*init)(void);
	int (*deinit)(void);

	struct transport_connection* (*create)(struct transport* tp, TCHAR* url, int is_server);
	void (*destroy)(struct transport_connection* conn);

	struct transport_connection* (*accept)(struct transport_connection* conn);
	int (*connect)(struct transport_connection* conn);

	int (*recv)(struct transport_connection* conn, void* buffer, size_t buflen);
	int (*send)(struct transport_connection* conn, const void* buffer, size_t buflen);
};

struct transport* GetTransport(TCHAR* url);


#endif // transport_h__
