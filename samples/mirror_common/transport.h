#ifndef transport_h__
#define transport_h__

#include <stdio.h>

struct transport;

struct transport_connection
{
	int type;
	struct transport* transport;
};

struct transport
{
	const char* name;

	int (*init)(void);
	int (*deinit)(void);

	struct transport_connection* (*create)(struct transport* tp, char* url, int is_server);
	void (*destroy)(struct transport* tp, struct transport_connection* conn);

	struct transport_connection* (*accept)(struct transport* tp, struct transport_connection* conn);
	int (*connect)(struct transport* tp, struct transport_connection* conn);
};

struct transport* GetTransport(char* url);


#endif // transport_h__
