#include "transport.h"
#include "trace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern struct transport tcp_transport;


struct transport* GetTransport(char* url)
{
	struct transport* tp = NULL;
	int ret;
	size_t len;

	if (strncmp(url, "tcp://", 6) == 0) {
		tp = &tcp_transport;
		len = strlen(url);
		memmove(url, &url[6], len - 6);
	}

	if (!tp) {
		pr_err("can't find transport for url %s\n", url);
		return NULL;
	}

	ret = tp->init();
	if (ret < 0) {
		pr_err("transport(%s) init failed, ret(%d)\n", tp->name, ret);
		return NULL;
	}

	pr_info("transport(%s) inited\n", tp->name);

	return tp;
}
