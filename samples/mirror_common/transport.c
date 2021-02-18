#include "transport.h"
#include "trace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern struct transport tcp_transport;


struct transport* GetTransport(TCHAR* url)
{
	struct transport* tp = NULL;
	int ret;
	size_t len;

	if (_tcsncmp(url, _T("tcp://"), 6) == 0) {
		tp = &tcp_transport;
		len = _tcslen(url);
		memmove(url, &url[6], (len - 6) * sizeof(TCHAR));
		url[len - 6] = _T('\0');
	}

	if (!tp) {
		pr_err(_T("can't find transport for url %s\n"), url);
		return NULL;
	}

	ret = tp->init();
	if (ret < 0) {
		pr_err(_T("transport(%s) init failed, ret(%d)\n"), tp->name, ret);
		return NULL;
	}

	pr_info(_T("transport(%s) inited\n"), tp->name);

	return tp;
}
