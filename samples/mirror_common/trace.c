#include "trace.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

int trace_level = LOG_LEVEL_ERROR;
int trace_dump_level = LOG_LEVEL_INFO;

void trace(int level, const char* fmt, ...)
{
	static DWORD startTick = 0;

	va_list argptr;
	char timestr[20];
	char buf[256];
	DWORD delta;

	if (startTick == 0) {
		startTick = GetTickCount();
	}

	if (level > trace_level)
		return;

	delta = GetTickCount() - startTick;

	_snprintf(timestr, ARRAYSIZE(timestr), "+%03d.%03d", delta / 1000, delta % 1000);

	va_start(argptr, fmt);
	_vsnprintf(buf, ARRAYSIZE(buf), fmt, argptr);
	printf("%s %s", timestr, buf);
	OutputDebugStringA(buf);
	va_end(argptr);
}


void trace_dump(void* buf, int buflen, const char* prefix)
{
#define LINELEN  16
	static char HEX[] = "0123456789ABCDEF";
	uint8_t* p = (uint8_t*)buf;
	int i;
	char str[LINELEN * 4 + 1] = { 0 };

	trace(trace_dump_level, "%s (length = %d):\n", prefix, buflen);

	for (i = 0; i < buflen; ++i) {
		if ((i % LINELEN) == 0) {
			if (i > 0) {
				trace(trace_dump_level, "%s\n", str);
			}
			str[0] = 0;
		}

		str[(i % LINELEN) * 3 + 0] = HEX[p[i] >> 4];
		str[(i % LINELEN) * 3 + 1] = HEX[p[i] & 0x0F];
		str[(i % LINELEN) * 3 + 2] = ' ';
		str[(i % LINELEN) * 3 + 3] = 0;
	}

	if (str[0] != 0) {
		trace(trace_dump_level, "%s\n", str);
	}
}
