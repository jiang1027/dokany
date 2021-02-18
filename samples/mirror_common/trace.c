#include "trace.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

int trace_level = LOG_LEVEL_ERROR;
int trace_dump_level = LOG_LEVEL_INFO;

void trace(int level, const TCHAR* fmt, ...)
{
	static ULONGLONG  startTick = 0;

	va_list argptr;
	TCHAR timestr[20];
	TCHAR buf[256];
	DWORD delta;

	if (startTick == 0) {
		startTick = GetTickCount64();
	}

	if (level > trace_level)
		return;

	delta = (DWORD)(GetTickCount64() - startTick);

	_sntprintf(timestr, ARRAYSIZE(timestr), _T("+%03d.%03d"), delta / 1000, delta % 1000);

	va_start(argptr, fmt);
	_vsntprintf(buf, ARRAYSIZE(buf), fmt, argptr);
	_tprintf(_T("%s %s"), timestr, buf);
	OutputDebugString(buf);
	va_end(argptr);
}


void trace_dump(void* buf, int buflen, const TCHAR* prefix)
{
#define LINELEN  16
	static TCHAR HEX[] = _T("0123456789ABCDEF");
	uint8_t* p = (uint8_t*)buf;
	int i;
	TCHAR str[LINELEN * 4 + 1] = { 0 };

	trace(trace_dump_level, _T("%s (length = %d):\n"), prefix, buflen);

	for (i = 0; i < buflen; ++i) {
		if ((i % LINELEN) == 0) {
			if (i > 0) {
				trace(trace_dump_level, _T("%s\n"), str);
			}
			str[0] = 0;
		}

		str[(i % LINELEN) * 3 + 0] = HEX[p[i] >> 4];
		str[(i % LINELEN) * 3 + 1] = HEX[p[i] & 0x0F];
		str[(i % LINELEN) * 3 + 2] = _T(' ');
		str[(i % LINELEN) * 3 + 3] = 0;
	}

	if (str[0] != 0) {
		trace(trace_dump_level, _T("%s\n"), str);
	}
}
