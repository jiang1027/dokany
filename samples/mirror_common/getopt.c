/*
Newsgroups: mod.std.unix
Subject: public domain AT&T getopt source
Date: 3 Nov 85 19:34:15 GMT

Here's something you've all been waiting for:  the AT&T public domain
source for getopt(3).  It is the code which was given out at the 1985
UNIFORUM conference in Dallas.  I obtained it by electronic mail
directly from AT&T.  The people there assure me that it is indeed
in the public domain.
*/

/*LINTLIBRARY*/

#include <stdio.h>
#include <string.h>
#include <io.h>

#include "getopt.h"

#define ERR(s, c)	if(opterr){\
	TCHAR errbuf[2];\
	errbuf[0] = (TCHAR)c; errbuf[1] = _T('\0'); \
	(void) _ftprintf(stderr, _T("%s %s %s\n"), argv[0], (s), errbuf);\
	}\

int	opterr = 1;
int	optind = 1;
int	optopt;
TCHAR* optarg;

int getopt(int argc, TCHAR* const * argv, const TCHAR* opts)
{
	static int sp = 1;
	int c;
	TCHAR* cp;

	if(sp == 1)
		if(optind >= argc ||
		   argv[optind][0] != _T('-') || argv[optind][1] == _T('\0'))
			return(EOF);
		else if(_tcscmp(argv[optind], _T("--")) == 0) {
			optind++;
			return(EOF);
		}
	optopt = c = argv[optind][sp];
	if(c == _T(':') || (cp=_tcschr(opts, c)) == NULL) {
		ERR(_T(": illegal option -- "), c);
		if(argv[optind][++sp] == _T('\0')) {
			optind++;
			sp = 1;
		}
		return _T('?');
	}
	if(*++cp == _T(':')) {
		if(argv[optind][sp+1] != _T('\0'))
			optarg = &argv[optind++][sp+1];
		else if(++optind >= argc) {
			ERR(_T(": option requires an argument -- "), c);
			sp = 1;
			return _T('?');
		} else
			optarg = argv[optind++];
		sp = 1;
	} else {
		if(argv[optind][++sp] == _T('\0')) {
			sp = 1;
			optind++;
		}
		optarg = NULL;
	}
	return c;
}
