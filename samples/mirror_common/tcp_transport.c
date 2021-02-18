#include <winsock2.h>
#include <WS2tcpip.h>
#include <ws2def.h>
#include <assert.h>

#include "transport.h"
#include "trace.h"

#define TCP_CONNECTION_TYPE	':TCP'

struct tcp_connection
{
	struct transport_connection conn;

	TCHAR* host;
	TCHAR* service;
	SOCKET sock;
};


void free_tcp_connection(struct tcp_connection* tcpconn)
{
	if (tcpconn->sock != INVALID_SOCKET) {
		closesocket(tcpconn->sock);
	}

	free(tcpconn->service);
	free(tcpconn->host);
	free(tcpconn);
}

struct tcp_connection* alloc_tcp_connection(
	struct transport* tp,
	const TCHAR* host, const TCHAR* service
)
{
	struct tcp_connection* tcpconn = (struct tcp_connection*)malloc(sizeof(*tcpconn));
	if (!tcpconn) {
		return NULL;
	}

	bzero(tcpconn, sizeof(*tcpconn));

	tcpconn->conn.type = TCP_CONNECTION_TYPE;
	tcpconn->conn.transport = tp;

	tcpconn->sock = INVALID_SOCKET;
	if (host) {
		tcpconn->host = _tcsdup(host);
		if (!tcpconn->host)
			goto Cleanup;
	}

	if (service) {
		tcpconn->service = _tcsdup(service);
		if (!tcpconn->service)
			goto Cleanup;
	}

	return tcpconn;
	
Cleanup:
	free_tcp_connection(tcpconn);
	return NULL;
}


static int tcp_init(void)
{
	WSADATA wsaData;
	int ret;

	ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != 0) {
		pr_err(_T("WSAStartup() failed, ret(%d)\n"), ret);
		return -1;
	}

	return 0;
}

static int tcp_deinit(void)
{
	WSACleanup();
	return 0;
}


static struct transport_connection* tcp_create(
	struct transport* tp, TCHAR* url, int is_server
)
{
	struct tcp_connection* tcpconn;
	int ret;

	TCHAR* str = _tcsdup(url);
	TCHAR* p = _tcschr(str, _T(':'));
	if (p == NULL) {
		pr_err(_T("receive invalid url for tcp transport\n"));
		free(str);
		return NULL;
	}

	*p++ = _T('\0');

	tcpconn = alloc_tcp_connection(tp, str, p);
	if (!tcpconn) {
		pr_err(_T("allocate tcp connection failed\n"));
		return NULL;
	}

	tcpconn->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (tcpconn->sock == INVALID_SOCKET) {
		pr_err(_T("create socket failed, error(%d)\n"), WSAGetLastError());
		goto CLeanup;
	}

	if (is_server) {
		SOCKADDR_IN addr = { 0 };
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(_ttoi(tcpconn->service));
		
		ret = bind(tcpconn->sock, (struct sockaddr*)&addr, sizeof(addr));
		if (ret == SOCKET_ERROR)
			goto CLeanup;

		ret = listen(tcpconn->sock, SOMAXCONN);
		if (ret == SOCKET_ERROR)
			goto CLeanup;
	}

	return &tcpconn->conn;

CLeanup:
	free_tcp_connection(tcpconn);
	return NULL;
}


static void tcp_destroy(struct transport_connection* conn)
{
	struct tcp_connection* tcpconn;

	assert(conn->type == TCP_CONNECTION_TYPE);

	tcpconn = CONTAINING_RECORD(conn, struct tcp_connection, conn);
	free_tcp_connection(tcpconn);
}


static struct transport_connection* tcp_accept(
	struct transport_connection* conn
)
{
	struct tcp_connection* tcpconn;
	struct tcp_connection* newconn;
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	SOCKET connfd = INVALID_SOCKET;
	TCHAR host[NI_MAXHOST], port[NI_MAXSERV];
	int ret;

	assert(conn->type == TCP_CONNECTION_TYPE);

	tcpconn = CONTAINING_RECORD(conn, struct tcp_connection, conn);

	connfd = accept(tcpconn->sock, (struct sockaddr*)&ss, &len);
	if (connfd == INVALID_SOCKET) {
		pr_err(_T("accept failed, error(%d)\n"), WSAGetLastError());
		return NULL;
	}
	
#ifdef _UNICODE
	ret = GetNameInfoW((struct sockaddr*)&ss, len, host, ARRAYSIZE(host), 
		port, ARRAYSIZE(port), NI_NUMERICHOST | NI_NUMERICSERV);
#else 
	ret = getnameinfo((struct sockaddr*)&ss, len, host, sizeof(host),
		port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
#endif 
	if (ret != 0) {
		pr_err(_T("getnameinfo failed, error(%d)\n"), WSAGetLastError());
		return NULL;
	}

	newconn = alloc_tcp_connection(conn->transport, host, port);
	if (!newconn) {
		pr_err(_T("allocate tcp connection for client failed\n"));
		goto Cleanup;
	}

	_sntprintf(newconn->conn.name, ARRAYSIZE(newconn->conn.name), _T("%s:%s"),
		newconn->host, newconn->service);

	pr_info(_T("client %s connected\n"), newconn->conn.name);

	newconn->sock = connfd;
	return &newconn->conn;

Cleanup:
	if (connfd != INVALID_SOCKET)
		closesocket(connfd);

	if (newconn)
		free_tcp_connection(newconn);

	return NULL;
}

static int tcp_connect(struct transport_connection* conn)
{
	struct tcp_connection* tcpconn;
#ifdef _UNICODE
	ADDRINFOW hints, * res, * rp;
#else 
	struct addrinfo hints, * res, * rp;
#endif
	SOCKET sockfd = INVALID_SOCKET;
	int ret;

	assert(conn->type == TCP_CONNECTION_TYPE);

	tcpconn = CONTAINING_RECORD(conn, struct tcp_connection, conn);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	/* get all possible addresses */
#ifdef _UNICODE
	ret = GetAddrInfoW(tcpconn->host, tcpconn->service, &hints, &res);
#else 
	ret = getaddrinfo(tcpconn->host, tcpconn->service, &hints, &res);
#endif 
	if (ret < 0) {
		pr_err(_T("getaddrinfo failed, host(%s), service(%s), error(%d)\n"), 
			tcpconn->host, tcpconn->service, WSAGetLastError());
		return -1;
	}

	/* try the addresses */
	for (rp = res; rp; rp = rp->ai_next) {
		ret = connect(tcpconn->sock, rp->ai_addr, (int)rp->ai_addrlen);
		if (ret == 0)
			break;
	}

#ifdef _UNICODE
	FreeAddrInfoW(res);
#else
	freeaddrinfo(res);
#endif 

	if (ret == 0) {
		pr_info(_T("%s:%s connected\n"), tcpconn->host, tcpconn->service);
	}

	return ret;
}


static int tcp_recv(
	struct transport_connection* conn, 
	void* buffer, size_t buflen
)
{
	struct tcp_connection* tcpconn;
	int total = 0;
	uint8_t* p = (uint8_t*)buffer;

	assert(conn->type == TCP_CONNECTION_TYPE);

	tcpconn = CONTAINING_RECORD(conn, struct tcp_connection, conn);

	if (buflen == 0)
		return 0;

	do {
		int nbytes;

		nbytes = recv(tcpconn->sock, p, (int)buflen, 0);
		if (nbytes <= 0)
			return -1;

		p += nbytes;
		buflen -= nbytes;
		total += nbytes;

	} while (buflen > 0);

	return total;
}

static int tcp_send(
	struct transport_connection* conn,
	const void* buffer, size_t buflen
)
{
	const uint8_t* p = (const uint8_t*)buffer;
	struct tcp_connection* tcpconn;
	int total = 0;

	assert(conn->type == TCP_CONNECTION_TYPE);

	tcpconn = CONTAINING_RECORD(conn, struct tcp_connection, conn);

	if (buflen == 0)
		return 0;

	do {
		int nbytes;

		nbytes = send(tcpconn->sock, p, (int)buflen, 0);
		if (nbytes <= 0)
			return -1;

		p += nbytes;
		buflen -= nbytes;
		total += nbytes;

	} while (buflen > 0);

	return total;
}


struct transport tcp_transport =
{
	/*name*/		_T("tcp"),
	/*init*/		tcp_init,
	/*deinit*/		tcp_deinit,
	/*create*/		tcp_create,
	/*destroy*/		tcp_destroy,
	/*accept*/		tcp_accept,
	/*connect*/		tcp_connect,
	/*recv*/		tcp_recv,
	/*send*/		tcp_send,
};

