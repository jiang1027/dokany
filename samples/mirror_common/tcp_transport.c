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

	char* host;
	char* service;
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
	const char* host, const char* service
)
{
	struct tcp_connection* tcpconn = (struct tcp_connection*)malloc(sizeof(*tcpconn));
	if (!tcpconn) {
		return NULL;
	}

	bzero(tcpconn, sizeof(*tcpconn));

	tcpconn->conn.type = TCP_CONNECTION_TYPE;
	tcpconn->sock = INVALID_SOCKET;
	if (host) {
		tcpconn->host = _strdup(host);
		if (!tcpconn->host)
			goto Cleanup;
	}

	if (service) {
		tcpconn->service = _strdup(service);
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
		pr_err("WSAStartup() failed, ret(%d)\n", ret);
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
	struct transport* tp, char* url, int is_server
)
{
	struct tcp_connection* tcpconn;
	int ret;

	char* str = _strdup(url);
	char* p = strchr(str, ':');
	if (p == NULL) {
		pr_err("receive invalid url for tcp transport\n");
		free(str);
		return NULL;
	}

	*p++ = '\0';

	tcpconn = alloc_tcp_connection(tp, str, p);
	if (!tcpconn) {
		pr_err("allocate tcp connection failed\n");
		return NULL;
	}

	tcpconn->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (tcpconn->sock == INVALID_SOCKET) {
		pr_err("create socket failed, error(%d)\n", WSAGetLastError());
		goto CLeanup;
	}

	if (is_server) {
		SOCKADDR_IN addr = { 0 };
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(atoi(tcpconn->service));
		
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


static void tcp_destroy(struct transport* tp, struct transport_connection* conn)
{
	struct tcp_connection* tcpconn;
	UNREFERENCED_PARAMETER(tp);

	assert(conn->type == TCP_CONNECTION_TYPE);

	tcpconn = CONTAINING_RECORD(conn, struct tcp_connection, conn);
	free_tcp_connection(tcpconn);
}


static struct transport_connection* tcp_accept(
	struct transport* tp, 
	struct transport_connection* conn
)
{
	struct tcp_connection* tcpconn;
	struct tcp_connection* newconn;
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	SOCKET connfd = INVALID_SOCKET;
	char host[NI_MAXHOST], port[NI_MAXSERV];
	int ret;

	assert(conn->type == TCP_CONNECTION_TYPE);

	tcpconn = CONTAINING_RECORD(conn, struct tcp_connection, conn);

	connfd = accept(tcpconn->sock, (struct sockaddr*)&ss, &len);
	if (connfd == INVALID_SOCKET) {
		pr_err("accept failed, error(%d)\n", WSAGetLastError());
		return NULL;
	}
	
	ret = getnameinfo((struct sockaddr*)&ss, len, host, sizeof(host),
		port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret != 0) {
		pr_err("getnameinfo failed, error(%d)\n", WSAGetLastError());
		return NULL;
	}

	newconn = alloc_tcp_connection(tp, host, port);
	if (!newconn) {
		pr_err("allocate tcp connection for client failed\n");
		goto Cleanup;
	}

	pr_info("client %s:%s connected\n", newconn->host, newconn->service);

	newconn->sock = connfd;
	return &newconn->conn;

Cleanup:
	if (connfd != INVALID_SOCKET)
		closesocket(connfd);

	if (newconn)
		free_tcp_connection(newconn);

	return NULL;
}

static int tcp_connect(struct transport* tp, struct transport_connection* conn)
{
	struct tcp_connection* tcpconn;
	struct addrinfo hints, * res, * rp;
	SOCKET sockfd = INVALID_SOCKET;
	int ret;

	assert(conn->type == TCP_CONNECTION_TYPE);

	tcpconn = CONTAINING_RECORD(conn, struct tcp_connection, conn);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	/* get all possible addresses */
	ret = getaddrinfo(tcpconn->host, tcpconn->service, &hints, &res);
	if (ret < 0) {
		pr_err("getaddrinfo failed, host(%s), service(%s), error(%d)\n", 
			tcpconn->host, tcpconn->service, WSAGetLastError());
		return -1;
	}

	/* try the addresses */
	for (rp = res; rp; rp = rp->ai_next) {
		ret = connect(tcpconn->sock, rp->ai_addr, (int)rp->ai_addrlen);
		if (ret == 0)
			break;
	}

	freeaddrinfo(res);

	if (ret == 0) {
		pr_info("%s:%s connected\n", tcpconn->host, tcpconn->service);
	}

	return ret;
}


struct transport tcp_transport =
{
	/*name*/		"tcp",
	/*init*/		tcp_init,
	/*deinit*/		tcp_deinit,
	/*create*/		tcp_create,
	/*destroy*/		tcp_destroy,
	/*accept*/		tcp_accept,
	/*connect*/		tcp_connect,
};

