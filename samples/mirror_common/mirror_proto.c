#include "mirror_proto.h"
#include "trace.h"

struct mirror_pdu* alloc_mirror_pdu(size_t length)
{
	struct mirror_pdu* pdu = (struct mirror_pdu*)malloc(length);
	if (!pdu) {
		pr_err(_T("allocate pdu failed, length(%d)\n"), (int)length);
		return NULL;
	}

	bzero(pdu, length);

	pdu->length = (uint32_t)length;
	return pdu;
}

void free_mirror_pdu(struct mirror_pdu** pdu)
{
	if (*pdu) {
		free(*pdu);
		*pdu = NULL;
	}
}


struct mirror_pdu* mirror_recv_pdu(struct transport_connection* conn)
{
	struct transport* tp = conn->transport;
	struct mirror_pdu* pdu;
	uint32_t length = 0;
	int ret;

	ret = tp->recv(conn, &length, sizeof(length));
	if (ret == 0) {
		pr_info(_T("%s disconnected\n"), conn->name);
		return NULL;
	}

	if (ret < 0) {
		pr_err(_T("transport(%s) %s receive pdu length failed\n"), 
			tp->name, conn->name);
		return NULL;
	}
	
	pr_info(_T("receive pdu length: %d\n"), length);

	if (length < sizeof(*pdu)) {
		pr_err(_T("receive invalid pdu length(%d), expected(%d)\n"), length, sizeof(*pdu));
		return NULL;
	}

	pdu = alloc_mirror_pdu(length);
	if (!pdu)
		return NULL;

	pr_info(_T("receiving trailing %d bytes ...\n"), length - sizeof(uint32_t));

	ret = tp->recv(conn, ((uint8_t*)pdu) + sizeof(uint32_t), length - sizeof(uint32_t));
	if (ret < 0) {
		pr_err(_T("transport(%s) receive pdu failed, length(%d)\n"), tp->name, length);
		free_mirror_pdu(&pdu);
		return NULL;
	}

	pr_info(_T("received\n"));

	return pdu;
}

