/**
 * libusnmp
 * Author : Yannick Marquet
 * 2009
 * (Fraunhofer Institute for Open Communication Systems (FhG Fokus). based)
 */
#ifndef USNMP_H_
#define USNMP_H_

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <limits.h>
#include <errno.h>

#include <netinet/in.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <string.h>

#include "../contrib/asn1.h"
#include "../contrib/snmp.h"
#include <sys/queue.h>

#define USNMP_AUTO_REQID 0
#define USNMP_DEFAULT_VERSION USNMP_V2c
#define USNMP_DEFAULT_SERV_PORT 161
#define USNMP_RANDOM_PORT -1
#define USNMP_DEFAULT_TIMEOUT 5
#define USNMP_DEFAULT_READ_COMMUNITY   "public"
#define USNMP_DEFAULT_WRITE_COMMUNITY   "private"

enum usnmp_common_error{
	USNMP_NO_ERROR = 0,
	USNMP_MALLOC_FAIL = -90,
	USNMP_PTR_PDU_NULL =-91,
	USNMP_SOCK_INVALID =-92
};
#define USNMP_MAX_MSG_SIZE          1472 /* ethernet MTU minus IP/UDP header */

#define MAX_IPV4_LEN 16 /* 123.567.901.345\0*/
/* other value is not yet implement */

typedef struct in_addr ipv4_addr;

typedef struct usnmp_socket_st {
	int fd;
	struct sockaddr_in sa_in;
	struct timeval t_out; /* timeout went wait a sync packet */
	// TODO erreur
	pthread_mutex_t lockme;
	u_int32_t last_reqid;
} usnmp_socket_t;

typedef struct usnmp_pdu usnmp_pdu_t;

typedef void * usnmp_mib_t;

typedef struct usnmp_value usnmp_var_t;

typedef struct usnmp_list_var_st {
	struct usnmp_list_var_st * next;
	usnmp_var_t var;
} usnmp_list_var_t;

typedef enum usnmp_version usnmp_version_t;

typedef struct smmp_device_st {
	/* device id, using for generation of request_id */
	void * id;
	/* community for snmpv2 */
	char * public;
	char * private; /* not use a this moment */
	/* v4 information */
	ipv4_addr ipv4;
	int remote_port;
	/* ipv6 information (not yet implement ) */
/* ipv6_addr ipv6; */
} usnmp_device_t;

typedef struct asn_oid usnmp_oid_t;

typedef enum usnmp_syntax usnmp_type_t;

/* */
inline void usnmp_init();
inline void usnmp_init_usnmp_pdu(usnmp_pdu_t *pdu);
inline void usnmp_init_device(usnmp_device_t * device);
inline void usnmp_clean_pdu(usnmp_pdu_t *pdu);
inline void usnmp_clean_var(usnmp_var_t *var);
inline void usnmp_free_var_list(usnmp_list_var_t * list);

inline int usnmp_str2oid(const char * str_oid,usnmp_oid_t * out_oid,usnmp_mib_t *mib);

/* return a pdu structure, you can free after use (after send for exemple) */
inline usnmp_pdu_t * usnmp_create_pdu(int op,usnmp_version_t version);
/* return a device, you can free after use (after send for exemple) */
inline usnmp_device_t * usnmp_create_device();

inline usnmp_var_t * usnmp_create_var(usnmp_oid_t oid, usnmp_type_t type,void * value);
inline usnmp_var_t * usnmp_create_null_var(usnmp_oid_t oid);

/* add variable to pdu, you can free after add to pdu */
int usnmp_add_variable_to_pdu(usnmp_pdu_t * pdu, usnmp_var_t * var);
/* return a cpy of usnmp_list_var_t free this after use */
usnmp_list_var_t * usnmp_get_var_list_from_pdu(usnmp_pdu_t * pdu);
/* simple pdu send */
/* lock the socket before use usnmp_send_packet_pdu,usnmp_recv_packet_pdu if multithread
 * use the same usnmp_socket for sending and receiving */
/* simple pdu send, socket can't be null, dev too
 * if pdu.reqid equal to USNMP_AUTO_REQID and the send is successfull the pdu->reqid
 * is change to the true value of the reqid
 */
/* recv possible error, value is between 0 and -8*/
enum usnmp_async_send_err{
	USNMP_ASSEND_NO_ERROR = USNMP_NO_ERROR,
	USNMP_ASSEND_TIMEOUT = -1,
	USNMP_ASSEND_INT_SIGN = -2,
	USNMP_ASSEND_ERR = -3,
	USNMP_ASSEND_PDU_MALFORM =-5,
	USNMP_ASSEND_PDU_TOO_SHORT =-6,
	USNMP_ASSEND_PDU_TOO_LONG = -7,
	USNMP_ASSEND_PDU_UNK_VERS =-8,
	USNMP_ASSEND_MALLOC_FAIL = USNMP_MALLOC_FAIL,
	USNMP_ASSEND_PTR_PDU_NULL = USNMP_PTR_PDU_NULL,
	USNMP_ASSEND_SOCK_INVALID = USNMP_SOCK_INVALID
};
enum usnmp_async_send_err usnmp_send_pdu(usnmp_pdu_t *pdu, usnmp_socket_t *socket,
				usnmp_device_t dev);
/* recv possible error, value is 0, between 11 and -18*/
enum usnmp_async_recv_err{
	USNMP_ASRECV_NO_ERROR = USNMP_NO_ERROR,
	USNMP_ASRECV_TIMEOUT = -11,
	USNMP_ASRECV_INT_SIGN = -12,
	USNMP_ASRECV_ERR = -13,
	USNMP_ASRECV_PDU_MALFORM =-15,
	USNMP_ASRECV_PDU_TOO_SHORT =-16,
	USNMP_ASRECV_PDU_TOO_LONG = -17,
	USNMP_ASRECV_PDU_UNK_VERS =-18,
	USNMP_ASRECV_MALLOC_FAIL = USNMP_MALLOC_FAIL,
	USNMP_ASRECV_PTR_PDU_NULL = USNMP_PTR_PDU_NULL,
	USNMP_ASRECV_SOCK_INVALID = USNMP_SOCK_INVALID
};
/**
 * if timeout equal NULL, wait indefinitely
 * return USNMP_RECV_TIMEOUT if timeout
 * return USNMP_INT_SIGN signal recev during recving no packet recv.
 * return USNMP_RECV_ERR if an error when reading
 * return USNMP_RECV_PDU_MALFORM
 * return USNMP_RECV_PDU_TOO_SHORT if read a packet to short to be a valid pdu
 * return USNMP_RECV_PDU_TOO_LONG if read a packet to long to be a valid pdu
 * return USNMP_MALLOC_FAIL if cant alloc more memories
 * return USNMP_RECV_PDU_UNK_VERS read a packet with a unknow version
 * return USNMP_PTR_PDU_NULL if retpdu is null
 * return USNMP_SOCK_INVALID if psocket is null or invalid
 */
enum usnmp_async_recv_err usnmp_recv_pdu(usnmp_pdu_t ** retpdu, struct timeval * timeout,
		usnmp_socket_t *socket);
/* sync_send_err */
enum usnmp_sync_err{
	USNMP_SSEND_SRECV_NO_ERROR = USNMP_NO_ERROR,
	USNMP_SRECV_TIMEOUT = USNMP_ASRECV_TIMEOUT,
	USNMP_SRECV_INT_SIGN = USNMP_ASRECV_INT_SIGN,
	USNMP_SRECV_ERR = USNMP_ASRECV_ERR,
	USNMP_SRECV_PDU_MALFORM = USNMP_ASRECV_PDU_MALFORM,
	USNMP_SRECV_PDU_TOO_SHORT = USNMP_ASRECV_PDU_TOO_SHORT,
	USNMP_SRECV_PDU_TOO_LONG = USNMP_ASRECV_PDU_TOO_LONG,
	USNMP_SRECV_PDU_UNK_VERS = USNMP_ASRECV_PDU_UNK_VERS,

	USNMP_SMALLOC_FAIL = USNMP_MALLOC_FAIL,
	USNMP_SPTR_PDU_NULL = USNMP_PTR_PDU_NULL,
	USNMP_SSOCK_INVALID = USNMP_SOCK_INVALID
};
/* this function is thread safe.
 * Send and wait response, if socket is NULL, create a socket et close this after receiving response
 * warning do not use this function with a socket already use for asynchronous receive because they
 * cause lost packet for functions are using this socket.
 *
 * if the returned value is positive this is the request id of the pdu, else the value is
 * an error code value in usnmp_sync_send_err
 * return USNMP_SUCESS if success
 * error :
 * return USNMP_SOCK_NULL_ERR if psocket is null and unable to create a new socket
 * return USNMP_SSIGNAL if a signal break the select
 * return USNMP_SSOCK_BUSY if the socket is already use when you use param socket.
 * return USNMP_SSEND_* if error is send error.
 * return USNMP_SRECV_* if error is receive error
 * return USNMP_SSOCK_INVALID
 */
enum usnmp_sync_err usnmp_sync_send_pdu(usnmp_pdu_t pdu_send,
		usnmp_pdu_t ** pdu_recv, usnmp_socket_t *socket,struct timeval *timeout,
		usnmp_device_t dev);

/* return socket */
usnmp_socket_t *usnmp_create_and_open_socket(int port);

inline void usnmp_close_socket(usnmp_socket_t * socket);

/* display function */
void usnmp_fprintf_device_t(FILE* _stream, usnmp_device_t dev);
void usnmp_fprintf_pdu_t(FILE* _stream, usnmp_pdu_t pdu);
void usnmp_fprintf_binding(FILE* _stream,const usnmp_var_t *val);
void usnmp_fprintf_oid_t(FILE* _stream, usnmp_oid_t oid);

/* TODO error function */

/* TODO Advance function (snmpwalk, )*/

#endif

