/**
 * libusnmp
 * Author : Yannick Marquet
 * 2009
 * (Fraunhofer Institute for Open Communication Systems (FhG Fokus). based)
 */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>

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
} usnmp_socket_t;

typedef//struct usnmp_pdu_st {
//	long version;
//	int command; /* Type of this PDU (see SNMP_PDU_*) */
//	ipv4_addr address; /* Address of peer */
//
//	/* snmpv1 & snmpv2 field */
//	u_char * community;
//	size_t community_len;
//
//	int reqid; /* Integer32: Request id */
//	int errstat; /* INTEGER:   Error status */
//	int errindex; /* INTEGER:   Error index */
//
//	struct usnmp_variable_list_st *variables; /* Variable Bindings */
//}
struct usnmp_pdu usnmp_pdu_t;

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
u_int32_t usnmp_send_pdu(usnmp_pdu_t *pdu, usnmp_socket_t *socket,
				usnmp_device_t dev);
/* if timeout equal NULL, wait indefinitely */
int usnmp_recv_pdu(usnmp_pdu_t ** retpdu, struct timeval * timeout,
		usnmp_socket_t *socket);

/* send and wait response, if socket is NULL, create a socket et close this after receiving response
 * warning do not use this function with a socket already use for asynchronous send */
int usnmp_sync_send_pdu(usnmp_pdu_t pdu_send,
		usnmp_pdu_t ** pdu_recv, usnmp_socket_t *socket,struct timeval *timeout,
		usnmp_device_t dev);

/* return socket */
usnmp_socket_t *usnmp_create_and_open_socket(int port, struct timeval * tout);

inline void usnmp_close_socket(usnmp_socket_t * socket);

/* display function */
void usnmp_fprintf_device_t(FILE* _stream, usnmp_device_t dev);
void usnmp_fprintf_pdu_t(FILE* _stream, usnmp_pdu_t pdu);
void usnmp_fprintf_binding(FILE* _stream, const struct usnmp_value *b);
void usnmp_fprintf_smmp_oid_t(FILE* _stream, usnmp_oid_t oid);

/* TODO error function */

/* TODO Advance function (snmpwalk, )*/
