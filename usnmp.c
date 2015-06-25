/*
 * ulibsnmp.c
 *
 *  Created on: 14 mai 2009
 *      Author: yannick
 */
#include "include/usnmp.h"

inline void usnmp_init() {
	srand(getpid());
}

inline void usnmp_init_device(usnmp_device_t * device) {
	memset(device, 0, sizeof(usnmp_device_t));
}

/* return a pdu structure, you can free after use (with usnmp_clean_pdu and free function)
 * after send for exemple */
inline usnmp_pdu_t * usnmp_create_pdu(int op, usnmp_version_t ver) {
	usnmp_pdu_t *pdu = (usnmp_pdu_t *) calloc(1, sizeof(usnmp_pdu_t));
	if (pdu == NULL) {
		return NULL;
	}
	return usnmp_init_pdu(pdu, op, ver);
}

/* initialise a  pdu structure point by pdu param
 * return the pdu structure initialise, or NULL if pdu param is set to NULL
 *  */
inline usnmp_pdu_t * usnmp_init_pdu(usnmp_pdu_t * pdu, int op, usnmp_version_t ver) {
	if (pdu == NULL) {
		return NULL;
	}
	pdu->type = op;
	pdu->version = ver;
	pdu->error_status = 0;
	pdu->error_index = 0;
	pdu->nbindings = 0;
	return pdu;
}

/* free all sub element of usnmp_pdu_t use with usnmp_*_pdu to change pdu.
 * Warning : this function should be used only if you don't change something yourself */
inline void usnmp_clean_pdu(usnmp_pdu_t *pdu) {
	u_int i;
	for (i = 0; i < pdu->nbindings; i++)
		usnmp_value_free(&pdu->bindings[i]);
	pdu->nbindings = 0;
	/* TODO clean other value */
}

inline void usnmp_clean_var(usnmp_var_t *var) {
	usnmp_value_free(var);
}
/**
 * create a variable, param value is a ptr to the value.
 * value special type :
 * 		ip : value is u_char[4] (ipv6 not supported)
 * 		oid : value is usnmp_oid_t
 *
 */
inline usnmp_var_t * usnmp_create_var(usnmp_oid_t oid, usnmp_type_t type,
		void * value) {
	usnmp_var_t * var = (usnmp_var_t *) calloc(1, sizeof(usnmp_var_t));
	var->var = oid;
	int i = 0;
	if (NULL != var) {
		var->syntax = type;
		switch (type) {
		case USNMP_SYNTAX_INTEGER:
			var->v.integer = *(int32_t*) value;
			break;
		case USNMP_SYNTAX_OCTETSTRING:
			var->v.octetstring.len = ((struct octetstring_st *) value)->len;
			/*fprintf(stdout, "OCTET STRING %ui:", var->v.octetstring.len);*/
			for (i = 0; i < var->v.octetstring.len; i++)
				/*fprintf(stdout, " %02x", var->v.octetstring.octets[i]); */
				var->v.octetstring.octets[i]
						= ((struct octetstring_st *) value)->octets[i];
			break;
		case USNMP_SYNTAX_OID:
			// TODO check
			/*fprintf(stdout, "OID %s", asn_oid2str_r(&var->v.oid, buf));*/
			var->v.oid.len = ((usnmp_oid_t *) value)->len;
			memcpy(var->v.oid.subs, ((usnmp_oid_t *) value)->subs,
					sizeof(asn_subid_t) * ASN_MAXOIDLEN);
			break;
		case USNMP_SYNTAX_IPADDRESS:
			// TODO check
			memcpy(var->v.ipaddress, value, sizeof(u_char) * 4);
			break;
		case USNMP_SYNTAX_COUNTER:
		case USNMP_SYNTAX_GAUGE:
		case USNMP_SYNTAX_TIMETICKS:
			var->v.uint32 = *(u_int32_t *) value;
			break;
		case USNMP_SYNTAX_COUNTER64:
			var->v.counter64 = *(u_int64_t*) value;
			break;
		case USNMP_SYNTAX_NULL:
		case USNMP_SYNTAX_NOSUCHOBJECT:
		case USNMP_SYNTAX_NOSUCHINSTANCE:
		case USNMP_SYNTAX_ENDOFMIBVIEW:
			break;
		default:
			fprintf(stderr, "UNKNOWN SYNTAX %u", var->syntax);
			free(var);
			var = NULL;
			break;
		}
	}
	return var;
}

inline usnmp_var_t * usnmp_create_null_var(usnmp_oid_t oid) {
	return usnmp_create_var(oid, USNMP_SYNTAX_NULL, NULL);
}

/* add variable to pdu, you can free usnmp_var_t after add to pdu,
 * return -1 if max binding is already reach */
int usnmp_add_variable_to_pdu(usnmp_pdu_t * pdu, usnmp_var_t * var) {
	int ret = pdu->nbindings;
	if (pdu->nbindings >= USNMP_MAX_BINDINGS) {
		/* TODO error */
		return (-1);
	}
	pdu->bindings[pdu->nbindings].var = var->var;
	pdu->bindings[pdu->nbindings].syntax = var->syntax;
	pdu->bindings[pdu->nbindings].v = var->v;
	pdu->nbindings++;
	return ret;
}
/* free and purge the list given by param */
inline void usnmp_free_var_list(usnmp_list_var_t * list) {
	usnmp_list_var_t * tmp;
	while (list != NULL) {
		tmp = list;
		list = list->next;
		usnmp_value_free(&tmp->var);
		free(tmp);
	}
}
/* return a usnmp_list_var_t free this after use */
usnmp_list_var_t * usnmp_get_var_list_from_pdu(usnmp_pdu_t * pdu) {
	usnmp_list_var_t *lvar = NULL;
	usnmp_list_var_t *cur = NULL;
	int i = 0;
	for (i = 0; i < pdu->nbindings; i++) {
		if (cur != NULL) {
			cur->next
					= (usnmp_list_var_t *) calloc(1, sizeof(usnmp_list_var_t));
			cur = cur->next;
		} else {
			cur = (usnmp_list_var_t *) calloc(1, sizeof(usnmp_list_var_t));
		}
		if (NULL == cur) {
			while (NULL != lvar) {
				cur = lvar;
				lvar = lvar->next;
				usnmp_value_free(&cur->var);
				free(cur);
			}
			lvar = NULL;
			break;
		}
		usnmp_value_copy(&cur->var, &pdu->bindings[i]);
		if (lvar == NULL) {
			lvar = cur;
		}
	}
	return lvar;
}

enum usnmp_sync_err usnmp_sync_send_pdu(usnmp_pdu_t pdu_send,
		usnmp_pdu_t ** pdu_recv, usnmp_socket_t *psocket,
		struct timeval *timeout, usnmp_device_t dev) {
	usnmp_socket_t *rsocket = NULL;
	int err = 0;
	if (NULL == psocket) {
		rsocket = usnmp_create_and_open_socket(USNMP_RANDOM_PORT);
	} else {
		rsocket = psocket;
	}
	if (NULL == timeout)
		timeout = &psocket->t_out;
	/* send packet */
	if (0 != (err = pthread_mutex_trylock(&rsocket->lockme))) {
		/* TODO error */
		fprintf(stderr, "socket is busy");
		return -1;
	}
	err = usnmp_send_pdu(&pdu_send, rsocket, dev);
	u_int32_t reqid = pdu_send.request_id;
	if (err != 0) {
		/* TODO error sending */
		pthread_mutex_unlock(&rsocket->lockme);
		return err; /* it's only an error */
	}
	/* waiting for a response drop all other packet */
	do {
		if (0 > (err = usnmp_recv_pdu(pdu_recv, timeout, rsocket))) {
			/* TODO error while recving */
			/* TODO define if timeout or other*/
			pthread_mutex_unlock(&rsocket->lockme);
			return err;
		}
	} while (reqid != (*pdu_recv)->request_id);
	pthread_mutex_unlock(&rsocket->lockme);
	if (NULL == psocket) {
		free(rsocket);
	}
	return EXIT_SUCCESS;
}

/* forge le packet */
inline int usnmp_build_packet(usnmp_pdu_t * pdu, u_char *sndbuf, size_t *sndlen) {
	struct asn_buf resp_b;

	resp_b.asn_ptr = sndbuf;
	resp_b.asn_len = USNMP_MAX_MSG_SIZE;

	if (usnmp_pdu_encode(pdu, &resp_b) != 0) {
		/* TODO gestion erreur */
		/*syslog(LOG_ERR, "cannot encode message");
		 abort();*/
		return -1;
	}
	*sndlen = (size_t) (resp_b.asn_ptr - sndbuf);
	return 0;
}

u_int32_t usnmp_next_reqid(usnmp_socket_t *sock) {
	return ++sock->last_reqid;
}

/*enum usnmp_async_send_err{
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
 };*/
// TODO memorisé le champs request_id du PDU pour le restoré apres envoi
enum usnmp_async_send_err usnmp_send_pdu(usnmp_pdu_t *pdu,
		usnmp_socket_t *psocket, usnmp_device_t dev) {
	/* snmp_output */
	int err = USNMP_ASSEND_NO_ERROR;
	if (pdu == NULL) {
		return USNMP_ASSEND_PTR_PDU_NULL;
	}
	if (psocket == NULL) {
		return USNMP_ASSEND_SOCK_INVALID;
	}
	u_int32_t reqid = usnmp_next_reqid(psocket);
	if (USNMP_AUTO_REQID == pdu->request_id) {
		pdu->request_id = reqid;
	}
	/* set the community */
	if (pdu->type != USNMP_PDU_SET) {
		if (dev.public == NULL) {
			strncpy(pdu->community, USNMP_DEFAULT_READ_COMMUNITY,
					sizeof(pdu->community));
		} else {
			strncpy(pdu->community, dev.public, sizeof(pdu->community));
		}
	} else {
		if (dev.public == NULL) {
			strncpy(pdu->community, USNMP_DEFAULT_WRITE_COMMUNITY,
					sizeof(pdu->community));
		} else {
			strncpy(pdu->community, dev.private, sizeof(pdu->community));
		}
	}
	u_char *sndbuf = malloc(USNMP_MAX_MSG_SIZE);
	size_t sndlen;
	ssize_t len;
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	if (dev.remote_port == 0) {
		addr.sin_port = htons(USNMP_DEFAULT_SERV_PORT);
	} else {
		addr.sin_port = htons(dev.remote_port);
	}
	addr.sin_addr = dev.ipv4;
	addr.sin_family = AF_INET;
	usnmp_build_packet(pdu, sndbuf, &sndlen);
	// TODO debug
	//usnmp_fprintf_pdu_t(stdout,*pdu);
	if ((len = sendto(psocket->fd, sndbuf, sndlen, 0,
			(struct sockaddr *) &addr, sizeof(struct sockaddr_in))) == -1) {
		/*syslog(LOG_ERR, "sendto: %m");*/
		err = USNMP_ASSEND_ERR;
		perror("sendto");
	} else if ((size_t) len != sndlen) {
		/*syslog(LOG_ERR, "sendto: short write %zu/%zu", sndlen, (size_t) len);*/
		err = USNMP_ASSEND_PDU_TOO_LONG;
		perror("sendto : short write ");
	}
	free(sndbuf);
	return err;
}

enum usnmp_async_recv_err usnmp_recv_pdu(usnmp_pdu_t ** retpdu,
		struct timeval * timeout, usnmp_socket_t *psocket) {
	u_char *resbuf = NULL;
	if (NULL == retpdu || NULL == psocket) {
		// TODO erro
		return USNMP_SOCK_INVALID;
	}
	ssize_t len;
	int32_t vi;
	fd_set rfds;
	int sret = 0;
	int err = 0;

	if (NULL != timeout) {
		struct timeval tv = *timeout;
		FD_ZERO(&rfds);
		FD_SET(psocket->fd, &rfds);
		sret = select(psocket->fd + 1, &rfds, NULL, NULL, &tv);
		if (-1 == sret) {
			perror("select()");
			if (errno == EINTR) {
				return USNMP_ASRECV_INT_SIGN;
			} else if (errno == EBADF) {
				return USNMP_SOCK_INVALID;
			}
			return USNMP_ASRECV_ERR;
		} else if (0 == sret) {
			/* FD_ISSET(socket+1, &rfds) est alors faux */
			return USNMP_ASRECV_TIMEOUT;
		}
	}

	if ((resbuf = malloc(USNMP_MAX_MSG_SIZE)) == NULL) {
		/* probleme d'allocation memoire */
		err = USNMP_MALLOC_FAIL;
	} else if ((len = recvfrom(psocket->fd, resbuf, USNMP_MAX_MSG_SIZE, 0,
			NULL, NULL)) == -1) {
		/* message de longueur null */
		perror("read error");
		err = USNMP_ASRECV_ERR;
	} else if ((size_t) len == USNMP_MAX_MSG_SIZE) {
		/* packet trop grand */
		err = USNMP_ASRECV_PDU_TOO_LONG;
	} else if (NULL
			== (*retpdu = (usnmp_pdu_t*) calloc(1, sizeof(usnmp_pdu_t)))) {
		/* plus de memoire */
		err = USNMP_MALLOC_FAIL;
	} else {
		/*
		 * Handle input
		 */
		struct asn_buf b;
		memset(&b, 0, sizeof(struct asn_buf));
		b.asn_ptr = resbuf;
		b.asn_len = len;
		enum usnmp_code code = usnmp_pdu_decode(&b, *retpdu, &vi);
		switch (code) {
		case USNMP_CODE_FAILED:
		case USNMP_CODE_BADVERS:
		case USNMP_CODE_BADLEN:
		case USNMP_CODE_OORANGE:
		case USNMP_CODE_BADENC:
			/* INPUT ERROR PACKET MALFORMED */
			err = USNMP_ASRECV_PDU_MALFORM;
			break;
		case USNMP_CODE_OK:
			switch ((*retpdu)->version) {
			case USNMP_V1:
			case USNMP_V2c:
				/* ok do nothing */
				break;
			case USNMP_Verr:
			default:
				/* unknown version*/
				err = USNMP_ASRECV_PDU_UNK_VERS;
				break;
			}
			break;
		}
		if (USNMP_ASRECV_NO_ERROR != err) {
			usnmp_clean_pdu(*retpdu);
			free(*retpdu);
			*retpdu = NULL;
		}
	}
	if (resbuf != NULL)
		free(resbuf);
	/**/
	return err;
}

/* return a malloc'd socket */
usnmp_socket_t * usnmp_create_and_open_socket(int port) {
	usnmp_socket_t * usnmp_socket = (usnmp_socket_t *) calloc(1,
			sizeof(usnmp_socket_t));
	usnmp_socket->last_reqid = 0;
	int pport = port;
	if (NULL == usnmp_socket) {
		perror("socket malloc fail !");
		return NULL;
	}
	pthread_mutex_init(&usnmp_socket->lockme, NULL);
	usnmp_socket->fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (usnmp_socket->fd < 0) {
		/* ERROR */
		perror("socket open error");
		free(usnmp_socket);
		usnmp_socket = NULL;
	} else {
		int i = 0;
		bool quit = false;
		while (!quit) {
			if (port < 0) {
				/* random port between 2000 and 65535 */
				int irand = rand();
				pport = (65535 - 2000) * (irand * 1.0 / RAND_MAX) + 2000;
			}
			usnmp_socket->sa_in.sin_family = AF_INET;
			usnmp_socket->sa_in.sin_port = htons(pport);
			usnmp_socket->sa_in.sin_addr.s_addr = htonl(INADDR_ANY);
			if (bind(usnmp_socket->fd,
					(const struct sockaddr *) &usnmp_socket->sa_in,
					sizeof(usnmp_socket->sa_in))) {
				if (i > 5) {
					perror("bind error !");
					close(usnmp_socket->fd);
					free(usnmp_socket);
					usnmp_socket = NULL;
					quit = true;
				}
				i++;
			} else {
				quit = true;
			}
		}
	}
	/* socket is open and ready listen sending */
	return usnmp_socket;
}

/* close the UDP socket */
void usnmp_close_socket(usnmp_socket_t * psocket) {
	pthread_mutex_trylock(&psocket->lockme);
	pthread_mutex_unlock(&psocket->lockme);
	//pthread_mutex_destroy(&psocket->lockme);
	close(psocket->fd);
}

/* display function */
void usnmp_fprintf_device_t(FILE* _stream, usnmp_device_t dev) {
	// char buf[MAX_IPV4_LEN];
	fprintf(_stream, "Device : \n");
	fprintf(_stream, "\tipv4:[%s] \n", inet_ntoa(dev.ipv4));
	//fprintf(_stream,"\tipv4:[%s] \n" ,inet_neta(dev.ipv4,buf,MAX_IPV4_LEN));
	if (dev.remote_port > 0) {
		fprintf(_stream, "\tport:[%i] \n", dev.remote_port);
	} else {
		fprintf(_stream, "\tport:[%i] \n", USNMP_DEFAULT_SERV_PORT);
	}
	if (NULL == dev.public) {
		fprintf(_stream, "\tRead Community :[%s]\n",
				USNMP_DEFAULT_READ_COMMUNITY);
	} else {
		fprintf(_stream, "\tRead Community :[%s]\n", dev.public);
	}
	if (NULL == dev.private) {
		fprintf(_stream, "\tWrite Community :[%s]\n",
				USNMP_DEFAULT_WRITE_COMMUNITY);
	} else {
		fprintf(_stream, "\tWrite Community :[%s]\n", dev.private);
	}
}
void usnmp_fprintf_pdu_t(FILE* _stream, usnmp_pdu_t pdu) {
	int i = 0;
	char buf[ASN_OIDSTRLEN];
	const char *vers;
	static const char *types[] = { /**/
	[USNMP_PDU_GET] = "GET",/**/
	[USNMP_PDU_GETNEXT] = "GETNEXT", /**/
	[USNMP_PDU_RESPONSE] = "RESPONSE",/**/
	[USNMP_PDU_SET] = "SET",/**/
	[USNMP_PDU_TRAP] = "TRAPv1",/**/
	[USNMP_PDU_GETBULK] = "GETBULK", [USNMP_PDU_INFORM] = "INFORM",/**/
	[USNMP_PDU_TRAP2] = "TRAPv2", /**/
	[USNMP_PDU_REPORT] = "REPORT", };/**/

	if (pdu.version == USNMP_V1)
		vers = "SNMPv1";
	else if (pdu.version == USNMP_V2c)
		vers = "SNMPv2c";
	else
		vers = "v?";

	switch (pdu.type) {
	case USNMP_PDU_TRAP:
		fprintf(_stream, "%s %s '%s'\n", types[pdu.type], vers, pdu.community);
		fprintf(_stream, " enterprise=%s\n",
				asn_oid2str_r(&pdu.enterprise, buf));
		fprintf(_stream, " agent_addr=%u.%u.%u.%u\n", pdu.agent_addr[0],
				pdu.agent_addr[1], pdu.agent_addr[2], pdu.agent_addr[3]);
		fprintf(_stream, " generic_trap=%d\n", pdu.generic_trap);
		fprintf(_stream, " specific_trap=%d\n", pdu.specific_trap);
		fprintf(_stream, " time-stamp=%u\n", pdu.time_stamp);
		for (i = 0; i < pdu.nbindings; i++) {
			fprintf(_stream, " [%u]: ", i);
			usnmp_fprintf_binding(_stream, &pdu.bindings[i]);
			fprintf(_stream, "\n");
		}
		break;

	case USNMP_PDU_GET:
	case USNMP_PDU_GETNEXT:
	case USNMP_PDU_RESPONSE:
	case USNMP_PDU_SET:
	case USNMP_PDU_GETBULK:
	case USNMP_PDU_INFORM:
	case USNMP_PDU_TRAP2:
	case USNMP_PDU_REPORT:
		fprintf(_stream, "%s %s '%s'", types[pdu.type], vers, pdu.community);
		fprintf(_stream, " request_id=%d\n", pdu.request_id);
		fprintf(_stream, " error_status=%d\n", pdu.error_status);
		fprintf(_stream, " error_index=%d\n", pdu.error_index);
		for (i = 0; i < pdu.nbindings; i++) {
			fprintf(_stream, " [%u]: ", i);
			usnmp_fprintf_binding(_stream, &pdu.bindings[i]);
			fprintf(_stream, "\n");
		}
		break;

	default:
		fprintf(_stream, "bad pdu type %u\n", pdu.type);
		break;
	}
}
/* only numeric oid type if mib == NULL
 * at the moment mib is always null
 * return 0 value if no error, if parse error, index of the last parse char, other error <0, */
inline int usnmp_str2oid(const char * int_str_oid, usnmp_oid_t * out_oid,
		usnmp_mib_t * mib) {
	/* split this string to number*/
	memset(out_oid, 0, sizeof(out_oid));
	char * cp = NULL;
	char * tok = NULL;
	char * endptr = NULL;
	char * bkptr = NULL;
	u_long val;
	if (int_str_oid == NULL || out_oid == NULL) {
		/* TODO error param */
		return -1;
	}
	if (mib != NULL) {
		/* not implement a the moment */
		return -1;
	} else {
		cp = strdup(int_str_oid);
		if (NULL == cp) {
			/* TODO error */
			return -1;
		}
		errno=0; // strtok don't reset to zero errno if no error
		tok = strtok_r(cp, ".", &bkptr);
		while (NULL != tok) {
			if (out_oid->len >= ASN_MAXOIDLEN) {
				/* TODO error (OID too long) */
				return -1;
			}
			val = strtoul(tok, &endptr, 10);
			if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
					|| (errno != 0 && val == 0)) {
				/* TODO error (value of index too big)*/
				perror("strtol");
				return 1;
			}

			if (endptr == tok || *endptr != '\0') {
				/* TODO not a number */
				return 1;
			}

			out_oid->subs[out_oid->len] = val;
			out_oid->len++;
			errno=0;// strtok don't reset to zero errno if no error
			tok = strtok_r(NULL, ".", &bkptr);
		}
		free(cp);
	}
	return 0;
}

void usnmp_fprintf_binding(FILE* _stream, const usnmp_var_t *val) {
	u_int i;
	char buf[ASN_OIDSTRLEN];

	fprintf(_stream, "%s=", asn_oid2str_r(&val->var, buf));
	switch (val->syntax) {

	case USNMP_SYNTAX_NULL:
		fprintf(_stream, "NULL");
		break;

	case USNMP_SYNTAX_INTEGER:
		fprintf(_stream, "INTEGER %"PRId32, val->v.integer);
		break;

	case USNMP_SYNTAX_OCTETSTRING:
		fprintf(_stream, "OCTET STRING %ui:", val->v.octetstring.len);
		for (i = 0; i < val->v.octetstring.len; i++) {
			fprintf(_stream, " %02x", val->v.octetstring.octets[i]);
		}
		fprintf(_stream, " =[");
		for (i = 0; i < val->v.octetstring.len; i++) {
			fprintf(_stream, "%c", val->v.octetstring.octets[i]);
		}
		fprintf(_stream, "]");
		break;

	case USNMP_SYNTAX_OID:
		fprintf(_stream, "OID %s", asn_oid2str_r(&val->v.oid, buf));
		break;

	case USNMP_SYNTAX_IPADDRESS:
		fprintf(_stream, "IPADDRESS %u.%u.%u.%u", val->v.ipaddress[0],
				val->v.ipaddress[1], val->v.ipaddress[2], val->v.ipaddress[3]);
		break;

	case USNMP_SYNTAX_COUNTER:
		fprintf(_stream, "COUNTER %"PRIu32, val->v.uint32);
		break;

	case USNMP_SYNTAX_GAUGE:
		fprintf(_stream, "GAUGE %"PRIu32, val->v.uint32);
		break;

	case USNMP_SYNTAX_TIMETICKS:
		fprintf(_stream, "TIMETICKS %"PRIu32, val->v.uint32);
		break;

	case USNMP_SYNTAX_COUNTER64:
		fprintf(_stream, "COUNTER64 %"PRIu64, val->v.counter64);
		break;

	case USNMP_SYNTAX_NOSUCHOBJECT:
		fprintf(_stream, "NoSuchObject");
		break;

	case USNMP_SYNTAX_NOSUCHINSTANCE:
		fprintf(_stream, "NoSuchInstance");
		break;

	case USNMP_SYNTAX_ENDOFMIBVIEW:
		fprintf(_stream, "EndOfMibView");
		break;

	default:
		fprintf(_stream, "UNKNOWN SYNTAX %u", val->syntax);
		break;
	}
	fflush(_stream);
}

void usnmp_fprintf_oid_t(FILE* _stream, usnmp_oid_t oid) {
	fprintf(_stream, "%s", asn_oid2str(&oid));
}

const char * usnmp_strerror(int code) {
	const char * ret;
	switch (code) {
	case USNMP_NO_ERROR:
		ret = "no error";
		break;
	case USNMP_MALLOC_FAIL:
		ret = "can't alloc more ressources";
		break;
	/* asrecv assend */
	case USNMP_ASSEND_INT_SIGN:
	case USNMP_ASRECV_INT_SIGN:
		ret = "recv catch a int signal";
		break;
	case USNMP_ASSEND_PDU_MALFORM:
	case USNMP_ASRECV_PDU_MALFORM:
		ret = "pdu malformed";
		break;
	case USNMP_ASSEND_PDU_TOO_LONG:
	case USNMP_ASRECV_PDU_TOO_LONG:
		ret = "pdu too long";
		break;
	case USNMP_ASSEND_PDU_TOO_SHORT:
	case USNMP_ASRECV_PDU_TOO_SHORT:
		ret = "pdu too short";
		break;
	case USNMP_ASSEND_PDU_UNK_VERS:
	case USNMP_ASRECV_PDU_UNK_VERS:
		ret = "pdu unknow pdu version";
		break;
	case USNMP_PTR_PDU_NULL:
		ret = "ptr too pdu is null";
		break;
	case USNMP_SOCK_INVALID:
		ret = "invalid socket";
		break;
	case USNMP_ASRECV_TIMEOUT:
		ret = "time out";
		break;
	/* unknown error */
	case USNMP_ASRECV_ERR:
	case USNMP_ASSEND_ERR:
	default:
		ret = "unknown error";
		break;
	}
	return ret;
}

