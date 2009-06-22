/*
 * Copyright (c) 2001-2003
 *	Fraunhofer Institute for Open Communication Systems (FhG Fokus).
 *	All rights reserved.
 *
 * Author: Harti Brandt <harti@freebsd.org>
 *
 * Redistribution of this software and documentation and use in source and
 * binary forms, with or without modification, are permitted provided that
 * the following conditions are met:
 *
 * 1. Redistributions of source code or documentation must retain the above
 *    copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE AND DOCUMENTATION IS PROVIDED BY FRAUNHOFER FOKUS
 * AND ITS CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * FRAUNHOFER FOKUS OR ITS CONTRIBUTORS  BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Header file for SNMP functions.
 *
 * $YMarquet : libusnmp/contrib/snmp.c 2009/05
 *
 * diff : 	- Useless function for libusnmp delete :
 *				- dump_ (suppress replace by usnmp_fprintf_function)
 *				- snmp_error_func, snmp_printf_func
 *			- replace snmp_* by usnmp_*
 *			- replace snmp_error( by ftprintf(sterr,
 *
 * $
 * SNMP
 */
#ifndef snmp_h_
#define snmp_h_

#include <sys/types.h>

#define USNMP_COMMUNITY_MAXLEN	128
#define USNMP_MAX_BINDINGS	100

enum usnmp_syntax {
	USNMP_SYNTAX_NULL	= 0,
	USNMP_SYNTAX_INTEGER,		/* == INTEGER32 */
	USNMP_SYNTAX_OCTETSTRING,
	USNMP_SYNTAX_OID,
	USNMP_SYNTAX_IPADDRESS,
	USNMP_SYNTAX_COUNTER,
	USNMP_SYNTAX_GAUGE,		/* == UNSIGNED32 */
	USNMP_SYNTAX_TIMETICKS,

	/* v2 additions */
	USNMP_SYNTAX_COUNTER64,
	USNMP_SYNTAX_NOSUCHOBJECT,	/* exception */
	USNMP_SYNTAX_NOSUCHINSTANCE,	/* exception */
	USNMP_SYNTAX_ENDOFMIBVIEW,	/* exception */
};

/* add by YMarquet 2009/05 */
struct octetstring_st{
		    u_int		len;
		    u_char		*octets;
};


struct usnmp_value {
	struct asn_oid		var;
	enum usnmp_syntax	syntax;
	union usnmp_values {
	  int32_t		integer;	/* also integer32 */
	  struct octetstring_st	octetstring;
	  struct asn_oid	oid;
	  u_char		ipaddress[4];
	  u_int32_t		uint32;		/* also gauge32, counter32,
						   unsigned32, timeticks */
	  u_int64_t		counter64;
	}			v;
};

enum usnmp_version {
	USNMP_Verr = 0,
	USNMP_V1 = 1,
	USNMP_V2c,
};

struct usnmp_pdu {
	char		community[USNMP_COMMUNITY_MAXLEN + 1];
	enum usnmp_version version;
	u_int		type;

	/* trap only */
	struct asn_oid	enterprise;
	u_char		agent_addr[4];
	int32_t		generic_trap;
	int32_t		specific_trap;
	u_int32_t	time_stamp;

	/* others */
	int32_t		request_id;
	int32_t		error_status;
	int32_t		error_index;

	/* fixes for encoding */
	u_char		*outer_ptr;
	u_char		*pdu_ptr;
	u_char		*vars_ptr;

	struct usnmp_value bindings[USNMP_MAX_BINDINGS];
	u_int		nbindings;
};
#define usnmp_v1_pdu usnmp_pdu

#define USNMP_PDU_GET		0
#define USNMP_PDU_GETNEXT	1
#define USNMP_PDU_RESPONSE	2
#define USNMP_PDU_SET		3
#define USNMP_PDU_TRAP		4	/* v1 */
#define USNMP_PDU_GETBULK	5	/* v2 */
#define USNMP_PDU_INFORM		6	/* v2 */
#define USNMP_PDU_TRAP2		7	/* v2 */
#define USNMP_PDU_REPORT		8	/* v2 */

#define USNMP_ERR_NOERROR	0
#define USNMP_ERR_TOOBIG		1
#define USNMP_ERR_NOSUCHNAME	2	/* v1 */
#define USNMP_ERR_BADVALUE	3	/* v1 */
#define USNMP_ERR_READONLY	4	/* v1 */
#define USNMP_ERR_GENERR		5
#define USNMP_ERR_NO_ACCESS	6	/* v2 */
#define USNMP_ERR_WRONG_TYPE	7	/* v2 */
#define USNMP_ERR_WRONG_LENGTH	8	/* v2 */
#define USNMP_ERR_WRONG_ENCODING	9	/* v2 */
#define USNMP_ERR_WRONG_VALUE	10	/* v2 */
#define USNMP_ERR_NO_CREATION	11	/* v2 */
#define USNMP_ERR_INCONS_VALUE	12	/* v2 */
#define USNMP_ERR_RES_UNAVAIL	13	/* v2 */
#define USNMP_ERR_COMMIT_FAILED	14	/* v2 */
#define USNMP_ERR_UNDO_FAILED	15	/* v2 */
#define USNMP_ERR_AUTH_ERR	16	/* v2 */
#define USNMP_ERR_NOT_WRITEABLE	17	/* v2 */
#define USNMP_ERR_INCONS_NAME	18	/* v2 */

#define USNMP_TRAP_COLDSTART	0
#define USNMP_TRAP_WARMSTART	1
#define USNMP_TRAP_LINKDOWN	2
#define USNMP_TRAP_LINKUP	3
#define USNMP_TRAP_AUTHENTICATION_FAILURE	4
#define USNMP_TRAP_EGP_NEIGHBOR_LOSS	5
#define USNMP_TRAP_ENTERPRISE	6

enum usnmp_code {
	USNMP_CODE_OK = 0,
	USNMP_CODE_FAILED,
	USNMP_CODE_BADVERS,
	USNMP_CODE_BADLEN,
	USNMP_CODE_BADENC,
	USNMP_CODE_OORANGE,
};

void usnmp_value_free(struct usnmp_value *);
int usnmp_value_parse(const char *, enum usnmp_syntax, union usnmp_values *);
int usnmp_value_copy(struct usnmp_value *, const struct usnmp_value *);

void usnmp_pdu_free(struct usnmp_pdu *);
enum usnmp_code usnmp_pdu_decode(struct asn_buf *b, struct usnmp_pdu *pdu, int32_t *);
enum usnmp_code usnmp_pdu_encode(struct usnmp_pdu *pdu, struct asn_buf *resp_b);

#define TRUTH_MK(F) ((F) ? 1 : 2)
#define TRUTH_GET(T) (((T) == 1) ? 1 : 0)
#define TRUTH_OK(T)  ((T) == 1 || (T) == 2)

#endif
