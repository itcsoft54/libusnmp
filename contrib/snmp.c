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
 * $YMarquet : libusnmp/contrib/snmp.c 2009/05
 *
 * diff : 	- Useless function for libusnmp delete :
 *				- dump_ (suppress remplace by usnmp_fprintf_function)
 *				- snmp_error_func, snmp_printf_func
 *			- remplace snmp_* by usnmp_*
 *			- remplace snmp_error( by ftprintf(sterr,
 *
 * $
 * SNMP
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>

#include "asn1.h"
#include "snmp.h"
#include "snmppriv.h"

/*
 * Get the next variable binding from the list.
 * ASN errors on the sequence or the OID are always fatal.
 */
static enum asn_err
get_var_binding(struct asn_buf *b, struct usnmp_value *binding)
{
	u_char type;
	asn_len_t len, trailer;
	enum asn_err err;

	if (asn_get_sequence(b, &len) != ASN_ERR_OK) {
		fprintf(stderr,"cannot parse varbind header");
		return (ASN_ERR_FAILED);
	}

	/* temporary truncate the length so that the parser does not
	 * eat up bytes behind the sequence in the case the encoding is
	 * wrong of inner elements. */
	trailer = b->asn_len - len;
	b->asn_len = len;

	if (asn_get_objid(b, &binding->var) != ASN_ERR_OK) {
		fprintf(stderr,"cannot parse binding objid");
		return (ASN_ERR_FAILED);
	}
	if (asn_get_header(b, &type, &len) != ASN_ERR_OK) {
		fprintf(stderr,"cannot parse binding value header");
		return (ASN_ERR_FAILED);
	}

	switch (type) {

	  case ASN_TYPE_NULL:
		binding->syntax = USNMP_SYNTAX_NULL;
		err = asn_get_null_raw(b, len);
		break;

	  case ASN_TYPE_INTEGER:
		binding->syntax = USNMP_SYNTAX_INTEGER;
		err = asn_get_integer_raw(b, len, &binding->v.integer);
		break;

	  case ASN_TYPE_OCTETSTRING:
		binding->syntax = USNMP_SYNTAX_OCTETSTRING;
		binding->v.octetstring.octets = malloc(len);
		if (binding->v.octetstring.octets == NULL) {
			fprintf(stderr,"%s", strerror(errno));
			return (ASN_ERR_FAILED);
		}
		binding->v.octetstring.len = len;
		err = asn_get_octetstring_raw(b, len,
		    binding->v.octetstring.octets,
		    &binding->v.octetstring.len);
		if (ASN_ERR_STOPPED(err)) {
			free(binding->v.octetstring.octets);
			binding->v.octetstring.octets = NULL;
		}
		break;

	  case ASN_TYPE_OBJID:
		binding->syntax = USNMP_SYNTAX_OID;
		err = asn_get_objid_raw(b, len, &binding->v.oid);
		break;

	  case ASN_CLASS_APPLICATION|ASN_APP_IPADDRESS:
		binding->syntax = USNMP_SYNTAX_IPADDRESS;
		err = asn_get_ipaddress_raw(b, len, binding->v.ipaddress);
		break;

	  case ASN_CLASS_APPLICATION|ASN_APP_TIMETICKS:
		binding->syntax = USNMP_SYNTAX_TIMETICKS;
		err = asn_get_uint32_raw(b, len, &binding->v.uint32);
		break;

	  case ASN_CLASS_APPLICATION|ASN_APP_COUNTER:
		binding->syntax = USNMP_SYNTAX_COUNTER;
		err = asn_get_uint32_raw(b, len, &binding->v.uint32);
		break;

	  case ASN_CLASS_APPLICATION|ASN_APP_GAUGE:
		binding->syntax = USNMP_SYNTAX_GAUGE;
		err = asn_get_uint32_raw(b, len, &binding->v.uint32);
		break;

	  case ASN_CLASS_APPLICATION|ASN_APP_COUNTER64:
		binding->syntax = USNMP_SYNTAX_COUNTER64;
		err = asn_get_counter64_raw(b, len, &binding->v.counter64);
		break;

	  case ASN_CLASS_CONTEXT | ASN_EXCEPT_NOSUCHOBJECT:
		binding->syntax = USNMP_SYNTAX_NOSUCHOBJECT;
		err = asn_get_null_raw(b, len);
		break;

	  case ASN_CLASS_CONTEXT | ASN_EXCEPT_NOSUCHINSTANCE:
		binding->syntax = USNMP_SYNTAX_NOSUCHINSTANCE;
		err = asn_get_null_raw(b, len);
		break;

	  case ASN_CLASS_CONTEXT | ASN_EXCEPT_ENDOFMIBVIEW:
		binding->syntax = USNMP_SYNTAX_ENDOFMIBVIEW;
		err = asn_get_null_raw(b, len);
		break;

	  default:
		if ((err = asn_skip(b, len)) == ASN_ERR_OK)
			err = ASN_ERR_TAG;
		fprintf(stderr,"bad binding value type 0x%x", type);
		break;
	}

	if (ASN_ERR_STOPPED(err)) {
		fprintf(stderr,"cannot parse binding value");
		return (err);
	}

	if (b->asn_len != 0)
		fprintf(stderr,"ignoring junk at end of binding");

	b->asn_len = trailer;

	return (err);
}

/*
 * Parse the different PDUs contents. Any ASN error in the outer components
 * are fatal. Only errors in variable values may be tolerated. If all
 * components can be parsed it returns either ASN_ERR_OK or the first
 * error that was found.
 */
enum asn_err
usnmp_parse_pdus_hdr(struct asn_buf *b, struct usnmp_pdu *pdu, asn_len_t *lenp)
{
	if (pdu->type == USNMP_PDU_TRAP) {
		if (asn_get_objid(b, &pdu->enterprise) != ASN_ERR_OK) {
			fprintf(stderr,"cannot parse trap enterprise");
			return (ASN_ERR_FAILED);
		}
		if (asn_get_ipaddress(b, pdu->agent_addr) != ASN_ERR_OK) {
			fprintf(stderr,"cannot parse trap agent address");
			return (ASN_ERR_FAILED);
		}
		if (asn_get_integer(b, &pdu->generic_trap) != ASN_ERR_OK) {
			fprintf(stderr,"cannot parse 'generic-trap'");
			return (ASN_ERR_FAILED);
		}
		if (asn_get_integer(b, &pdu->specific_trap) != ASN_ERR_OK) {
			fprintf(stderr,"cannot parse 'specific-trap'");
			return (ASN_ERR_FAILED);
		}
		if (asn_get_timeticks(b, &pdu->time_stamp) != ASN_ERR_OK) {
			fprintf(stderr,"cannot parse trap 'time-stamp'");
			return (ASN_ERR_FAILED);
		}
	} else {
		if (asn_get_integer(b, &pdu->request_id) != ASN_ERR_OK) {
			fprintf(stderr,"cannot parse 'request-id'");
			return (ASN_ERR_FAILED);
		}
		if (asn_get_integer(b, &pdu->error_status) != ASN_ERR_OK) {
			fprintf(stderr,"cannot parse 'error_status'");
			return (ASN_ERR_FAILED);
		}
		if (asn_get_integer(b, &pdu->error_index) != ASN_ERR_OK) {
			fprintf(stderr,"cannot parse 'error_index'");
			return (ASN_ERR_FAILED);
		}
	}

	if (asn_get_sequence(b, lenp) != ASN_ERR_OK) {
		fprintf(stderr,"cannot get varlist header");
		return (ASN_ERR_FAILED);
	}

	return (ASN_ERR_OK);
}

static enum asn_err
parse_pdus(struct asn_buf *b, struct usnmp_pdu *pdu, int32_t *ip)
{
	asn_len_t len, trailer;
	struct usnmp_value *v;
	enum asn_err err, err1;

	err = usnmp_parse_pdus_hdr(b, pdu, &len);
	if (ASN_ERR_STOPPED(err))
		return (err);

	trailer = b->asn_len - len;

	v = pdu->bindings;
	err = ASN_ERR_OK;
	while (b->asn_len != 0) {
		if (pdu->nbindings == USNMP_MAX_BINDINGS) {
			fprintf(stderr,"too many bindings (> %u) in PDU",
			    USNMP_MAX_BINDINGS);
			return (ASN_ERR_FAILED);
		}
		err1 = get_var_binding(b, v);
		if (ASN_ERR_STOPPED(err1))
			return (ASN_ERR_FAILED);
		if (err1 != ASN_ERR_OK && err == ASN_ERR_OK) {
			err = err1;
			*ip = pdu->nbindings + 1;
		}
		pdu->nbindings++;
		v++;
	}

	b->asn_len = trailer;

	return (err);
}

/*
 * Parse the outer SEQUENCE value. ASN_ERR_TAG means 'bad version'.
 */
enum asn_err
usnmp_parse_message_hdr(struct asn_buf *b, struct usnmp_pdu *pdu, asn_len_t *lenp)
{
	int32_t version;
	u_char type;
	u_int comm_len;

	if (asn_get_integer(b, &version) != ASN_ERR_OK) {
		fprintf(stderr,"cannot decode version");
		return (ASN_ERR_FAILED);
	}

	if (version == 0) {
		pdu->version = USNMP_V1;
	} else if (version == 1) {
		pdu->version = USNMP_V2c;
	} else {
		pdu->version = USNMP_Verr;
		fprintf(stderr,"unsupported SNMP version");
		return (ASN_ERR_TAG);
	}

	comm_len = USNMP_COMMUNITY_MAXLEN;
	if (asn_get_octetstring(b, (u_char *)pdu->community,
	    &comm_len) != ASN_ERR_OK) {
		fprintf(stderr,"cannot decode community");
		return (ASN_ERR_FAILED);
	}
	pdu->community[comm_len] = '\0';

	if (asn_get_header(b, &type, lenp) != ASN_ERR_OK) {
		fprintf(stderr,"cannot get pdu header");
		return (ASN_ERR_FAILED);
	}
	if ((type & ~ASN_TYPE_MASK) !=
	    (ASN_TYPE_CONSTRUCTED | ASN_CLASS_CONTEXT)) {
		fprintf(stderr,"bad pdu header tag");
		return (ASN_ERR_FAILED);
	}
	pdu->type = type & ASN_TYPE_MASK;

	switch (pdu->type) {

	  case USNMP_PDU_GET:
	  case USNMP_PDU_GETNEXT:
	  case USNMP_PDU_RESPONSE:
	  case USNMP_PDU_SET:
		break;

	  case USNMP_PDU_TRAP:
		if (pdu->version != USNMP_V1) {
			fprintf(stderr,"bad pdu type %u", pdu->type);
			return (ASN_ERR_FAILED);
		}
		break;

	  case USNMP_PDU_GETBULK:
	  case USNMP_PDU_INFORM:
	  case USNMP_PDU_TRAP2:
	  case USNMP_PDU_REPORT:
		if (pdu->version == USNMP_V1) {
			fprintf(stderr,"bad pdu type %u", pdu->type);
			return (ASN_ERR_FAILED);
		}
		break;

	  default:
		fprintf(stderr,"bad pdu type %u", pdu->type);
		return (ASN_ERR_FAILED);
	}


	if (*lenp > b->asn_len) {
		fprintf(stderr,"pdu length too long");
		return (ASN_ERR_FAILED);
	}

	return (ASN_ERR_OK);
}

static enum asn_err
parse_message(struct asn_buf *b, struct usnmp_pdu *pdu, int32_t *ip)
{
	enum asn_err err;
	asn_len_t len, trailer;

	err = usnmp_parse_message_hdr(b, pdu, &len);
	if (ASN_ERR_STOPPED(err))
		return (err);

	trailer = b->asn_len - len;
	b->asn_len = len;

	err = parse_pdus(b, pdu, ip);
	if (ASN_ERR_STOPPED(err))
		return (ASN_ERR_FAILED);

	if (b->asn_len != 0)
		fprintf(stderr,"ignoring trailing junk after pdu");

	b->asn_len = trailer;

	return (err);
}

/*
 * Decode the PDU except for the variable bindings itself.
 * If decoding fails because of a bad binding, but the rest can be
 * decoded, ip points to the index of the failed variable (errors
 * OORANGE, BADLEN or BADVERS).
 */
enum usnmp_code
usnmp_pdu_decode(struct asn_buf *b, struct usnmp_pdu *pdu, int32_t *ip)
{
	asn_len_t len;

	memset(pdu, 0, sizeof(*pdu));

	if (asn_get_sequence(b, &len) != ASN_ERR_OK) {
		fprintf(stderr,"cannot decode pdu header\n");
		return (USNMP_CODE_FAILED);
	}
	if (b->asn_len < len) {
		fprintf(stderr,"outer sequence value too short\n");
		return (USNMP_CODE_FAILED);
	}
	if (b->asn_len != len) {
		fprintf(stderr,"ignoring trailing junk in message\n");
		b->asn_len = len;
	}

	switch (parse_message(b, pdu, ip)) {

	  case ASN_ERR_OK:
		return (USNMP_CODE_OK);

	  case ASN_ERR_FAILED:
	  case ASN_ERR_EOBUF:
		usnmp_pdu_free(pdu);
		return (USNMP_CODE_FAILED);

	  case ASN_ERR_BADLEN:
		return (USNMP_CODE_BADLEN);

	  case ASN_ERR_RANGE:
		return (USNMP_CODE_OORANGE);

	  case ASN_ERR_TAG:
		if (pdu->version == USNMP_Verr)
			return (USNMP_CODE_BADVERS);
		else
			return (USNMP_CODE_BADENC);
	}

	return (USNMP_CODE_OK);
}

/*
 * Encode the SNMP PDU without the variable bindings field.
 * We do this the rather uneffective way by
 * moving things around and assuming that the length field will never
 * use more than 2 bytes.
 * We need a number of pointers to apply the fixes afterwards.
 */
enum usnmp_code
usnmp_pdu_encode_header(struct asn_buf *b, struct usnmp_pdu *pdu)
{
	enum asn_err err;

	if (asn_put_temp_header(b, (ASN_TYPE_SEQUENCE|ASN_TYPE_CONSTRUCTED),
	    &pdu->outer_ptr) != ASN_ERR_OK)
		return (USNMP_CODE_FAILED);

	if (pdu->version == USNMP_V1)
		err = asn_put_integer(b, 0);
	else if (pdu->version == USNMP_V2c)
		err = asn_put_integer(b, 1);
	else
		return (USNMP_CODE_BADVERS);
	if (err != ASN_ERR_OK)
		return (USNMP_CODE_FAILED);

	if (asn_put_octetstring(b, (u_char *)pdu->community,
	    strlen(pdu->community)) != ASN_ERR_OK)
		return (USNMP_CODE_FAILED);

	if (asn_put_temp_header(b, (ASN_TYPE_CONSTRUCTED | ASN_CLASS_CONTEXT |
	    pdu->type), &pdu->pdu_ptr) != ASN_ERR_OK)
		return (USNMP_CODE_FAILED);

	if (pdu->type == USNMP_PDU_TRAP) {
		if (pdu->version != USNMP_V1 ||
		    asn_put_objid(b, &pdu->enterprise) != ASN_ERR_OK ||
		    asn_put_ipaddress(b, pdu->agent_addr) != ASN_ERR_OK ||
		    asn_put_integer(b, pdu->generic_trap) != ASN_ERR_OK ||
		    asn_put_integer(b, pdu->specific_trap) != ASN_ERR_OK ||
		    asn_put_timeticks(b, pdu->time_stamp) != ASN_ERR_OK)
			return (USNMP_CODE_FAILED);
	} else {
		if (pdu->version == USNMP_V1 && (pdu->type == USNMP_PDU_GETBULK ||
		    pdu->type == USNMP_PDU_INFORM ||
		    pdu->type == USNMP_PDU_TRAP2 ||
		    pdu->type == USNMP_PDU_REPORT))
			return (USNMP_CODE_FAILED);

		if (asn_put_integer(b, pdu->request_id) != ASN_ERR_OK ||
		    asn_put_integer(b, pdu->error_status) != ASN_ERR_OK ||
		    asn_put_integer(b, pdu->error_index) != ASN_ERR_OK)
			return (USNMP_CODE_FAILED);
	}

	if (asn_put_temp_header(b, (ASN_TYPE_SEQUENCE|ASN_TYPE_CONSTRUCTED),
	    &pdu->vars_ptr) != ASN_ERR_OK)
		return (USNMP_CODE_FAILED);

	return (USNMP_CODE_OK);
}

enum usnmp_code
usnmp_fix_encoding(struct asn_buf *b, const struct usnmp_pdu *pdu)
{
	if (asn_commit_header(b, pdu->vars_ptr) != ASN_ERR_OK ||
	    asn_commit_header(b, pdu->pdu_ptr) != ASN_ERR_OK ||
	    asn_commit_header(b, pdu->outer_ptr) != ASN_ERR_OK)
		return (USNMP_CODE_FAILED);
	return (USNMP_CODE_OK);
}

/*
 * Encode a binding. Caller must ensure, that the syntax is ok for that version.
 * Be sure not to cobber b, when something fails.
 */
enum asn_err
usnmp_binding_encode(struct asn_buf *b, const struct usnmp_value *binding)
{
	u_char *ptr;
	enum asn_err err;
	struct asn_buf save = *b;

	if ((err = asn_put_temp_header(b, (ASN_TYPE_SEQUENCE |
	    ASN_TYPE_CONSTRUCTED), &ptr)) != ASN_ERR_OK) {
		*b = save;
		return (err);
	}

	if ((err = asn_put_objid(b, &binding->var)) != ASN_ERR_OK) {
		*b = save;
		return (err);
	}

	switch (binding->syntax) {

	  case USNMP_SYNTAX_NULL:
		err = asn_put_null(b);
		break;

	  case USNMP_SYNTAX_INTEGER:
		err = asn_put_integer(b, binding->v.integer);
		break;

	  case USNMP_SYNTAX_OCTETSTRING:
		err = asn_put_octetstring(b, binding->v.octetstring.octets,
		    binding->v.octetstring.len);
		break;

	  case USNMP_SYNTAX_OID:
		err = asn_put_objid(b, &binding->v.oid);
		break;

	  case USNMP_SYNTAX_IPADDRESS:
		err = asn_put_ipaddress(b, binding->v.ipaddress);
		break;

	  case USNMP_SYNTAX_TIMETICKS:
		err = asn_put_uint32(b, ASN_APP_TIMETICKS, binding->v.uint32);
		break;

	  case USNMP_SYNTAX_COUNTER:
		err = asn_put_uint32(b, ASN_APP_COUNTER, binding->v.uint32);
		break;

	  case USNMP_SYNTAX_GAUGE:
		err = asn_put_uint32(b, ASN_APP_GAUGE, binding->v.uint32);
		break;

	  case USNMP_SYNTAX_COUNTER64:
		err = asn_put_counter64(b, binding->v.counter64);
		break;

	  case USNMP_SYNTAX_NOSUCHOBJECT:
		err = asn_put_exception(b, ASN_EXCEPT_NOSUCHOBJECT);
		break;

	  case USNMP_SYNTAX_NOSUCHINSTANCE:
		err = asn_put_exception(b, ASN_EXCEPT_NOSUCHINSTANCE);
		break;

	  case USNMP_SYNTAX_ENDOFMIBVIEW:
		err = asn_put_exception(b, ASN_EXCEPT_ENDOFMIBVIEW);
		break;
	}

	if (err != ASN_ERR_OK) {
		*b = save;
		return (err);
	}

	err = asn_commit_header(b, ptr);
	if (err != ASN_ERR_OK) {
		*b = save;
		return (err);
	}

	return (ASN_ERR_OK);
}

/*
 * Encode an PDU.
 */
enum usnmp_code
usnmp_pdu_encode(struct usnmp_pdu *pdu, struct asn_buf *resp_b)
{
	u_int idx;
	enum usnmp_code err;

	if ((err = usnmp_pdu_encode_header(resp_b, pdu)) != USNMP_CODE_OK)
		return (err);
	for (idx = 0; idx < pdu->nbindings; idx++)
		if ((err = usnmp_binding_encode(resp_b, &pdu->bindings[idx]))
		    != ASN_ERR_OK)
			return (USNMP_CODE_FAILED);

	return (usnmp_fix_encoding(resp_b, pdu));
}

void
usnmp_value_free(struct usnmp_value *value)
{
	if (value->syntax == USNMP_SYNTAX_OCTETSTRING)
		free(value->v.octetstring.octets);
	value->syntax = USNMP_SYNTAX_NULL;
}

int
usnmp_value_copy(struct usnmp_value *to, const struct usnmp_value *from)
{
	to->var = from->var;
	to->syntax = from->syntax;

	if (from->syntax == USNMP_SYNTAX_OCTETSTRING) {
		if ((to->v.octetstring.len = from->v.octetstring.len) == 0)
			to->v.octetstring.octets = NULL;
		else {
			to->v.octetstring.octets = malloc(to->v.octetstring.len);
			if (to->v.octetstring.octets == NULL)
				return (-1);
			(void)memcpy(to->v.octetstring.octets,
			    from->v.octetstring.octets, to->v.octetstring.len);
		}
	} else
		to->v = from->v;
	return (0);
}

void
usnmp_pdu_free(struct usnmp_pdu *pdu)
{
	u_int i;

	for (i = 0; i < pdu->nbindings; i++)
		usnmp_value_free(&pdu->bindings[i]);
}

/*
 * Parse an ASCII SNMP value into the binary form
 */
int
usnmp_value_parse(const char *str, enum usnmp_syntax syntax, union usnmp_values *v)
{
	char *end;

	switch (syntax) {

	  case USNMP_SYNTAX_NULL:
	  case USNMP_SYNTAX_NOSUCHOBJECT:
	  case USNMP_SYNTAX_NOSUCHINSTANCE:
	  case USNMP_SYNTAX_ENDOFMIBVIEW:
		if (*str != '\0')
			return (-1);
		return (0);

	  case USNMP_SYNTAX_INTEGER:
		v->integer = strtoll(str, &end, 0);
		if (*end != '\0')
			return (-1);
		return (0);

	  case USNMP_SYNTAX_OCTETSTRING:
	    {
		u_long len;	/* actual length of string */
		u_long alloc;	/* allocate length of string */
		u_char *octs;	/* actual octets */
		u_long oct;	/* actual octet */
		u_char *nocts;	/* to avoid memory leak */
		u_char c;	/* actual character */

# define STUFFC(C)							\
		if (alloc == len) {					\
			alloc += 100;					\
			if ((nocts = realloc(octs, alloc)) == NULL) {	\
				free(octs);				\
				return (-1);				\
			}						\
			octs = nocts;					\
		}							\
		octs[len++] = (C);

		len = alloc = 0;
		octs = NULL;

		if (*str == '"') {
			str++;
			while((c = *str++) != '\0') {
				if (c == '"') {
					if (*str != '\0') {
						free(octs);
						return (-1);
					}
					break;
				}
				if (c == '\\') {
					switch (c = *str++) {

					  case '\\':
						break;
					  case 'a':
						c = '\a';
						break;
					  case 'b':
						c = '\b';
						break;
					  case 'f':
						c = '\f';
						break;
					  case 'n':
						c = '\n';
						break;
					  case 'r':
						c = '\r';
						break;
					  case 't':
						c = '\t';
						break;
					  case 'v':
						c = '\v';
						break;
					  case 'x':
						c = 0;
						if (!isxdigit(*str))
							break;
						if (isdigit(*str))
							c = *str++ - '0';
						else if (isupper(*str))
							c = *str++ - 'A' + 10;
						else
							c = *str++ - 'a' + 10;
						if (!isxdigit(*str))
							break;
						if (isdigit(*str))
							c += *str++ - '0';
						else if (isupper(*str))
							c += *str++ - 'A' + 10;
						else
							c += *str++ - 'a' + 10;
						break;
					  case '0': case '1': case '2':
					  case '3': case '4': case '5':
					  case '6': case '7':
						c = *str++ - '0';
						if (*str < '0' || *str > '7')
							break;
						c = *str++ - '0';
						if (*str < '0' || *str > '7')
							break;
						c = *str++ - '0';
						break;
					  default:
						break;
					}
				}
				STUFFC(c);
			}
		} else {
			while (*str != '\0') {
				oct = strtoul(str, &end, 16);
				str = end;
				if (oct > 0xff) {
					free(octs);
					return (-1);
				}
				STUFFC(oct);
				if (*str == ':')
					str++;
				else if(*str != '\0') {
					free(octs);
					return (-1);
				}
			}
		}
		v->octetstring.octets = octs;
		v->octetstring.len = len;
		return (0);
# undef STUFFC
	    }

	  case USNMP_SYNTAX_OID:
	    {
		u_long subid;

		v->oid.len = 0;

		for (;;) {
			if (v->oid.len == ASN_MAXOIDLEN)
				return (-1);
			subid = strtoul(str, &end, 10);
			str = end;
			if (subid > ASN_MAXID)
				return (-1);
			v->oid.subs[v->oid.len++] = (asn_subid_t)subid;
			if (*str == '\0')
				break;
			if (*str != '.')
				return (-1);
			str++;
		}
		return (0);
	    }

	  case USNMP_SYNTAX_IPADDRESS:
	    {
		struct hostent *he;
		u_long ip[4];
		int n;

		if (sscanf(str, "%lu.%lu.%lu.%lu%n", &ip[0], &ip[1], &ip[2],
		    &ip[3], &n) == 4 && (size_t)n == strlen(str) &&
		    ip[0] <= 0xff && ip[1] <= 0xff &&
		    ip[2] <= 0xff && ip[3] <= 0xff) {
			v->ipaddress[0] = (u_char)ip[0];
			v->ipaddress[1] = (u_char)ip[1];
			v->ipaddress[2] = (u_char)ip[2];
			v->ipaddress[3] = (u_char)ip[3];
			return (0);
		}

		if ((he = gethostbyname(str)) == NULL)
			return (-1);
		if (he->h_addrtype != AF_INET)
			return (-1);

		v->ipaddress[0] = he->h_addr[0];
		v->ipaddress[1] = he->h_addr[1];
		v->ipaddress[2] = he->h_addr[2];
		v->ipaddress[3] = he->h_addr[3];
		return (0);
	    }

	  case USNMP_SYNTAX_COUNTER:
	  case USNMP_SYNTAX_GAUGE:
	  case USNMP_SYNTAX_TIMETICKS:
	    {
		u_int64_t sub;

		sub = strtoull(str, &end, 0);
		if (*end != '\0' || sub > 0xffffffff)
			return (-1);
		v->uint32 = (u_int32_t)sub;
		return (0);
	    }

	  case USNMP_SYNTAX_COUNTER64:
		v->counter64 = strtoull(str, &end, 0);
		if (*end != '\0')
			return (-1);
		return (0);
	}
	abort();
}
/* @Modification by Yannick Marquet 2009 */
