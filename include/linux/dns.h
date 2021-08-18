#pragma once

#define DNS_OPCODE_QUERY	0
#define DNS_OPCODE_IQUERY	1
#define DNS_OPCODE_STATUS	2
#define DNS_OPCODE_NOTIFY	4
#define DNS_OPCODE_UPDATE	5

#define DNS_RCODE_NOERROR	0
#define DNS_RCODE_FORMERR	1
#define DNS_RCODE_SERVFAIL	2
#define DNS_RCODE_NXDOMAIN	3
#define DNS_RCODE_NOTIMP	4
#define DNS_RCODE_REFUSED	5
#define DNS_RCODE_YXDOMAIN	6
#define DNS_RCODE_YXRRSET	7
#define DNS_RCODE_NXRRSET	8
#define DNS_RCODE_NOTAUTH	9
#define DNS_RCODE_NOTZONE	10
#define DNS_RCODE_BADVERS	16
#define DNS_RCODE_BADSIG	16
#define DNS_RCODE_BADKEY	17
#define DNS_RCODE_BADTIME	18
#define DNS_RCODE_BADMODE	19
#define DNS_RCODE_BADNAME	20
#define DNS_RCODE_BADALG	21
#define DNS_RCODE_BADTRUNC	22
#define DNS_RCODE_BADCOOKIE	23

#include <endian.h>
#include <stdint.h>
#include <strings.h>

struct dnshdr {
	__be16      id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16       recursion_desired:1,
                truncated:1,
                authoritative:1,
                opcode:4,
                qr:1,
                reply_code:4,
                non_authenticated_data:1,
                answer_authenticated:1,
                zero:1,
                recursion_available:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16       qr:1,
                opcode:4,
                authoritative:1,
                truncated:1,
                recursion_desired:1,
                recursion_available:1,
                zero:1,
                answer_authenticated:1,
                non_authenticated_data:1,
                reply_code:4;
#else
#error        "Adjust your <asm/byteorder.h> defines"
#endif
	__be16      qcount;	    /* questions count */
	__be16      ancount;	/* answer records count */
	__be16      nscount;	/* name server (autority record) count */
	__be16      adcount;	/* additional record count */
};
