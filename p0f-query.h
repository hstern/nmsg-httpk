#ifndef P0F_QUERY_H
#define P0F_QUERY_H

typedef unsigned char		_u8;
typedef unsigned short		_u16;
typedef unsigned int		_u32;
typedef unsigned long long	_u64;

typedef signed char		_s8;
typedef signed short		_s16;
typedef signed int		_s32;
typedef signed long long	_s64;

#define QUERY_MAGIC		0x0defaced

#define QTYPE_FINGERPRINT	1

#define RESP_OK			0
#define RESP_BADQUERY		1
#define RESP_NOMATCH		2

struct p0f_query {
	_u32	magic;
	_u8	type;
	_u32	id;
	_u32	src_ip;
	_u32	dst_ip;
	_u16	src_port;
	_u16	dst_port;
};

struct p0f_response {
	_u32	magic;
	_u32	id;
	_u8	type;

	_u8	genre[20];
	_u8	detail[40];
	_s8	dist;
	_u8	link[30];
	_u8	tos[30];
	_u8	fw;
	_u8	nat;
	_u8	real;
	_s16	score;
	_u16	mflags;
	_s32	uptime;
};

#endif /* P0F_QUERY_H */
