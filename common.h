#ifndef _LOCAL_COMMON_H
#define _LOCAL_COMMON_H

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdarg.h>

#include <poll.h> 
#include <sys/epoll.h>

#include <sys/wait.h>
#include <signal.h>

#include <sys/socket.h>
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/file.h>
#include <fcntl.h>

#include <unistd.h>
#include <pthread.h>

#include <assert.h>
#include <errno.h>

#define DEV_PORT	8001
#define USER_PORT	8002

#define IP_LEN 128
#define NAME_LEN 16
#define DATA_LEN 256

enum MSG_TYPE {
	CONN_AUTH_REQ=1,
	CONN_AUTH_RESP,
	CONN_AUTH_REAUTH,
	PUSH_DATA,
	CONN_CLOSE,
	PING_REQ,
	PING_RESP
};

#define REG_FORMAT "{\"type\":\"%d\", \"is_user\":\"%d\", \"name\":\"%s\", \"module\":\"%s\",\"fd\":\"%d\", \"data\":\"%s\"}"

#define REG 0
#define NO_EXIST 0
#define UNREG 1
#define EXIST 2

#define BACK_SIZE 32
#define MSG_UNREG "Unregister!"
#define MSG_REG "Register OK!"
#define MSG_REGFAIL "Register Failed, close!"
#define MSG_DEVNOREG "Device not Register!"


typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef unsigned int u32_t;

#define list_for_node(pos, n, head) \
	for(pos = head, n = pos->next; n != NULL; pos = n, n = n->next)

typedef struct node_info {
	char name[NAME_LEN];
	char peerip[IP_LEN];
	char peerport[IP_LEN];
	char fd_s[NAME_LEN];
	int fd;
} NODE;
#define NODE_LEN sizeof(NODE)

typedef struct msg_info {
	int fd;
	bool is_user;
	int type;
	char name[NAME_LEN];
	char module[NAME_LEN];
	char data[DATA_LEN];
} MSG;

#define MSG_LEN sizeof(MSG)

struct buf {
	char v[64*1024];
	int b, e;
};

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) ((a) < (b) ? (b) : (a))
#endif

#endif
