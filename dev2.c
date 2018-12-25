/*************************************************************************
  > File Name: cli.c
  > Author: zll
  > Mail: zhnllion@126.com 
  > Created Time: Tue 13 Nov 2018 09:50:23 AM CST
 ************************************************************************/

#include "common.h"
#include "epoll.h"
#include "cJSON.h"

#if 0
ai_family	
AF_INET		2		IPv4
AF_INET6	23		IPv6
AF_UNSPEC	0		协议无关

ai_protocol
IPPROTO_IP		0	IP协议
IPPROTO_IPV4	4	IPv4
IPPROTO_IPV6	41	IPv6
IPPROTO_UDP		17	UDP
IPPROTO_TCP		6	TCP

ai_socktype
SOCK_STREAM		1	流
SOCK_DGRAM		2	数据报

ai_flags
AI_PASSIVE		1	被动的，用于bind，通常用于server socket
AI_CANONNAME	2	用于返回主机的规范名称
AI_NUMERICHOST	4	地址为数字串
#endif

#define HOST "127.0.0.1"
#define IP6HOST "::1"
#define PORT "8001"

int connect_to_server(const char *host, const char *port){
	int fd;
	//	struct sockaddr_in;
	struct addrinfo hints, *ai, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; 
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;

	if(getaddrinfo(host, port, &hints, &res)){
		printf("name lookup %s:%s failed %s", host, port, strerror(errno));
		return -1;
	}

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if(fd < 0){
			printf("fd < 0\n");
			continue;
		}

		if (connect(fd, ai->ai_addr, ai->ai_addrlen)) {
			close(fd);
			fd = -1;
			continue;
		}
		//printf("ai family:%d,", ai->ai_family);
		//printf("ai protocol:%d,", ai->ai_protocol);
		//printf("ai socket type:%d\n", ai->ai_socktype);
	}
	return fd;
}


int main(void){
	int fd;
	char reg[MSG_LEN], msg[MSG_LEN];
	memset(&reg, 0, MSG_LEN);
	memset(&msg, 0, MSG_LEN);

	fd = connect_to_server(HOST, PORT);
	if(fd < 0){
		printf("connect server err:%s\n", strerror(fd));
		return -1;
	}
	sprintf((char *)&reg, REG_FORMAT, CONN_AUTH_REQ, 0, "ID-KEY2", "temp", 0, "none");
	
	send(fd, &reg, DATA_LEN, 0);
	while(1){
		recv(fd, msg, MSG_LEN, 0);
		printf("%s\n", msg);
		//		send(fd,"{\"data\":\"xxx\"}", MSG_LEN, 0);
		sleep(1);
		memset(msg, 0, MSG_LEN);
	}
	return 0;
}
