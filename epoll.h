#ifndef _EPOLL_H
#define _EPOLL_H

#define BUF_SIZE        64
#define MAX_EVENT_NUMBER 10240

typedef struct _fds
{
	int epollfd;
	int sockfd;
	int user;
}fds;

void add_fd(int epollfd, int fd, bool enable_et);
void add_oneshot_fd(int epollfd, int fd, bool oneshot);
void del_fd(int epollfd, int fd);
void lt(struct epoll_event* events, int number, int epollfd, int listenfd);
void et(struct epoll_event* events, int number, int epollfd, int listenfd);
void reset_oneshot(int epollfd, int fd);
#endif
