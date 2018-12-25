#include "common.h"
#include "epoll.h"

int setnonblocking(int fd)
{
	int old_option = fcntl(fd, F_GETFL);
	int new_option = old_option | O_NONBLOCK;
	fcntl(fd, F_SETFL, new_option);
	return fd;
}

void reset_oneshot(int epollfd, int fd)
{
	struct epoll_event event;
	event.data.fd = fd;
	event.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
	epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event);
}

void add_fd(int epollfd, int fd, bool enable_et)
{
	struct epoll_event event = {};
	event.data.fd = fd;
	event.events = EPOLLIN;
	if(enable_et){
		event.events |= EPOLLET;
	}

	epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
	setnonblocking(fd);
}

void add_oneshot_fd(int epollfd, int fd, bool oneshot)
{
	struct epoll_event event;
	memset(&event, 0, sizeof(struct epoll_event));

	event.data.fd = fd;
	event.events = EPOLLIN | EPOLLET;
	if(oneshot)
	{
		event.events |= EPOLLONESHOT;
	}

	epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
	setnonblocking(fd);
}


void del_fd(int epollfd, int fd)
{
	struct epoll_event event;
	event.data.fd = fd;
	event.events = EPOLLIN;

	epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &event);
}

void lt(struct epoll_event* events, int number, int epollfd, int listenfd)
{
	char buf[BUF_SIZE];
	for (int i = 0; i < number; i++){
		int sockfd = events[i].data.fd;
		if(sockfd == listenfd)
		{
			struct sockaddr_in client_address;
			socklen_t client_addrlength = sizeof(client_address);
			int connfd = accept(listenfd, (struct sockaddr*)&client_address, &client_addrlength);
			printf("connfd %d\n", connfd);
			add_fd(epollfd, connfd, false);
		}
		else if( events[i].events & EPOLLIN)
		{
			printf("event trigger once\n");
			memset(buf, 0, BUF_SIZE);
			int ret = recv(sockfd, buf, (BUF_SIZE - 1), 0);
			if(ret <= 0 )
			{
				close(sockfd);
				continue;
			}
			printf("get %d bytes of content:%s\n", ret, buf);
		}
		else
		{
			printf("something else happended\n");
		}
	}
}

void et(struct epoll_event* events, int number, int epollfd, int listenfd)
{
	char buf[BUF_SIZE];
	for (int i = 0; i < number; i++){
		int sockfd = events[i].data.fd;
		if(sockfd == listenfd)
		{
			struct sockaddr_in client_address;
			socklen_t client_addrlength = sizeof(client_address);
			int connfd = accept(listenfd, (struct sockaddr*)&client_address, &client_addrlength);
			printf("connfd %d\n", connfd);
			add_fd(epollfd, connfd, false);
		}
		else if( events[i].events & EPOLLIN)
		{
			printf("event trigger once\n");
			while(1){
				memset(buf, 0, BUF_SIZE);
				int ret = recv(sockfd, buf, BUF_SIZE - 1, 0);
				if(ret < 0)
				{
					if( (errno == EAGAIN) || ( errno == EWOULDBLOCK))
					{
						printf("read later\n");
						break;
					}
					close(sockfd);
					break;
				}
				else if(ret == 0)
				{
					close(sockfd);
				}
				else{
					printf("get %d bytes of content:%s\n", ret, buf);
				}
			}
		}
		else
		{
			printf("something else happended\n");
		}
	}
}

