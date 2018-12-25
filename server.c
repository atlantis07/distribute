#include "common.h"
#include "epoll.h"
#include "hashmap.h"
#include "cJSON.h"

map_t devmap, fdmap;
pthread_mutex_t mutex_lock = PTHREAD_MUTEX_INITIALIZER;

char *hash_free(void *p1, void *p2){
	NODE *n = (NODE *)p2;
//	hashmap_get();

	return MAP_OK;
}

static int listen_tcp(u16_t port) {
	int fd;
	struct sockaddr_in6 si6;
	struct sockaddr_in si4;
	struct sockaddr* sa = (struct sockaddr*) &si6;
	size_t salen = sizeof(si6);
	int v6only = 0;

	memset(&si6, 0, sizeof(si6));
	si6.sin6_family = AF_INET6;
	si6.sin6_port = htons(port);

	memset(&si4, 0, sizeof(si4));
	si4.sin_family = AF_INET;
	si4.sin_port = htons(port);

	fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0 || setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only))) {
		printf("IPv6 only not supported, falling back to IPv4");
		close(fd);
		fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		sa = (struct sockaddr*) &si4;
		salen = sizeof(si4);
	}

	int on = 1;
	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0){
		printf("set addr reuse failed\n");
		return -1;
	}

	if (bind(fd, sa, salen)) {
		printf("bind to *:%d failed %s", port, strerror(errno));
		return -1;
	}
	if (listen(fd, SOMAXCONN)) {
		printf("listen to *:%d failed %s", port, strerror(errno));
		return -1;
	}

	return fd;
}

#if 0
static int lockfd;
static void FILE_LOCK_INIT(){
	lockfd = open("./file.lock", O_RDWR);
	if (lockfd < 0){
		printf("file open error!\n");
		exit(-1);
	}
}

static void FILE_LOCK(void){
	flock(lockfd, LOCK_EX);
}

static void FILE_UNLOCK(void){
	flock(lockfd, LOCK_UN);
}

#endif

static int hashmap_check(map_t in, char *key){
	//chech conflict
	NODE *chk = NULL;
	int error = hashmap_get(in, key, (void **)&chk);
	if(error == MAP_OK){// already register msg.name
		printf("register conflict\n");
		return EXIST;
	}
	return NO_EXIST;
}

static int hash_conflict_remove(map_t in, char* key){
	NODE *p = NULL;
	return 0;
}

static int Register(MSG msg, int fd, int is_user){
	if(strlen(msg.name) == 0){
		printf("reg info err\n");
		goto fail;
	}

	if(!is_user){
		if(hashmap_check(devmap, msg.name) == EXIST){
			printf("%s exist\n", msg.name);
			goto fail;
		};
	}

	char fd_s[NAME_LEN];
	memset(fd_s, 0, NAME_LEN);
	snprintf(fd_s, NAME_LEN, "%d", fd);
	if(hashmap_check(fdmap, fd_s) == EXIST){
		printf("fd %d exist\n", fd);
		goto fail;
	}


	int error;
	if(!is_user){
		// name ------> fd
		NODE *pn = NULL;
		pn = malloc(sizeof(NODE));
		if(!pn){
			printf("malloc for device failed\n");
			goto fail;
		}
		snprintf(pn->name, NAME_LEN, "%s", msg.name);
		pn->fd = fd;

		error = hashmap_put(devmap, pn->name, pn);
		if(error != MAP_OK){
			printf("hash put device info failed\n");
			free(pn);
		}
	}


	NODE *pfn = NULL;
	pfn = malloc(sizeof(NODE));
	if(!pfn){
		printf("malloc for device failed\n");
		goto fail;
	}
	snprintf(pfn->name, NAME_LEN, "%s", msg.name);
	snprintf(pfn->fd_s, NAME_LEN, "%d", fd);
	pfn->fd = fd;

#if 1
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	int len = sizeof(sa);
	if(!getpeername(fd, (struct sockaddr *)&sa, &len))
	{
		snprintf(pfn->peerip, IP_LEN, "%s", inet_ntoa(sa.sin_addr));
		snprintf(pfn->peerport, IP_LEN, "%d", ntohs(sa.sin_port));
		
//		printf( "对方IP：%s \n", inet_ntoa(sa.sin_addr));
//		printf( "对方PORT：%d \n", ntohs(sa.sin_port));
	}
#endif

	error = hashmap_put(fdmap, pfn->fd_s, pfn);
	if(error != MAP_OK){
		printf("hash put device info failed\n");
		goto fdmapfail;
	}
	return REG;

fdmapfail:
	free(pfn);
fail:
	return UNREG;
}

int check_if_register(int fd){
	if(fd <= 0){
		return UNREG;
	}

	NODE *ppn = NULL;

	char fd_s[NAME_LEN];
	memset(fd_s, 0, NAME_LEN);
	snprintf(fd_s, NAME_LEN, "%d", fd);

	int ret = hashmap_get(fdmap, fd_s, (void**)(&ppn));
	if(ret == MAP_OK){
		return REG;
	}
	return UNREG;
}

static int do_transfer(void* buf, bool is_user, int fd, char *name, char *module, char* data){
	if(is_user){
		int dev_fd;

		if(dev_fd){
			memset(buf, 0, MSG_LEN);
			sprintf((char *)buf, REG_FORMAT, PUSH_DATA, 1, "ID-KEY", "temp", fd, data);
			printf("send to device[%d] %s\n", dev_fd, (char *)buf);
			send(dev_fd, buf, MSG_LEN, MSG_DONTWAIT);
		}
		else{
			return -1;
		}
	}
	else{
		printf("send to %d\n", fd);
		send(fd, buf, MSG_LEN, MSG_DONTWAIT);
	}

	return 0;
}

void free_client(int sockfd, int is_user){
	NODE *pfd = NULL, *pn = NULL;

	char fd_s[NAME_LEN];
	memset(fd_s, 0, NAME_LEN);
	snprintf(fd_s, NAME_LEN, "%d", sockfd);

	int ret = hashmap_get(fdmap, fd_s, (void**)(&pfd));
	if(ret == MAP_OK){

		if(!is_user){
			ret = hashmap_get(devmap, pfd->name, (void**)(&pn));
			if(ret == MAP_OK){
				ret = hashmap_remove(devmap, pfd->name);
				if(ret == MAP_OK){
					free(pn);
				}
			}
		}

		ret = hashmap_remove(fdmap, fd_s);
		if(ret == MAP_OK){
			free(pfd);
		}
	}
}

void send_back(int fd, char *s){
	send(fd, s, BACK_SIZE, 0);
}

void *worker(void *arg)
{
	pthread_detach(pthread_self());

	int sockfd = ((fds*)arg)->sockfd;
	int epollfd = ((fds*)arg)->epollfd;
	int is_user = ((fds*)arg)->user;
	free(arg);

//	printf("start new thread to receive data on fd:%d\n", sockfd);
	char buf[MSG_LEN];
	memset(buf, 0, MSG_LEN);

	while(1)
	{
		int ret = recv(sockfd, buf, MSG_LEN, 0);
		if(ret == 0)
		{
			printf("%d closed the connection\n", sockfd);

			close(sockfd);

			pthread_mutex_lock(&mutex_lock);
			free_client(sockfd, is_user);
			pthread_mutex_unlock(&mutex_lock);

			break;
		}
		else if (ret < 0)
		{
			if(errno == EAGAIN)
			{
				reset_oneshot(epollfd, sockfd);
				//printf("read later\n");
				break;
			}
		}
		else
		{
			MSG msg = do_analysis(buf);
			if(check_if_register(sockfd) == UNREG){
				if(msg.type != CONN_AUTH_REQ){
					send_back(sockfd, MSG_UNREG);
					break;
				}
				// lock
				pthread_mutex_lock(&mutex_lock);
				int reg = Register(msg, sockfd, is_user);
				if(reg == UNREG){
					send_back(sockfd, MSG_REGFAIL);
					pthread_mutex_unlock(&mutex_lock);
					close(sockfd);
					break;
				}
				pthread_mutex_unlock(&mutex_lock);

				send_back(sockfd, MSG_REG);
			}
			else{
				if(msg.type == CONN_AUTH_REAUTH){
					pthread_mutex_lock(&mutex_lock);

					free_client(sockfd, is_user);

					int reg = Register(msg, sockfd, is_user);
					if(reg == UNREG){
						send_back(sockfd, MSG_REGFAIL);
						pthread_mutex_unlock(&mutex_lock);

						close(sockfd);
						break;
					}

					pthread_mutex_unlock(&mutex_lock);
					send_back(sockfd, MSG_REG);

					break;
				}

				//PUSH DATA
				if(is_user){
					//map
					char fd_s[NAME_LEN];
					memset(fd_s, 0, NAME_LEN);
					snprintf(fd_s, NAME_LEN, "%d", sockfd);
					
					NODE *p1 = NULL, *p2 = NULL;

					//get device name
					int ret = hashmap_get(fdmap, fd_s, (void **)&p1);
					if(ret != MAP_OK){
						break;
					}

					//get device fd
					ret = hashmap_get(devmap, p1->name, (void **)&p2);
					if(ret != MAP_OK){
						send_back(sockfd, MSG_DEVNOREG);
						break;
					}
	
					cJSON *root;
					root = cJSON_CreateObject();
					if(!root){
						break;
					}

					cJSON_AddStringToObject(root, "data", buf);
					cJSON_AddStringToObject(root, "fd", fd_s);
					cJSON_AddStringToObject(root, "ip", p1->peerip);
					cJSON_AddStringToObject(root, "port", p1->peerport);
					
					char *s = cJSON_PrintUnformatted(root);
					if(s){
						send(p2->fd, s, strlen(s), 0);
						free(s);
					}
					cJSON_Delete(root);
				}
				else{
				}
			}

		}
	}
	reset_oneshot(epollfd, sockfd);
	
	//	printf("end thread receiving data on fd:%d\n", sockfd);
}

int dev_data_receiver(int dev_fd, int dev_epollfd, struct epoll_event *dev_events) {
	int ret = epoll_wait(dev_epollfd, dev_events, MAX_EVENT_NUMBER, 0);
	if(ret < 0){
		printf("epoll failed %s", strerror(errno));
		//		break;
	}

	for(int i = 0;i < ret; i++)
	{
		int sockfd = dev_events[i].data.fd;
		if(sockfd == dev_fd)
		{
			struct sockaddr_in client_address;
			socklen_t client_addrlength = sizeof(client_address);
			int connfd = accept(dev_fd, (struct sockaddr*)&client_address, &client_addrlength);

			add_oneshot_fd(dev_epollfd, connfd, true);
		}
		else if(dev_events[i].events & EPOLLIN)
		{
			pthread_t thread;

			fds *fds_for_new_worker;
			fds_for_new_worker = malloc(sizeof(fds));

			fds_for_new_worker->epollfd = dev_epollfd;
			fds_for_new_worker->sockfd = sockfd;
			fds_for_new_worker->user = 0;

			if ((pthread_create(&thread, NULL, worker, (void*)fds_for_new_worker)) == -1){
				printf("create thread fail\n");
			}

		}
		else
		{
			printf("something else happended\n");
		}
	}
}

int user_data_receiver(int user_fd, int user_epollfd, struct epoll_event *user_events) {
	int ret = epoll_wait(user_epollfd, user_events, MAX_EVENT_NUMBER, 0);
	if(ret < 0){
		printf("epoll failed %s", strerror(errno));
		//		break;
	}

	for(int i = 0;i < ret; i++)
	{
		int sockfd = user_events[i].data.fd;
		if(sockfd == user_fd)
		{
			struct sockaddr_in client_address;
			socklen_t client_addrlength = sizeof(client_address);
			int connfd = accept(user_fd, (struct sockaddr*)&client_address, &client_addrlength);

			add_oneshot_fd(user_epollfd, connfd, true);
			//			add_fd(user_epollfd, connfd, true);
		}
		else if(user_events[i].events & EPOLLIN)
		{
			pthread_t thread;

			fds *fds_for_new_worker;
			fds_for_new_worker = malloc(sizeof(fds));

			fds_for_new_worker->epollfd = user_epollfd;
			fds_for_new_worker->sockfd = sockfd;
			fds_for_new_worker->user = 1;

			if ((pthread_create(&thread, NULL, worker, (void*)fds_for_new_worker)) == -1){
				printf("create thread fail\n");
			}
		}
		else
		{
			printf("something else happended\n");
		}
	}
}


void signal_int_handler(int sig) {
	hashmap_free(devmap);
	hashmap_free(fdmap);
	exit(0);
}

void init(void) {
	devmap = hashmap_new();
	if(devmap == NULL){
		printf("devmap NULL\n");
		exit(0);
	}
	fdmap = hashmap_new();
	if(fdmap == NULL){
		printf("fdmap NULL\n");
		free(devmap);
		exit(0);
	}
	return;
}


void signal_handle(void) {
//	hashmap_iterate(fdmap, hash_free, NULL);
	signal(SIGINT, signal_int_handler);
}

int main(int argc, char* argv[]) {

	init();
	signal_handle();

	int dev_fd = listen_tcp(DEV_PORT);
	if(dev_fd < 0){
		printf("LISTEN %d FAILED:%s\n", dev_fd, strerror(errno));
		return -1;
	}

	int user_fd = listen_tcp(USER_PORT);
	if(user_fd < 0){
		printf("LISTEN %d FAILED:%s\n", user_fd, strerror(errno));
		return -1;
	}

	struct epoll_event dev_events[MAX_EVENT_NUMBER], user_events[MAX_EVENT_NUMBER];
	int dev_epollfd = epoll_create(MAX_EVENT_NUMBER);
	int user_epollfd = epoll_create(MAX_EVENT_NUMBER);

	add_fd(dev_epollfd, dev_fd, true);
	add_fd(user_epollfd, user_fd, true);

	while(1){
#if 1
		dev_data_receiver(dev_fd, dev_epollfd, dev_events);
		user_data_receiver(user_fd, user_epollfd, user_events);
		usleep(1000);
#else
		int ret = epoll_wait(user_epollfd, user_events, MAX_EVENT_NUMBER, 0);
		if(ret < 0)
		{
			printf("epoll failure \n");
		}
		lt(user_events, ret, user_epollfd, user_fd);
		//et(user_events, ret, user_epollfd, user_fd);
#endif
	}

	close(user_epollfd);
	close(user_fd);
	return 0;
}
