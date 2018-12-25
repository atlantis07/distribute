.PHONY: all clean

all: server user dev1 dev2

CC = gcc
AR = ar
CFLAGS = -g
FLAGS = -s 

LD = hashmap.c epoll.c cJSON.c
LD_THREAD = -lpthread
LD_MATH = -lm
server: server.c
	$(CC) server.c $(CFLAGS) $(LD) $(LD_THREAD) $(LD_MATH) -o server

dev1: dev1.c
	$(CC) $(CFLAGS) $(LD) $(LD_THREAD) $(LD_MATH) dev1.c -o dev1

dev2: dev2.c
	$(CC) $(CFLAGS) $(LD) $(LD_THREAD) $(LD_MATH) dev2.c -o dev2

user: user.c
	$(CC) user.c $(CFLAGS) $(LD) $(LD_THREAD) $(LD_MATH) -o user

clean:
	rm -f server dev1 dev2 user user2 *.o
