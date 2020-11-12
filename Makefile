all: brute thr

CFLAGS += -O2 -Wall -g
LDLIBS += -lcrypt -lpthread
