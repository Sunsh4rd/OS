all: thr brute

CFLAGS += -O2 -Wall -g
LDLIBS += -lcrypt -lpthread
