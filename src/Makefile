all: icmpcsum

CC = gcc
CFLAGS = -O2 -std=gnu99 -Wall `pkg-config --cflags libnetfilter_queue libnfnetlink`
LDLIBS = `pkg-config --libs libnetfilter_queue libnfnetlink` -lrt
