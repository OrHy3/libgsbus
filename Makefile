CC = gcc
CFLAGS = -I/usr/include/dbus-1.0 -I/lib64/dbus-1.0/include
LDFLAGS = -ldbus-1

all: session
session: session.o
