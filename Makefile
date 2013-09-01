SRC=rso.cpp
OBJS=rso.o
CC=g++
LD=g++
#CC=clang++ -v
#LD=clang++
CFLAGS=-D__IDP__ -D__PLUGIN__ -c -D__LINUX__ \
	   -I/usr/local/idaadv/sdk/include $(SRC)
LDFLAGS=--shared $(OBJS) -L/usr/local/idaadv -lida \
		-Wl,--version-script=./plugin.script
all:
	$(CC) $(CFLAGS)
	$(LD) $(LDFLAGS) -o rso.llx

clean:
	rm -f rso.llx rso.o

install:
	sudo cp rso.llx /usr/local/idaadv/loaders

remove:
	sudo rm -f /usr/local/idaadv/loaders/rso.llx

