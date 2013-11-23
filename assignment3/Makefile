CC = gcc
CCFLAG = -g
C99FLAG = -std=c99
MYSQL_FLAG = `mysql_config --cflags --libs`
FUSE_FLAG = `pkg-config fuse --cflags --libs`
WALL = -Wall
D64_FLAG = -D_FILE_OFFSET_BITS=64
FUSE_USE = -DFUSE_USE_VERSION=26
MOUNT_DIR = picFS/

all:
	$(CC) $(WALL) $(CCFLAG) $(FUSE_USE) $(D64_FLAG) picFS.c -o picFS.o $(MYSQL_FLAG) $(FUSE_FLAG)
	./picFS.o $(MOUNT_DIR)

debug:
	$(CC) $(WALL) $(CCFLAG) $(FUSE_USE) $(D64_FLAG) picFS.c -o picFS.o $(MYSQL_FLAG) $(FUSE_FLAG)
	./picFS.o $(MOUNT_DIR) -d

clean:
	rm -f *.o
	fusermount -u $(MOUNT_DIR)
