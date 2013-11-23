#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <mysql.h>
#include <stdlib.h>

#define MAX_FILENAME_LENGTH 30

//MYSQL connection pointer
MYSQL *con;

static const char *hello_str = "Hello World!\n";
static const char *hello_path = "/hello";

static char buffer[20];
 
//Handler function
static int picFS_getattr(const char *path, struct stat *stbuf);
static int picFS_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
static int picFS_open(const char *path, struct fuse_file_info *fi);
static int picFS_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int picFS_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int picFS_mkdir(const char *, mode_t);
static int picFS_rmdir(const char *);
static int picFS_rename(const char *, const char *);
static int picFS_chmod(const char *, mode_t);
static int picFS_setxattr(const char *, const char *, const char *, size_t, int);
static int picFS_getxattr(const char *, const char *, char *, size_t);
static int picFS_removexattr(const char *, const char *);
static int picFS_create(const char *, mode_t, struct fuse_file_info *);
void picFS_destroy(void *s);

void database_initializer(void);

static struct fuse_operations picFS_oper = {
    .getattr 		= picFS_getattr,
    .mkdir 		= picFS_mkdir,
    .rmdir 		= picFS_rmdir,
    .rename 		= picFS_rename,
    .chmod	 	= picFS_chmod,
    .readdir 		= picFS_readdir,
    .open    		= picFS_open,
    .read    		= picFS_read,
    .write   		= picFS_write,
    .setxattr	 	= picFS_setxattr,
    .getxattr 		= picFS_getxattr,
    .removexattr 	= picFS_removexattr,
    .create 		= picFS_create,
    .destroy 		= picFS_destroy
};

typedef struct path_struct_t {
	int depth; //0 = root, all others true
	char *path_parts[MAX_FILENAME_LENGTH];
} path_struct;

path_struct * parsePath(const char*);
void freePathStruct(path_struct *);
void getParentPath(path_struct * ps, char * buf);
