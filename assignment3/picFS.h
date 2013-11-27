#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <mysql.h>
#include <stdlib.h>
#include <time.h>

#define MAX_FILENAME_LENGTH 30
#define MAX_PATH_LENGTH 1000
#define QUERY_LENGTH 3000
#define MAX_ACL_SIZE 1000
#define MAX_FILE_SIZE 4194304
#define PICFS_PASSWORD "MY_PICFS_PASSWORD"

//MYSQL connection pointer
MYSQL *con;
 
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
static int picFS_access(const char *, int);
static int picFS_unlink(const char *);
static int picFS_utimens(const char*, const struct timespec tv[2]);
static int picFS_truncate(const char*, off_t);
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
    .access		= picFS_access,
    .unlink 		= picFS_unlink,
    .utimens		= picFS_utimens,
    .truncate		= picFS_truncate,
    .destroy 		= picFS_destroy
};

typedef struct path_struct_t {
	int depth; //0 = root, all others true
	char *path_parts[MAX_FILENAME_LENGTH];
} path_struct;

path_struct * parsePath(const char*);
void freePathStruct(path_struct *);
void getParentPath(path_struct * ps, char * buf);
