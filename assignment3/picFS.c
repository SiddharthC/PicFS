  #include <fuse.h>
  #include <stdio.h>
  #include <string.h>
  #include <errno.h>
  #include <fcntl.h>
#include <mysql.h>

  //#define FUSE_USE_VERSION  26
  
  static const char *hello_str = "Hello World!\n";
  static const char *hello_path = "/hello";

//******************************************************************************//
//  *************************  HANDLER FUNCTIONS  ****************************  //
//******************************************************************************//
  static int picFS_getattr(const char *path, struct stat *stbuf) {
    int res = 0;
    memset(stbuf, 0, sizeof(struct stat));
    
    if(strcmp(path, "/") == 0) {
	stbuf->st_mode = S_IFDIR | 0755;
	stbuf->st_nlink = 2;
    }
    else if(strcmp(path, hello_path) == 0) {
	stbuf->st_mode = S_IFREG | 0444;
	stbuf->st_nlink = 1;
	stbuf->st_size = strlen(hello_str);
    }
    else
	res = -ENOENT;
    
    return res;
  }
  
  static int picFS_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    (void) offset;
    (void) fi;

    if(strcmp(path, "/") != 0)
	return -ENOENT;		       
    
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, hello_path + 1, NULL, 0);

    return 0;
  }
  
  static int picFS_open(const char *path, struct fuse_file_info *fi) {
    if(strcmp(path, hello_path) != 0)
        return -ENOENT;

    if((fi->flags & 3) != O_RDONLY)
	return -EACCES;
   
    return 0;
  }
  
  static int picFS_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    size_t len;
    (void) fi;
    
    if(strcmp(path, hello_path) != 0)
	return -ENOENT;

    len = strlen(hello_str);
    if (offset < len) {
	if (offset + size > len)
		size = len - offset;
	memcpy(buf, hello_str + offset, size);
    } 
    else
	size = 0;

    return size;
  }


//**********************************************************************//
//  ***********************   MAIN BELOW   ************** ************  //
//*********************************************************************//
  static struct fuse_operations picFS_oper = {
    .getattr = picFS_getattr,
    .readdir = picFS_readdir,
    .open    = picFS_open,
    .read    = picFS_read,
  };
  
//Database functions
void database_initializer(void){
	MYSQL *con = mysql_init(NULL);

	if(con == NULL){
		fprintf(stderr, "%s\n", mysql_error(con));
		exit(1);
	}

	if(mysql_real_connect(con, "192.168.5.1", "root", "fire", NULL, 0, NULL, 0) == NULL){
		fprintf(stderr, "%s\n", mysql_error(con));
		mysql_close(con)
		exit(1);
	}

	if (mysql_query(con, "CREATE DATABASE testdb")){
		fprintf(stderr, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);
	}
	
	mysql_close(con);
//	exit(0);
}

int main(int argc, char *argv[]) {
	
	database_initializer();

	return fuse_main(argc, argv, &picFS_oper, NULL);
}
