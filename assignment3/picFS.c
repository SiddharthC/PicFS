#include "picFS.h"

FILE *log_file;

//******************************************************************************//
//  *************************  HANDLER FUNCTIONS  ****************************  //
//******************************************************************************//
static int picFS_mkdir(const char *path, mode_t mode){
	log_file = fopen("fuse_log.log", "a");
	fprintf(log_file, "In mkdir\n");

	path_struct *ps = parsePath(path);

	//Gets file name from path
	char file_name[MAX_FILENAME_LENGTH];
	strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);
	fprintf(log_file, "The filename is %s", file_name);

	//Get parent path
	char parent_path[1000];
	getParentPath(ps, parent_path);

	struct fuse_context *fc = fuse_get_context();

	char query[200];
	//TODO fix mode_t
	sprintf(query,  "insert into file_table (file_name, path, perm_unix, perm_acl,"
				"owner_name, size, file_type, file_data, nlink)  values(\"%s\",\"%s\", %u32,\"\", %d, 0, 0, \"hello\",2);", file_name, parent_path, 
				mode, fc->uid);
	fprintf(log_file, "query executed -- %s\n", query);
	if (mysql_query(con, query)){
		fprintf(stdout, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);
	}

	fclose(log_file);
	return 0;

}

static int picFS_rmdir(const char *path){
	return 0;
}
static int picFS_rename(const char *path, const char *name){
	return 0;
}
static int picFS_chmod(const char *path, mode_t mode){
	return 0;
}
static int picFS_setxattr(const char *path, const char *attr, const char *input, size_t input_size, int flags){
	return 0;
}
static int picFS_getxattr(const char *path, const char *attr, char *output, size_t output_size){
	return 0;
}
static int picFS_removexattr(const char *path, const char *attr){
	return 0;
}
static int picFS_create(const char *path, mode_t mode, struct fuse_file_info *fi){
	log_file = fopen("fuse_log.log", "a");
	fprintf(log_file, "In create\n");

	path_struct *ps = parsePath(path);

	//Gets file name from path
	char file_name[MAX_FILENAME_LENGTH];
	strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);
	fprintf(log_file, "The filename is %s", file_name);

	//Get parent path
	char parent_path[1000];
	getParentPath(ps, parent_path);

	struct fuse_context *fc = fuse_get_context();

	char query[200];
	sprintf(query,  "insert into file_table (file_name, path, perm_unix, perm_acl,"
				"owner_name, size, file_type, file_data, nlink)  values(\"%s\",\"%s\", %u32,\"\", %d, 0, 0, \"hello\",1);", file_name, parent_path, 
				mode, fc->uid);
	fprintf(log_file, "query executed -- %s\n", query);
	if (mysql_query(con, query)){
		fprintf(stdout, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);
	}

	fclose(log_file);
	return 0;
}

static int picFS_getattr(const char *path, struct stat *stbuf) {
    int res = 0;
    memset(stbuf, 0, sizeof(struct stat));
    
    if(strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0666;
		stbuf->st_nlink = 2;
    }
    else if(strcmp(path, hello_path) == 0) {
		stbuf->st_mode = S_IFREG | 0666;
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

    	filler(buf, ".", NULL, 0);
    	filler(buf, "..", NULL, 0);
    
	//Read all files in that path

    	log_file = fopen("fuse_log.log", "a");
	fprintf(log_file, "In readdir\n");


	char query[200];
	sprintf(query,  "select file_name from file_table where path=\"%s\";", path);
	fprintf(log_file, "query executed -- %s\n", query);
	if (mysql_query(con, query)){
		fprintf(stdout, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);
	}

	MYSQL_RES *result = mysql_store_result(con);

	if(result == NULL){
		fprintf(stdout, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);	
	}

	MYSQL_ROW row;

	while((row = mysql_fetch_row(result))){
		filler(buf, row[0], NULL, 0);
	}


	fclose(log_file);
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
    //size_t len;
    (void) fi;
    
    if(strcmp(path, hello_path) != 0)
		return -ENOENT;

    memcpy(buf, buffer, 19);

/*
    len = strlen(hello_str);
    if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, hello_str + offset, size);
    } 
    else
		size = 0;

	return size;
*/
    return 20;
}


static int picFS_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	memcpy(buffer, buf, 19);
	return 20;
}

void picFS_destroy(void *s) {
	mysql_close(con);
}

//**********************************************************************//
//  ***********************   MAIN BELOW   ************** ************  //
//*********************************************************************//
 
//Database functions
void database_initializer(void){
	con = mysql_init(NULL);

	if(con == NULL){
		fprintf(stdout, "%s\n", mysql_error(con));
		exit(1);
	}

	if(mysql_real_connect(con, "127.0.0.1", "root", "fire", NULL, 0, NULL, 0) == NULL){
		fprintf(stdout, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);
	}

	//Create Database
	if (mysql_query(con, "CREATE DATABASE IF NOT EXISTS picFS_db;")){
		fprintf(stdout, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);
	}

	if (mysql_query(con, "USE picFS_db;")){
		fprintf(stdout, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);
	}

	//TODO remember to change file_data to longblob
	if (mysql_query(con, "create table if not exists file_table (file_name varchar(200), path varchar(2000), perm_unix int,"
				"perm_acl varchar(200), owner_name int, size int, file_type int, file_data varchar(200), nlink int); ")){
		fprintf(stdout, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);
	}
}

path_struct * parsePath(const char* path) {
	char * tmp = NULL;
	path_struct * ps;

	ps = (path_struct*)malloc(sizeof(path_struct));
	ps->depth = 0;
	
	if(!strcmp(path,"/"))
		return ps;
	
	tmp = strtok(path, "/");
	while(tmp != NULL) {
		ps->path_parts[ps->depth] = (char*)malloc(MAX_FILENAME_LENGTH*sizeof(char));
		strcpy(ps->path_parts[ps->depth++],tmp);
		tmp = strtok(NULL, "/");
	}

	return ps;
}

void getParentPath(path_struct * ps, char * buf) {
	int i;

	if(ps->depth < 2) {
		strcpy(buf, "/\0");
		return;
	}

	strcpy(buf, ps->path_parts[0]);
	strcat(buf, "/");
	for(i=1;i<ps->depth-1;i++) {
		strcat(buf, ps->path_parts[i]);
		strcat(buf, "/");
	}
}

void freePathStruct(path_struct * ps) {
	int i;
	for(i=0; i<ps->depth; i++)
		free(ps->path_parts[i]);
	free(ps);
}

int main(int argc, char *argv[]) {

	//Initialize Database
	database_initializer();
	
	//Start Fuse
	return fuse_main(argc, argv, &picFS_oper, NULL);
}
