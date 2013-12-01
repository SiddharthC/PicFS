#include "picFS.h"

#define TIME (int)time(NULL)

//******************************************************************************//
//  *************************  HANDLER FUNCTIONS  ****************************  //
//******************************************************************************//

static int picFS_mkdir(const char *path, mode_t mode){
	path_struct *ps = parsePath(path);

	char file_name[MAX_FILENAME_LENGTH];
	strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);

	if(strcmp(file_name, "/") == 0)
		return -EBADF;

	char parent_path[MAX_PATH_LENGTH];
	getParentPath(ps, parent_path);

	struct fuse_context *fc = fuse_get_context();

	char query[QUERY_LENGTH];
	sprintf(query,  "INSERT INTO file_table (file_name, path, perm_unix, perm_acl, owner, gid, size, file_data, nlink, " 
			"ctime, mtime) VALUES (\"%s\", \"%s\", %u, \"\", %d, %d, 4096, \"Directory\", 2, %d, %d);", 
			file_name, parent_path, mode | S_IFDIR, fc->uid, fc->gid, TIME, TIME);
	
	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}

	//UPDATE PARENT DIRECTORY NLINK + 1
	path_struct *ps1 = parsePath(parent_path);
	if(ps1->depth == 0) {
		sprintf(query,  "UPDATE file_table SET nlink = nlink + 1 WHERE file_name=\"/\";"); 
	}
	else {
		char ppath[MAX_PATH_LENGTH];
		getParentPath(ps1, ppath);
		sprintf(query,  "UPDATE file_table SET nlink = nlink + 1 WHERE file_name=\"%s\" AND path=\"%s\";",
				ps1->path_parts[ps1->depth-1], ppath); 
	}

	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}

	freePathStruct(ps1);
	freePathStruct(ps);
	return 0;

}

static int picFS_rmdir(const char *path){
	//Check if any files in this Directory
	char query[QUERY_LENGTH];
	sprintf(query, "SELECT COUNT(*) FROM file_table WHERE path=\"%s\";", path);	
	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}
	MYSQL_RES *result = mysql_store_result(con);
	MYSQL_ROW row = mysql_fetch_row(result);
	if(atoi(row[0]) != 0)
		return -EBADF;
	
	path_struct *ps = parsePath(path);

	char file_name[MAX_FILENAME_LENGTH];
	strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);

	if(strcmp(file_name, "/") == 0)
		return -EBADF;

	char parent_path[MAX_PATH_LENGTH];
	getParentPath(ps, parent_path);

	sprintf(query, "DELETE FROM file_table WHERE file_name=\"%s\" AND path=\"%s\";", file_name, parent_path); 
	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}

	//UPDATE PARENT DIRECTORY NLINK - 1
	path_struct *ps1 = parsePath(parent_path);
	if(ps1->depth == 0) {
		sprintf(query,  "UPDATE file_table SET nlink = nlink - 1 WHERE file_name=\"/\";"); 
	}
	else {
		char ppath[MAX_PATH_LENGTH];
		getParentPath(ps1, ppath);
		sprintf(query,  "UPDATE file_table SET nlink = nlink - 1 WHERE file_name=\"%s\" AND path=\"%s\";",
				ps1->path_parts[ps1->depth-1], ppath); 
	}

	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}

	freePathStruct(ps1);
	freePathStruct(ps);
	return 0;
}

static int picFS_rename(const char *path, const char *name){
	if(strcmp(path, "/") == 0)
		return -EBADF;
	
	path_struct *ps = parsePath(path);
	
	char file_name[MAX_FILENAME_LENGTH];
	strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);
	
	char parent_path[MAX_PATH_LENGTH];
	getParentPath(ps, parent_path);
	
	char query[QUERY_LENGTH];
	sprintf(query, "SELECT perm_unix FROM file_table WHERE file_name=\"%s\" AND path=\"%s\";",
			file_name, parent_path);	
	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}
	MYSQL_RES *result = mysql_store_result(con);
	MYSQL_ROW row = mysql_fetch_row(result);

	if(atoi(row[0]) & S_IFREG) { //FILE
		sprintf(query, "UPDATE file_table SET file_name=\"%s\", mtime=%d WHERE file_name=\"%s\" AND path=\"%s\";",
			name+1, TIME, file_name, parent_path);
		if (mysql_query(con, query)){
			mysql_close(con);
			exit(1);
		}
	}
	
	freePathStruct(ps);
	return 0;
}

static int picFS_chmod(const char *path, mode_t mode){
	if(strcmp(path, "/") == 0)
		return -EBADF;
	
	path_struct *ps = parsePath(path);
	char file_name[MAX_FILENAME_LENGTH];
	strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);
	char parent_path[MAX_PATH_LENGTH];
	getParentPath(ps, parent_path);
	
	char query[QUERY_LENGTH];
	sprintf(query, "UPDATE  file_table SET perm_unix = %d, mtime=%d WHERE file_name=\"%s\" AND path=\"%s\";",
			mode, TIME,  file_name, parent_path);	
	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}

	freePathStruct(ps);
	return 0;
}

static int picFS_create(const char *path, mode_t mode, struct fuse_file_info *fi){
	path_struct *ps = parsePath(path);

	char file_name[MAX_FILENAME_LENGTH];
	strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);

	if(strcmp(file_name, "/") == 0)
		return -EBADF;

	char parent_path[MAX_PATH_LENGTH];
	getParentPath(ps, parent_path);

	struct fuse_context *fc = fuse_get_context();

	char query[QUERY_LENGTH];
	sprintf(query,  "INSERT INTO file_table (file_name, path, perm_unix, perm_acl, owner, gid, size, file_data, nlink, " 
			"ctime, mtime) VALUES (\"%s\", \"%s\", %u, \"\", %d, %d, 0, \"\", 1, %d, %d);", 
			file_name, parent_path, mode, fc->uid, fc->gid, TIME, TIME);
	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}
	
	freePathStruct(ps);
	return 0;
}

static int picFS_unlink(const char * path) {
	path_struct *ps = parsePath(path);

	char file_name[MAX_FILENAME_LENGTH];
	strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);

	char parent_path[MAX_PATH_LENGTH];
	getParentPath(ps, parent_path);

	char query[QUERY_LENGTH];
	sprintf(query,  "DELETE FROM file_table WHERE file_name=\"%s\" AND path=\"%s\";",
			file_name, parent_path);
	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}
	
	freePathStruct(ps);
	return 0;
}

static int picFS_getattr(const char *path, struct stat *stbuf) {
	int res = 0;
	memset(stbuf, 0, sizeof(struct stat));

	if(strcmp(path, "/") == 0) {
		char query[QUERY_LENGTH];
		sprintf(query, "SELECT perm_unix, nlink, size, owner, gid, ctime, mtime FROM file_table WHERE file_name = \"/\";");
		if (mysql_query(con, query)){
			mysql_close(con);
			exit(1);
		}
		MYSQL_RES *result = mysql_store_result(con);
		MYSQL_ROW row = mysql_fetch_row(result);

		stbuf->st_mode  = atoi(row[0]);
		stbuf->st_nlink = atoi(row[1]);
		stbuf->st_size  = atoi(row[2]);
		stbuf->st_uid   = atoi(row[3]);
		stbuf->st_gid   = atoi(row[4]);
		stbuf->st_ctime = atoi(row[5]);
		stbuf->st_mtime = atoi(row[6]);
		res = 0;
	}
	else {
		path_struct *ps = parsePath(path);
	
		char file_name[MAX_FILENAME_LENGTH];
		strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);
	
		char parent_path[MAX_PATH_LENGTH];
		getParentPath(ps, parent_path);
	
		char query[QUERY_LENGTH];
		sprintf(query,  "SELECT perm_unix, nlink, size, owner, gid, ctime, mtime FROM file_table "
				"WHERE path=\"%s\" AND file_name=\"%s\";",
				parent_path, file_name);
		if (mysql_query(con, query)){
			mysql_close(con);
			exit(1);
		}
	
		MYSQL_RES *result = mysql_store_result(con);
		if(result == NULL){
			mysql_close(con);
			exit(1);	
		}
	
		int numRows = mysql_num_rows(result);
		if(numRows == 0) { 
			res = -ENOENT;
		}
		else {
			MYSQL_ROW row;
			if(!(row = mysql_fetch_row(result))) {
				mysql_close(con);
				exit(1);
			}

			stbuf->st_mode  = atoi(row[0]);
			stbuf->st_nlink = atoi(row[1]);
			stbuf->st_size  = atoi(row[2]);
			stbuf->st_uid   = atoi(row[3]);
			stbuf->st_gid   = atoi(row[4]);
			stbuf->st_ctime = atoi(row[5]);
			stbuf->st_mtime = atoi(row[6]);
			res = 0;
		}
		freePathStruct(ps);
	}
    	return res;
}

static int picFS_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    	(void) offset;
    	(void) fi;

	filler(buf, ".", NULL, 0);
    	filler(buf, "..", NULL, 0);

	char query[QUERY_LENGTH];
	sprintf(query,  "SELECT file_name, perm_unix, perm_acl, owner, gid, nlink FROM file_table WHERE path=\"%s\";", path);
	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}
	
	MYSQL_RES *result = mysql_store_result(con);
	if(result == NULL){
		mysql_close(con);
		exit(1);	
	}

	struct fuse_context *fc = fuse_get_context();
	MYSQL_ROW row;
	while((row = mysql_fetch_row(result))){
		int nlink = atoi(row[5]);
		if(nlink > 1){	
			filler(buf, row[0], NULL, 0);
			continue;
		}

		int perm_unix = atoi(row[1]);
		char perm_acl[MAX_ACL_SIZE];
		strcpy(perm_acl, row[2]);
		int flag = -1;

		if(fc->uid == atoi(row[3])) { //OWNER
			if(perm_unix & S_IRUSR)	{
				if(perm_unix & S_IWUSR) flag = O_RDWR;
				else flag = O_RDONLY;
			}
			else {
				if(perm_unix & S_IWUSR) flag = O_WRONLY;
			}
		}
		else if(fc->gid == atoi(row[4])) { //GROUP
			if(perm_unix & S_IRGRP)	{
				if(perm_unix & S_IWGRP) flag = O_RDWR;
				else flag = O_RDONLY;
			}
			else {
				if(perm_unix & S_IWGRP) flag = O_WRONLY;
			}
		} 
		else { //OTHER
			if(perm_unix & S_IROTH)	{
				if(perm_unix & S_IWOTH){
					flag = O_RDWR;
				}
				else flag = O_RDONLY;	
			}
			else {
				if(perm_unix & S_IWOTH) flag = O_WRONLY;
				else {// TODO check acl
				
				}
			}
		}

		if(flag != -1)
			filler(buf, row[0], NULL, 0);
	}

	return 0;
}
  
static int picFS_open(const char *path, struct fuse_file_info *fi) {	
	struct fuse_context *fc = fuse_get_context();
	path_struct *ps = parsePath(path);

	char file_name[MAX_FILENAME_LENGTH];
	strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);
	
	char parent_path[MAX_PATH_LENGTH];
	getParentPath(ps, parent_path);

	char query[QUERY_LENGTH];
	sprintf(query,  "SELECT perm_unix, perm_acl, owner, gid FROM file_table WHERE path=\"%s\" AND file_name=\"%s\";",
			parent_path, file_name);
	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}
	MYSQL_RES *result = mysql_store_result(con);
	MYSQL_ROW row = mysql_fetch_row(result);

	int perm_unix = atoi(row[0]);
	char perm_acl[MAX_ACL_SIZE];
	strcpy(perm_acl, row[1]);
	int flag = 0;

	if(fc->uid == atoi(row[2])) { //OWNER
		if(perm_unix & S_IRUSR)	{
			if(perm_unix & S_IWUSR) flag = O_RDWR;
			else flag = O_RDONLY;
		}
		else {
			if(perm_unix & S_IWUSR) flag = O_WRONLY;
		}
	}
	else if(fc->gid == atoi(row[3])) { //GROUP
		if(perm_unix & S_IRGRP)	{
			if(perm_unix & S_IWGRP) flag = O_RDWR;
			else flag = O_RDONLY;
		}
		else {
			if(perm_unix & S_IWGRP) flag = O_WRONLY;
		}
	} 
	else { //OTHER
		if(perm_unix & S_IROTH)	{
			if(perm_unix & S_IWOTH) flag = O_RDWR;
			else flag = O_RDONLY;
		}
		else {
			if(perm_unix & S_IWOTH) flag = O_WRONLY;
			else {
				//TODO: Check perm_acl string here to see if this specific uid/gid has access, set flag accordingly
			}
		}
	}

	//fprintf(stdout, "File Name - %s, fi->flags - %x, flag - %x", file_name, fi->flags, flag);

	freePathStruct(ps);

	if(flag == O_RDWR) {
		if((fi->flags&3) == O_RDONLY || (fi->flags&3) == O_WRONLY) return 0;
	}
	if((fi->flags&3) == flag) return 0;
	return -EACCES;
}

//4MB File Buffer
char file_buffer[MAX_FILE_SIZE];
int file_size;

static int picFS_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	if(size == 0 || offset < 0)
		return 0;
	
	char *temp_buffer;
	path_struct *ps = parsePath(path);
	char file_name[MAX_FILENAME_LENGTH];
	strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);
	char parent_path[MAX_PATH_LENGTH];
	getParentPath(ps, parent_path);
	
	//DECRYPTION done
	char query[QUERY_LENGTH];
	sprintf(query,  "SELECT DECODE(file_data, \"%s\"), size FROM file_table WHERE path=\"%s\" AND file_name=\"%s\";",
		PICFS_PASSWORD, parent_path, file_name);
	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}
	MYSQL_RES *result = mysql_store_result(con);
	MYSQL_ROW row = mysql_fetch_row(result);
	
	//Allocating temporary buffer
	temp_buffer = (char *)calloc(MAX_FILE_SIZE, sizeof(char));
	strcpy(temp_buffer, row[0]);
	file_size = atoi(row[1]);
	freePathStruct(ps);
	
   	 if (offset < file_size-1) {
		if (size > file_size)
			size = file_size;
		if (offset + size > file_size)
			size = file_size-offset;
		memcpy(buf, temp_buffer + offset, size);
		return size;
    	} 
    	else {
		file_size = 0;
		return 0;
	}
}

static int picFS_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	if(size ==0 || offset < 0)
		return 0;

	char query[QUERY_LENGTH];
	memset(query, 0, QUERY_LENGTH);
	path_struct *ps = parsePath(path);
	char file_name[MAX_FILENAME_LENGTH];
	strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);
	char parent_path[MAX_PATH_LENGTH];
	getParentPath(ps, parent_path);
	int file_size;
	char *temp_buffer;
	
	temp_buffer = (char *)  calloc((size + 1), sizeof(char));
	mysql_real_escape_string(con, temp_buffer, buf, (size+1));

	//ENCRYPTION done
	if(offset == 0) {

		sprintf(query,  "UPDATE file_table SET file_data=ENCODE(\"%s\",\"%s\"), size=%zu WHERE path=\"%s\" AND file_name=\"%s\";",
			temp_buffer, PICFS_PASSWORD, size, parent_path, file_name);


	}
	else {/*
		fprintf(stdout, "failed before first query\n");
		//DECRYPTION done
		sprintf(query,  "SELECT DECODE(file_data, \"%s\") , size FROM file_table WHERE path=\"%s\" AND file_name=\"%s\";",
			PICFS_PASSWORD, parent_path, file_name);
		if (mysql_query(con, query)){
			mysql_close(con);
			exit(1);
		}
		MYSQL_RES *result = mysql_store_result(con);
		MYSQL_ROW row = mysql_fetch_row(result);
		temp_buffer = (char *)calloc(MAX_FILE_SIZE, sizeof(char));
		strcpy(temp_buffer, row[0]);
		file_size = atoi(row[1]);

		//Make the new buffer
		if(offset > file_size - 1 )
			offset = 0;
		strcpy(temp_buffer + offset, buf );

		if(offset == 0)
			file_size = size;
		if((offset + size) > file_size)
			file_size = offset + size;

		fprintf(stdout, "Failed before second query\n");
		//ENCRYPTION done
		sprintf(query,  "UPDATE file_table SET file_data=ENCODE(\"%s\", \"%s\"), size=size+%d WHERE path=\"%s\" AND file_name=\"%s\";",
				temp_buffer, PICFS_PASSWORD, file_size, parent_path, file_name);
				*/
		//ENCRYPTION done
		sprintf(query,  "UPDATE file_table SET file_data=concat(file_data, ENCODE(\"%s\", \"%s\")), size=size+%d WHERE path=\"%s\" AND file_name=\"%s\";",
				temp_buffer, PICFS_PASSWORD, size, parent_path, file_name);
	
	}
	if (mysql_real_query(con, query, QUERY_LENGTH)){
		fprintf(stdout, "mysql connection closed\n");
		fprintf(stdout, "The query is -- %s\n", query);
		fflush(stdout);
		mysql_close(con);
		exit(1);
	}
	freePathStruct(ps);
	return size ;
}

//Command Line -> setfattr -n u:501:rw -h picFS/filepath
static int picFS_setxattr(const char *path, const char *attr, const char *input, size_t input_size, int flags){
	fprintf(stdout, "IN SETXATTR: attr = %s\n", attr);
	//TODO append attr to the perm_acl string for the specific file
	return 0;
}

//Command Line -> setfattr -x u:501:rw -h picFS/filepath
static int picFS_removexattr(const char *path, const char *attr){
	fprintf(stdout, "IN REMOVEXATTR: attr = %s\n", attr);
	//TODO search through perm_acl string and remove attr if it is present
	return 0;
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/
static int picFS_access(const char* path, int flags) {

	if(path[1] == '\0')
		return 0;
	
	struct fuse_context *fc = fuse_get_context();
	path_struct *ps = parsePath(path);

	char file_name[MAX_FILENAME_LENGTH];
	strncpy(file_name, ps->path_parts[ps->depth - 1], MAX_FILENAME_LENGTH);
	
	char parent_path[MAX_PATH_LENGTH];
	getParentPath(ps, parent_path);

	char query[QUERY_LENGTH];
	sprintf(query,  "SELECT perm_unix, perm_acl, owner, gid FROM file_table WHERE path=\"%s\" AND file_name=\"%s\";",
			parent_path, file_name);
	if (mysql_query(con, query)){
		mysql_close(con);
		exit(1);
	}
	MYSQL_RES *result = mysql_store_result(con);
	MYSQL_ROW row = mysql_fetch_row(result);

	int perm_unix = atoi(row[0]);
	char perm_acl[MAX_ACL_SIZE];
	strcpy(perm_acl, row[1]);
	int flag = -1;

	if(fc->uid == atoi(row[2])) { //OWNER
		if(perm_unix & S_IRUSR)	{
			if(perm_unix & S_IWUSR) flag = O_RDWR;
			else flag = O_RDONLY;
		}
		else {
			if(perm_unix & S_IWUSR) flag = O_WRONLY;
		}
	}
	else if(fc->gid == atoi(row[3])) { //GROUP
		if(perm_unix & S_IRGRP)	{
			if(perm_unix & S_IWGRP) flag = O_RDWR;
			else flag = O_RDONLY;
		}
		else {
			if(perm_unix & S_IWGRP) flag = O_WRONLY;
		}
	} 
	else { //OTHER
		if(perm_unix & S_IROTH)	{
			if(perm_unix & S_IWOTH) flag = O_RDWR;
			else flag = O_RDONLY;
		}
		else {
			if(perm_unix & S_IWOTH) flag = O_WRONLY;
			else {
				//TODO: Check perm_acl string here to see if this specific uid/gid has access, set flag accordingly
			}
		}
	}

	freePathStruct(ps);
	
	fprintf(stdout, "flag is %x\n", flag);
	fflush(stdout);

	if(flag == -1)
		return -EACCES;
	
	return 0;
}

static int picFS_getxattr(const char *path, const char *attr, char *output, size_t output_size){
	//DOES NOT NEED IMPLEMENT
	return 0;
}

static int picFS_utimens(const char* path, const struct timespec tv[2]) {
	//DOES NOT NEED IMPLEMENT
	return 0;
}

static int picFS_truncate(const char* path, off_t offset) {
	//DOES NOT NEED IMPLEMENT
	return 0;
}

void picFS_destroy(void *s) {
	mysql_close(con);
}
//**********************************************************************//
//  ***********************   MAIN BELOW   ************** ************  //
//*********************************************************************//
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

	//Create File Table
	if (mysql_query(con, "CREATE TABLE IF NOT EXISTS file_table (file_name VARCHAR(200), path VARCHAR(2000), perm_unix INT, "
				"perm_acl VARCHAR(200), owner INT, gid INT, size INT, file_data LONGBLOB, nlink INT, "
				"ctime BIGINT, mtime BIGINT);")){
		fprintf(stdout, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);
	}

	//Insert Root Directory
	if(mysql_query(con, "SELECT * FROM file_table WHERE file_name = \"/\";")) {
		fprintf(stdout, "%s\n", mysql_error(con));
		mysql_close(con);
		exit(1);
	}
	MYSQL_RES *result = mysql_store_result(con);

	if(mysql_num_rows(result) == 0) {
		char query[QUERY_LENGTH];
		sprintf(query, "INSERT INTO file_table (file_name, path, perm_unix, perm_acl, owner, gid, size, file_data, nlink, "
			"ctime, mtime) VALUES (\"/\", \"MOUNT\", %u, \"NONE\", 0, 0, 4096, \"Root Directory\", 2, %d, %d);",
			0777 | S_IFDIR, TIME, TIME);
		if (mysql_query(con, query)){
			fprintf(stdout, "%s\n", mysql_error(con));
			mysql_close(con);
			exit(1);
		}
	}
}

path_struct * parsePath(const char* path) {
	char * tmp = NULL;
	path_struct * ps;

	ps = (path_struct*)malloc(sizeof(path_struct));
	ps->depth = 0;
	
	if(!strcmp(path,"/"))
		return ps;
	
	tmp = strtok((char *) path, "/");
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

	strcpy(buf, "/");
	strcat(buf, ps->path_parts[0]);
	for(i=1;i<ps->depth-1;i++) {
		strcat(buf, "/");
		strcat(buf, ps->path_parts[i]);
	}
}

void freePathStruct(path_struct * ps) {
	int i;
	for(i=0; i<ps->depth; i++)
		free(ps->path_parts[i]);
	free(ps);
}

int main(int argc, char *argv[]) {
	database_initializer();
	return fuse_main(argc, argv, &picFS_oper, NULL);
}
