/* Joe Greubel and Siddharth Choudhary - Key Pair User Lookup System - Sept 19, 2013 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/kmod.h>
#include <linux/string.h>

#define userdir "__usernames"
#define MAX_USERS 		1000
#define USERNAME_MAX_LENGTH 	40
#define PROCFS_MAX_USIZE 	8192
#define PROCFS_MAX_KEY_SIZE	4096

/* 20 character long usernames + null terminator */
static char usernameList[MAX_USERS][USERNAME_MAX_LENGTH + 1];
static int num_users = 0;

static char procfs_ufile_buffer[PROCFS_MAX_USIZE];
static char procfs_username_buffer[PROCFS_MAX_KEY_SIZE];
static unsigned long procfs_ufile_buffer_size = 0;
static unsigned long procfs_username_buffer_size=0;

struct proc_dir_entry *procfileUserList[MAX_USERS];
struct proc_dir_entry *usernameProcFile;


/*
int procfileRead(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data)
{
	int ret;

	//Get Current User and Get File Name

	if(offset > 0)
	{
		ret = 0;
	}
	else
	{
		//Check if Current_User == File_Username

		ret = sprintf(buffer, "HelloWorld!\n");
	}

	return ret;
}

 *
void keyPairFileCreation(char* username) {

	procFileList[num_users] = create_proc_entry(username, 0444, NULL);

	if(keyFile == NULL)
	{
		remove_proc_entry(username, NULL);
		return -ENOMEM;
	}

	procFileList[num_users]->read_proc = procfs_read;
	procFileList[num_users]->write_proc = .....
	procFileList[num_users]->mode = S_IFREG | S_IRUGO;
	procFileList[num_users]->uid = 0;
	procFileList[num_users]->gid = 0;
	procFileList[num_users]->size = 4096;

	username_list[num_users] = username;
}

 *
int usernamesFileRead(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{

	int ret;

	if(offset > 0)
	{
		ret = 0;
	}
	else
	{
		char* usernameBuffer = "";
		int i;
	
		for(i=0; i<num_users; i++) {
			usernameBuffer += username_list[i];
			usernameBuffer += '\n'; 
		}
		ret = sprtinf(buffer, usernameBuffer); 
	}

	return ret;

}


*
int usernamesFileWrite(struct file *file, const char *buffer, unsigned long count, void *data) {

	int len = count;
	char* = writtenData;

	if(count > 8192) len = 8192;

	if(copy_from_user(writtenData, buffer, len))
		return -EINVAL;

	//SEE WHAT USER WROTE AND ACT ACCORDINGLY

	num_users++;
	return count;
}
*/

int keyFileRead(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){
	 int ret;

         if(offset > 0)
         {
                 ret=0;
         }
         else
         {
		 memcpy(buffer, procfs_username_buffer, procfs_username_buffer_size);
		 printk(KERN_ALERT "offset username else is called\n");
                 ret = procfs_username_buffer_size;
         }
         return ret;
}

int keyFileWrite(struct file *file, const char *buffer, unsigned long count, void *data){

	procfs_username_buffer_size = count;

	if(procfs_username_buffer_size > PROCFS_MAX_USIZE){
		procfs_username_buffer_size = PROCFS_MAX_KEY_SIZE;
	}
	
	if(copy_from_user(procfs_username_buffer, buffer, procfs_username_buffer_size)){
		return -EFAULT;
	}

	return procfs_username_buffer_size;

}



int initkeyfile(char * username){
	
	int ret;
	char *envp[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL};
	char *command = (char *) kmalloc(500, GFP_KERNEL);
	char *argv[] = {"/bin/bash", "-c", command, NULL};

	command = strncat("ssh-keygen -t rsa -b 2048 -f __key -q -N \"\" | cat __key __key.pub > __temp | cat __temp > /proc/", username, USERNAME_MAX_LENGTH);
	

//	char *argv[] = {"/bin/bash", "-c", "ls -la > /__usernames", NULL};


	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);	

	printk(KERN_INFO "Inside initkeyfile and ret value is %d\n", ret);

	return 0;
}

int userCreator(char *username, int loc){

	procfileUserList[loc] = create_proc_entry(username, 0666, NULL);

	if (procfileUserList[loc] == NULL)
	{
		remove_proc_entry(username, NULL);
		return -ENOMEM;
	}

	procfileUserList[loc]->read_proc = keyFileRead;
	procfileUserList[loc]->write_proc = keyFileWrite;
	procfileUserList[loc]->mode = S_IFREG | S_IRUGO;
	procfileUserList[loc]->uid = 0;
	procfileUserList[loc]->gid = 0;
	procfileUserList[loc]->size = 4096;

	initkeyfile(username);

	return 0;
}

void bufferRipper(const char *buffer, unsigned long count){
	
	int i, usize=0;
	
	for (i=0; i<count; i++){
		if(buffer[i] == '\n'){
			usernameList[num_users][usize] = '\0';
			usize=0;
			num_users++;
		}
		else{
			usernameList[num_users][usize] = buffer[i];
			usize++;
		}
	
	}
	for (i=0; i<num_users;i++ ){
		printk(KERN_INFO "For list - %s", usernameList[i]);
		userCreator(usernameList[i], i);
	}

}


int usernamesFileRead(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){
	 int ret;

         printk(KERN_INFO "procfile_read (/proc/%s) called\n", userdir);

         if(offset > 0)
         {
                 ret=0;
         }
         else
         {
		 memcpy(buffer, procfs_ufile_buffer, procfs_ufile_buffer_size);
		 printk(KERN_ALERT "offset else is called\n");
                 ret = procfs_ufile_buffer_size;
         }
         return ret;
 }


int usernamesFileWrite(struct file *file, const char *buffer, unsigned long count, void *data){

	procfs_ufile_buffer_size = count;

	if(procfs_ufile_buffer_size > PROCFS_MAX_USIZE){
		procfs_ufile_buffer_size = PROCFS_MAX_USIZE;
	}
	
	if(num_users == 0){

		bufferRipper(buffer, count);
	}
	else {
		//some modifying function
	}


	if(copy_from_user(procfs_ufile_buffer, buffer, procfs_ufile_buffer_size)){
		return -EFAULT;
	}

	return procfs_ufile_buffer_size;

}

int inituserfile(void){
	
	char *envp[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL};
	char *argv[] = {"/bin/bash", "-c", "awk -F ':' '{ print \$1}' /etc/passwd > /proc/__usernames", NULL};
	
//	char *argv[] = {"/bin/bash", "-c", "ls -la > /__usernames", NULL};


	int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);	

	printk(KERN_INFO "Inside inituserfile and ret value is %d\n", ret);

	return 0;
}

int usernamesFileCreation(void){

	usernameProcFile = create_proc_entry(userdir, 0666, NULL);

	if (usernameProcFile == NULL)
	{
		remove_proc_entry(userdir, NULL);
		return -ENOMEM;
	}

	usernameProcFile->read_proc = usernamesFileRead;
	usernameProcFile->write_proc = usernamesFileWrite;
	usernameProcFile->mode = S_IFREG | S_IRUGO;
	usernameProcFile->uid = 0;
	usernameProcFile->gid = 0;
	usernameProcFile->size = 8192;

	inituserfile();
	
	return 0;
}

int init_module()
{
	usernamesFileCreation();
	return 0;
}

void cleanup_module()
{
	int i;
	for(i=0; i<num_users; i++) {
		char* username = usernameList[i];
		remove_proc_entry(username, NULL);
	}

	remove_proc_entry(userdir, NULL);
}
