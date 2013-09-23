/* Joe Greubel and Siddharth Choudhary - Key Pair User Lookup System - Sept 19, 2013 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/kmod.h>
#include <linux/string.h>
#include <linux/current.h>

#define userdir "__usernames"
#define MAX_USERS 		1000
#define USERNAME_MAX_LENGTH 	40
#define PROCFS_MAX_USIZE 	8192
#define PROCFS_MAX_KEY_SIZE	4096

/* 20 character long usernames + null terminator */
static char usernameList[MAX_USERS][USERNAME_MAX_LENGTH + 1];
static int num_users = 0;
static char command[MAX_USERS][500];

static char procfs_ufile_buffer[PROCFS_MAX_USIZE];
static char procfs_username_buffer[PROCFS_MAX_KEY_SIZE];
static unsigned long procfs_ufile_buffer_size = 0;
static unsigned long procfs_username_buffer_size=0;

struct proc_dir_entry *procfileUserList[MAX_USERS];
struct proc_dir_entry *usernameProcFile;

typedef struct _procFileData{
	unsigned short uid;
	char *username;
	char *privKey;
	char *pubKey;
}procFileData;

static procFileData userList[MAX_USERS];

//static struct task_struct *cur_task;


/*
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



int initkeyfile(char * username, int loc){
	
	int ret;
	char *envp[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL};

	sprintf(command[loc], "ssh-keygen -t rsa -b 2048 -C \"%s\" -f __key%s -q -N \"\" && cat __key%s __key%s.pub > __temp%s && cat __temp%s > /proc/%s && rm -f __temp%s __key%s __key%s.pub", username, username, username,username,username,username,username,username, username,username);

	printk(KERN_INFO "Value of command is %s\n", command[loc]);


	char *argv[] = {"/bin/bash", "-c", command[loc], NULL};

	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);	

	printk(KERN_INFO "Inside initkeyfile and ret value is %d\n", ret);

	return 0;
}
*/

int userCreator(procFileData *data, int loc){

	procfileUserList[loc] = create_proc_entry(data->username, 0666, NULL);

	if (procfileUserList[loc] == NULL)
	{
		remove_proc_entry(data->username, NULL);
		return -ENOMEM;
	}

//	procfileUserList[loc]->read_proc = keyFileRead;
//	procfileUserList[loc]->write_proc = keyFileWrite;
	procfileUserList[loc]->mode = S_IFREG | S_IRUGO;
	procfileUserList[loc]->uid = 0;
	procfileUserList[loc]->gid = 0;
	procfileUserList[loc]->size = 4096;
	procfileUserList[loc]->data = data;

	//initkeyfile(username, loc);

	return 0;
}

void bufferRipper(const char *buffer, unsigned long count){
	
	int i, usize=0;

	char *tempname = (char *)kmalloc(sizeof(char)*40, GFP_KERNEL);

	for(i=0; i<40; i++) {
		if(buffer[i] == '\n') {
			tempname[i] = '\0';
			usize++;
			break;
		}
		tempname[i] = buffer[i];
		usize++;	
	}

	printk(KERN_INFO "User name is - %s", tempname);

//	cur_task = get_current();

	userList[num_users].uid = current->uid;
	userList[num_users].username = (char *) kmalloc(sizeof(char)*usize, GFP_KERNEL);
	memcpy(userList[num_users].username, tempname, usize);
	
	userCreator(&userList[num_users],num_users);
	

	printk(KERN_INFO "User userlistname is - %s", userList[num_users].username);
	printk(KERN_INFO "User uid is - %d", userList[num_users].uid);

	num_users++;
}

int usernamesFileRead(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){
	 int ret, i;

	 char*templist;

         printk(KERN_INFO "procfile_read (/proc/%s) called\n", userdir);

         if(offset > 0)
         {
                 ret=0;
         }
         else
         {
		templist = (char *)kmalloc(sizeof(char)*40*num_users, GFP_KERNEL);

		templist = "\0";

		 for (i=0; i< num_users; i++){
			strcat(templist, userList[i].username);
			strcat(templist, "\n");
		 }
			
		 memcpy(buffer, templist, sizeof(char)*42*num_users);
		 printk(KERN_ALERT "after templist memcpy\n");
                 ret = 0;
         }
         return ret;
 }


int usernamesFileWrite(struct file *file, const char *buffer, unsigned long count, void *data){

	char *tempBuffer;

	if(count > PROCFS_MAX_USIZE){
		count = PROCFS_MAX_USIZE;
	}
	

	tempBuffer = (char *)kmalloc(sizeof(char)*count, GFP_KERNEL);


	if(copy_from_user(tempBuffer, buffer, sizeof(char)*count)){
		return -EFAULT;
	}

	bufferRipper(tempBuffer, (sizeof(char)*count));
	

	return count;

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
