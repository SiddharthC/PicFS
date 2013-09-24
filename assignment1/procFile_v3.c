/* Joe Greubel and Siddharth Choudhary - Key Pair User Lookup System - Sept 19, 2013 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/kmod.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/sched.h>

#define userdir "__usernames"
#define MAX_USERS 		1000
#define USERNAME_MAX_LENGTH 	40
#define PROCFS_MAX_USIZE 	8192
#define PROCFS_MAX_KEY_SIZE	4096
#define PRIV_KEY_MAX_SIZE	2048
#define PUB_KEY_MAX_SIZE	1024

/* 20 character long usernames + null terminator */
static int num_users = 0;
//static char command[MAX_USERS][500];

//static char procfs_ufile_buffer[PROCFS_MAX_USIZE];
//static char procfs_username_buffer[PROCFS_MAX_KEY_SIZE];
//static unsigned long procfs_ufile_buffer_size = 0;
//static unsigned long procfs_username_buffer_size=0;

struct proc_dir_entry *procfileUserList[MAX_USERS];
struct proc_dir_entry *usernameProcFile;

typedef struct _procFileData{
	uid_t uid;
	char *username;
	char privKey[PRIV_KEY_MAX_SIZE];
	char pubKey[PUB_KEY_MAX_SIZE];
}procFileData;

static procFileData userList[MAX_USERS];

// command to list all real users with root.  echo "root" && cat /etc/passwd | grep '/home' | cut -d: -f1

int keyFileRead(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){
	int ret;

	procFileData *tempproc = (procFileData *) data;

        if(offset > 0)
                ret=0;
        else
        {
		if(tempproc->uid == current_uid()){
			memcpy(buffer, tempproc->privKey, PRIV_KEY_MAX_SIZE);
			printk(KERN_INFO "uid match private key shown\n");
			printk(KERN_INFO "Buffer is \n%s\n", buffer);

			ret=PRIV_KEY_MAX_SIZE;
		}
		else{
			memcpy(buffer, tempproc->pubKey, PUB_KEY_MAX_SIZE);
			printk(KERN_INFO "uid did not match public key shown\n");
			printk(KERN_INFO "Buffer is \n%s\n", buffer);

			ret=PUB_KEY_MAX_SIZE;
		}
        }
        return ret;
}

int keyFileWrite(struct file *file, const char *buffer, unsigned long count, void *data){

	procFileData *tempproc = (procFileData *) data;
	char *startLoc, *tempBuffer, uid[10], loc[10];
	int i; 
	uid_t useruid[1];
	int key_loc[1];
	int ret;

	char splitString[] = "-----END RSA PRIVATE KEY-----";

	if(count > PROCFS_MAX_KEY_SIZE)
		count = PROCFS_MAX_KEY_SIZE;

	tempBuffer = (char *) kmalloc(sizeof(char)*count, GFP_KERNEL);
	
	if(copy_from_user(tempBuffer, buffer, count)){
		return -EFAULT;
	}

	printk(KERN_INFO "In key file write before 1st for\n");
/*
	for (i=0; i<10; i++){
		if(tempBuffer[i] == '\n'){
			loc[i]='\0';
			break;
		}
		loc[i] = tempBuffer[i];
	}
	
	tempBuffer +=(i+1);

	printk(KERN_INFO "In key file write after 1st for\n");

	ret = kstrtoint(loc, 10, key_loc);

	printk(KERN_INFO "loc recieved from the file - %d\n", key_loc[1]);

	for (i=0; i<10; i++){
		if(tempBuffer[i] == '\n'){
			uid[i]='\0';
			break;
		}
		uid[i] = tempBuffer[i];
	}

	tempBuffer += (i+1);

	ret = kstrtoint(uid,10,useruid);

	printk(KERN_INFO "Uid received from file - %u\n", useruid[1]);

	userList[key_loc[1]].uid = useruid[1];
*/
	startLoc = strstr(tempBuffer, splitString);

	if (NULL != startLoc){
		memcpy(tempproc->privKey, tempBuffer, (startLoc-tempBuffer+30+1000));
		printk(KERN_INFO "private key is \n%s\n", tempproc->privKey);
		memcpy(tempproc->pubKey, (startLoc+30), (count-(startLoc-tempBuffer+30)));
		printk(KERN_INFO "public  key is \n%s\n", tempproc->pubKey);
	}

	return count;

}

void initkeyfile(char * username, int loc){
	
	int ret;
	char *envp[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL};

	char command[500];

	sprintf(command, "ssh-keygen -t rsa -b 2048 -C \"%s\" -f __key -q -N \"\" && echo \"%d\" > __temp && id -u \"%s\" >> __temp && cat __key __key.pub >> __temp && cat __temp > /proc/%s && rm -f __temp __key __key.pub", username, loc, username, username);

	char *argv[] = {"/bin/bash", "-c", command, NULL};

	printk(KERN_INFO "Value of command is %s\n", command);

	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);	

	printk(KERN_INFO "Inside initkeyfile and ret value is %d\n", ret);
}

int userCreator(procFileData *data, int loc){

	procfileUserList[loc] = create_proc_entry(data->username, 0666, NULL);

	if (procfileUserList[loc] == NULL)
	{
		remove_proc_entry(data->username, NULL);
		return -ENOMEM;
	}

	procfileUserList[loc]->read_proc = keyFileRead;
	procfileUserList[loc]->write_proc = keyFileWrite;
	procfileUserList[loc]->mode = S_IFREG | S_IRUGO;
	procfileUserList[loc]->uid = 0;
	procfileUserList[loc]->gid = 0;
	procfileUserList[loc]->size = 4096;
	procfileUserList[loc]->data = data;

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

//	userList[num_users].uid = current_uid();		//TODO think to implement command id -r <username> could write it to temp file
//	current_uid();
	userList[num_users].username = (char *) kmalloc(sizeof(char)*usize, GFP_KERNEL);
	memcpy(userList[num_users].username, tempname, usize);
	
	userCreator(&userList[num_users],num_users);
	
	initkeyfile(userList[num_users].username, num_users);

	printk(KERN_INFO "User userlistname is - %s", userList[num_users].username);
	printk(KERN_INFO "User uid is - %d", userList[num_users].uid);

	num_users++;
}

int usernamesFileRead(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){
	 int ret, i;

	 char*templist;

         printk(KERN_INFO "procfile_read (/proc/%s) called\n", userdir);

         if(offset > 0)
                 ret=0;
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
                 ret = (sizeof(char)*42*num_users);
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
		char* username = userList[i].username;
		remove_proc_entry(username, NULL);
	}

	remove_proc_entry(userdir, NULL);
}
