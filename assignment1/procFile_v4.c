/* Joe Greubel and Siddharth Choudhary - Key Pair User Lookup System - Sept 19, 2013 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/kmod.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/random.h>

#define userdir "__usernames"
#define keyfile "key"
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
struct proc_dir_entry *prockey[MAX_USERS];
struct proc_dir_entry *usernameProcFile;

typedef struct _procFileData{
	uid_t uid;
	char *username;
	char privKey[PRIV_KEY_MAX_SIZE];
	char pubKey[PUB_KEY_MAX_SIZE];
}procFileData;

static procFileData userList[MAX_USERS];

//char sourceChars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
//int scLen = strlen(sourceChars);


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

int userCreator(procFileData *data, int loc){

	procfileUserList[loc] = proc_mkdir(data->username, NULL);
		
	prockey[loc] = create_proc_entry(keyfile, 0666, procfileUserList[loc]);

	if (prockey[loc] == NULL)
	{
		remove_proc_entry(keyfile, procfileUserList[loc]);
		remove_proc_entry(data->username, NULL);
		return -ENOMEM;
	}

	prockey[loc]->read_proc = keyFileRead;
	prockey[loc]->mode = S_IFREG | S_IRUGO;
	prockey[loc]->uid = 0;
	prockey[loc]->gid = 0;
	prockey[loc]->size = 4096;
	prockey[loc]->data = data;

	return 0;
}

void gen_random(char *s, const int len){
	int i, j=0;

	static const char alphanum[]="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcefghijklmnopqrstuvwxyz";

	for(i=0; i<len; ++i){
		get_random_bytes(&j, sizeof(int));
		s[i]= alphanum[j % (sizeof(alphanum)-1)];
	}

	s[len] = 0;
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
	userList[num_users].username = (char *) kmalloc(sizeof(char)*usize, GFP_KERNEL);
	memcpy(userList[num_users].username, tempname, usize);

	//random keys 2048 and 1024 bytes long
	//get_random_bytes(userList[num_users].privKey, 2048);
	gen_random(userList[num_users].privKey, 2048);

	//get_random_bytes(userList[num_users].pubKey, 1024);
	gen_random(userList[num_users].pubKey, 1024); 
	
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
                 ret=0;
         else
         {
		templist = (char *)kmalloc(sizeof(char)*40*num_users, GFP_KERNEL);

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
		remove_proc_entry(keyfile, userList[i].username);
		remove_proc_entry(userList[i].username, NULL);
	}

	remove_proc_entry(userdir, NULL);
}
