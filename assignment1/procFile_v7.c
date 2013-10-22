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
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>



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

struct proc_dir_entry *procfileUserList[MAX_USERS];
struct proc_dir_entry *prockey[MAX_USERS];
struct proc_dir_entry *usernameProcFile;

typedef struct _procFileData{
	uid_t uid;
	char *username;
	char privKey[PRIV_KEY_MAX_SIZE];
	char pubKey[PUB_KEY_MAX_SIZE];
	int delFlag;
}procFileData;

static procFileData userList[MAX_USERS];

int keyFileRead(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){
	int ret;

	procFileData *tempproc = (procFileData *) data;

        if(offset < 0)
                ret=0;
        else
        {
		if(tempproc->uid == current_uid()){
			memcpy(buffer, tempproc->privKey, PRIV_KEY_MAX_SIZE);
			printk(KERN_INFO "uid match private key shown\n");

			ret=PRIV_KEY_MAX_SIZE;
		}
		else{
			memcpy(buffer, tempproc->pubKey, PUB_KEY_MAX_SIZE);
			printk(KERN_INFO "uid did not match public key shown\n");

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

	for(i=0; i<len-1; ++i){
		get_random_bytes(&j, sizeof(int));
		s[i]= alphanum[j % (sizeof(alphanum)-1)];
	}
	
	s[len-1] = '\n';

	s[len] = 0;
}

int read_file_getuid(char *filename, char *username){

	printk(KERN_INFO "in read file \n"); 

	//file reading for uid
	int i, uid, j=0, dummy;
	char *buf;
	int look=0;

	char temp[100];

	struct file *f;

	mm_segment_t fs;

	buf = (char *) kmalloc(200000, GFP_KERNEL);
	memset(buf, 0, 200000);

	f = filp_open(filename, O_RDONLY, 0);

	if(NULL != f){
		fs = get_fs();
		set_fs(get_ds());

		vfs_read(f, buf, 100000, ((&f->f_pos)+100));
		//f->f_op->read(f, buf, 200000, &f->f_pos);

//		printk(KERN_INFO "THe value of buf is %s", buf);

		char *loc = strstr(buf, username);

		if(NULL != loc){

		printk(KERN_INFO "loc is %s", loc);

		for (i=0; i< sizeof(buf); i++){
			if ((loc[i] == ':') && (look != 3)){
				look++;
				memset(temp, 0, sizeof(temp));
				j=0;
				printk(KERN_INFO "in special loc\n");

			}
			else if (look == 3){

				printk(KERN_INFO "temp is %s\n", temp);
				dummy = kstrtoint(temp, 10, &uid);

				printk(KERN_INFO "uid parsed is %d\n", uid);

				return uid;
			}
			else{
				printk(KERN_INFO "in for\n");
				temp[j] = loc[i];
				j++;
			}
		}
		}

		set_fs(fs);
	}
	filp_close(f, NULL);
	
	kfree(buf);

	return 0;

}

void clearProcEntry(char *uname){

	int i;

	for (i=0; i<num_users; i++){
		if (strcmp(userList[i].username, uname) == 0){
			userList[i].delFlag = 1;
			remove_proc_entry(keyfile, procfileUserList[i]);
			remove_proc_entry(userList[i].username, NULL);
		}
	}
	//search username and set del flag
}

void bufferRipper(const char *buffer, unsigned long count){
	
	int i, usize=0, j=0, dummy;
	char *tempname = (char *)kmalloc(sizeof(char)*40, GFP_KERNEL);

	char uidstr[10] = "";
	int deletionFlag = 2, flag=0;

	//asking user for uid as a work around

	for(i=0; i<40; i++) {
		if(i==0){
			if(buffer[i] == '-'){
				deletionFlag=1;
			}
			else if (buffer[i]== '+')
			{
				deletionFlag=0;
			}
			continue;
		}
		if (flag == 0 ){
			if(buffer[i] == '\n') {
				tempname[i-1] = '\0';
				usize++;
				break;
			}
			if(buffer[i] == ':'){
				flag = 1;
				continue;
			}
			tempname[i-1] = buffer[i];
			usize++;
		}
		else {
			if(buffer[i] == '\n'){
				uidstr[j] = '\0';
				break;
			}
			uidstr[j] = buffer[i];
			j++;
		}
	}

	if(deletionFlag == 0){

		printk(KERN_INFO "addition called\n");

		userList[num_users].username = (char *) kmalloc(sizeof(char)*usize, GFP_KERNEL);
		memcpy(userList[num_users].username, tempname, usize);
	
		gen_random(userList[num_users].privKey, 2048);

		gen_random(userList[num_users].pubKey, 1024);

		//userList[num_users].uid = read_file_getuid("/etc/passwd", tempname);

		dummy = kstrtoint(uidstr, 10, &userList[num_users].uid);

		userList[num_users].delFlag = 0;

		userCreator(&userList[num_users],num_users);

	
		printk(KERN_INFO "User userlistname is - %s", userList[num_users].username);
		printk(KERN_INFO "User uid is - %d", userList[num_users].uid);

		num_users++;
	}
	else if (deletionFlag == 1){

		printk(KERN_INFO "deletion called\n");
		
		clearProcEntry(tempname);
	}
	else {
		printk(KERN_INFO "Invalid symbol at start no change to structures\n");
	}
}

int usernamesFileRead(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){
	 int ret, i;
	 char *templist;

         if(offset < 0)
                 ret=0;
         else
         {
		templist = (char *)kmalloc(sizeof(char)*40*num_users, GFP_KERNEL);

		memset(templist, 0, (sizeof(char)*40*num_users));

		 for (i=0; i< num_users; i++){
			 if (userList[i].delFlag == 0){
				strcat(templist, userList[i].username);
				strcat(templist, "\n");
			 }
		 }
			
		 memcpy(buffer, templist, sizeof(char)*42*num_users);
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
		if(userList[i].delFlag == 0){
			remove_proc_entry(keyfile, procfileUserList[i]);
			remove_proc_entry(userList[i].username, NULL);
		}
	}

	remove_proc_entry(userdir, NULL);
}
