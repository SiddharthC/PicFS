/* Joe Greubel and Siddharth Choudhary - Systemcall Interposer Module - October 20 , 2013 */

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



#define sysmon_uid 		"sysmon_uid"
#define sysmon_toggle 		"sysmon_toggle"
#define sysmon_log 		"sysmon_log"

#define	SYSMON_UID_MAXSIZE	4096
#define	SYSMON_TOGGLE_MAXSIZE	4096
#define	SYSMON_LOG_MAXSIZE	1024000

#define UID_MONITOR_STRING_SIZE	10 	

//Global variables

int uid_monitored_int;
char uid_monitored_string = "";

int toggle_monitored_int;

#define keyfile 		"key"
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

        if(offset > 0)
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

int sysmon_uid_read(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){

	memcpy(buffer, uid_monitored_string, UID_MONITORED_STRING_SIZE);

        return UID_MONITORED_STRING_SIZE;
}

int sysmon_toggle_read(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){

	char message[10] = {0};

	if(offset > 0)
		return 0;

	if(toggle_monitored_int){
		message = "On\n";
		memcpy(buffer, message, 4);
		return 4;
	}
	else{
		message = "Off\n";
		memcpy(buffer, message, 5);
		return 5;
	}

}

int sysmon_log_read(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){

}

int sysmon_uid_write(struct file *file, const char *buffer, unsigned long count, void *data){

	int i, dummy;

	uid_monitored_string = "";

	if(count > SYSMON_UID_MAXSIZE)
			count = SYSMON_UID_MAXSIZE;

	char *tempBuffer = (char *) kmalloc(sizeof(char)*count, GFP_KERNEL);

	memset(tempBuffer, 0, sizeof(char)*count);

	if(copy_from_user(tempBuffer, buffer, sizeof(char)*count)){
		return -EFAULT;
	}

	for(i=0; i<UID_MONITORED_STRING_SIZE; i++){
		if(!((tempBuffer[i] >= '0' && tempBuffer[i] <= '9')|| tempBuffer[i] == '\n' || tempBuffer[i] == ' ')){
			return -EINVAL;	
		}

		if((tempBuffer[i] == '\n') || (tempBuffer[i] == ' ')){
			uid_monitored_string[i] = '\0';
			break;
		}
		
		uid_monitored_string[i] = tempBuffer[i];
	}
	
	dummy = kstrtoint(uid_monitored_string, i, &uid_monitored_int);

	return count;
}

int sysmon_toggle_write(struct file *file, const char *buffer, unsigned long count, void *data){

	uid_monitored_string = "";

	if(count > SYSMON_UID_MAXSIZE)
			count = SYSMON_UID_MAXSIZE;

	char tempBuffer = '\0';

	memset(tempBuffer, 0, sizeof(char)*count);

	if(copy_from_user(&tempBuffer, buffer, 1)){
		return -EFAULT;
	}

	if(tempBuffer != '0' && tempBuffer != '1')
		return -EINVAL;	

	if(tempBuffer == '1')
		toggle_monitored_int = 1;
	else
		toggle_monitor_int = 0;
		
	return count;
}

int proc_creator(void){
	
	sysmon_uid_Entry = create_proc_entry(sysmon_uid, 0600, NULL);

	if(sysmon_uid_Entry == NULL){
		remove_proc_entry(sysmon_uid, NULL);
		return -ENOMEM;
	}

	sysmon_uid_Entry->read_proc = sysmon_uid_read;
	sysmon_uid_Entry->write_proc = sysmon_uid_write;
	sysmon_uid_Entry->mode = S_IFREG | S_IRUGO;
	sysmon_uid_Entry->uid = 0;
	sysmon_uid_Entry->gid = 0;
	sysmon_uid_Entry->size = SYSMON_UID_MAXSIZE;


	sysmon_toggle_Entry = create_proc_entry(sysmon_toggle, 0600, NULL);

	if(sysmon_toggle_Entry == NULL){
		remove_proc_entry(sysmon_toggle, NULL);
		return -ENOMEM;
	}

	sysmon_toggle_Entry->read_proc = sysmon_toggle_read;
	sysmon_toggle_Entry->write_proc = sysmon_toggle_write;
	sysmon_toggle_Entry->mode = S_IFREG | S_IRUGO;
	sysmon_toggle_Entry->uid = 0;
	sysmon_toggle_Entry->gid = 0;
	sysmon_toggle_Entry->size = SYSMON_TOGGLE_MAXSIZE;

	sysmon_log_Entry = create_proc_entry(sysmon_log, 0400, NULL);

	if(sysmon_log_Entry == NULL){
		remove_proc_entry(sysmon_log, NULL);
		return -ENOMEM;
	}

	sysmon_log_Entry->read_proc = sysmon_log_read;
	sysmon_log_Entry->mode = S_IFREG | S_IRUGO;
	sysmon_log_Entry->uid = 0;
	sysmon_log_Entry->gid = 0;
	sysmon_log_Entry->size = SYSMON_LOG_MAXSIZE;

}

int init_module()
{
	proc_creator();
	return 0;
}

void cleanup_module()
{
	remove_proc_entry(sysmon_uid, NULL);
	remove_proc_entry(sysmon_toggle, NULL);
	remove_proc_entry(sysmon_log, NULL);
}