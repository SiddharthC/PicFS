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
#define UID_MONITORED_STRING_SIZE	10

//Global variables
int uid_monitored_int;
char uid_monitored_string[UID_MONITORED_STRING_SIZE] = "" ;
int toggle_monitored_int;

//Proc File Entries
struct proc_dir_entry *sysmon_uid_Entry;
struct proc_dir_entry *sysmon_toggle_Entry;
struct proc_dir_entry *sysmon_log_Entry;

//Structures
char** syscalls = {"sys_access", "sys_brk", "sys_chdir", "sys_chmod", "sys_clone", "sys_close", "sys_dup", "sys_dup2",
		   "sys_execve", "sys_exit_group", "sys_fcntl", "sys_fork", "sys_getdents", "sys_getpid", "sys_gettid",
		   "sys_ioctl", "sys_lseek", "sys_mkdir", "sys_mmap", "sys_munmap", "sys_open", "sys_pipe", "sys_read",
		   "sys_rmdir", "sys_select", "sys_stat", "sys_fstat", "sys_lstat", "sys_wait4", "sys_write"};

//*************************************************************************************************************//
// Function Definitions
int sysmon_uid_read(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){

	memcpy(buffer, uid_monitored_string, UID_MONITORED_STRING_SIZE);

        return UID_MONITORED_STRING_SIZE;
}

int sysmon_toggle_read(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){

	if(offset > 0)
		return 0;

	if(toggle_monitored_int){
		char message[5] = "On\n";
		memcpy(buffer, message, 4);
	}
	else{
		char message[5] = "Off\n";
		memcpy(buffer, message, 5);
	}

	return 5;

}

int sysmon_log_read(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){

	return 0;
}

int sysmon_uid_write(struct file *file, const char *buffer, unsigned long count, void *data){

	int i, dummy;
	char *tempBuffer;

	strncpy(uid_monitored_string, "", UID_MONITORED_STRING_SIZE);

	if(count > SYSMON_UID_MAXSIZE)
			count = SYSMON_UID_MAXSIZE;

	tempBuffer = (char *) kmalloc(sizeof(char)*count, GFP_KERNEL);

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

	uid_monitored_string[i] = '\n';
	uid_monitored_string[++i] = '\0';

	return count;
}

int sysmon_toggle_write(struct file *file, const char *buffer, unsigned long count, void *data){

	char tempBuffer = '\0';

	if(count > SYSMON_UID_MAXSIZE)
			count = SYSMON_UID_MAXSIZE;

	if(copy_from_user(&tempBuffer, buffer, 1)){
		return -EFAULT;
	}

	if(tempBuffer != '0' && tempBuffer != '1')
		return -EINVAL;	

	if(tempBuffer == '1')
		toggle_monitored_int = 1;
	else
		toggle_monitored_int = 0;

	return count;
}

int proc_creator(void){

	//UID Proc File
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

	//Toggle File
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

	//Log File
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

	return 0;

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
