/* Joe Greubel and Siddharth Choudhary - Systemcall Interposer Module - October 20 , 2013 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
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

#define MODULE_NAME "interposer_beta"

#define sysmon_uid 			"sysmon_uid"
#define sysmon_toggle 			"sysmon_toggle"
#define sysmon_log 			"sysmon_log"

#define	SYSMON_UID_MAXSIZE		4096
#define	SYSMON_TOGGLE_MAXSIZE		4096
#define	SYSMON_LOG_MAXSIZE		1048576
#define UID_MONITORED_STRING_SIZE	10
#define NUM_SYSCALL_MONITORED		30
#define SIZE_OF_LOG_BUFFER		1048576

MODULE_LICENSE("GPL");

//Global variables
int uid_monitored_int;
char uid_monitored_string[UID_MONITORED_STRING_SIZE] = "" ;
int toggle_monitored_int;

//Proc File Entries
struct proc_dir_entry *sysmon_uid_Entry;
struct proc_dir_entry *sysmon_toggle_Entry;
struct proc_dir_entry *sysmon_log_Entry;

char *log_ptr;
int log_offset;

static struct kprobe probe[NUM_SYSCALL_MONITORED];

//Structures

char syscalls[NUM_SYSCALL_MONITORED][15] = {"sys_access", "sys_brk", "sys_chdir", "sys_chmod", "sys_clone", "sys_close", "sys_dup", "sys_dup2",
		   "sys_execve", "sys_exit_group", "sys_fcntl", "sys_fork", "sys_getdents", "sys_getpid", "sys_gettid",
		   "sys_ioctl", "sys_lseek", "sys_mkdir", "sys_mmap", "sys_munmap", "sys_open", "sys_pipe", "sys_read",
		   "sys_rmdir", "sys_select", "sys_stat", "sys_fstat", "sys_lstat", "sys_wait4", "sys_write"};
 
//*************************************************************************************************************//
// Function Definitions

static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{
	int ret = 0;
	if (current_uid() != uid_monitored_int)
		return 0;
	switch (regs->ax) {
		case __NR_access:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_brk:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_chdir:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_chmod:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_clone:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_close:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_dup:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_dup2:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_execve:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_exit_group:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_fcntl:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_fork:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_getdents:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_getpid:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_gettid:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_ioctl:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_lseek:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_mkdir:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_mmap:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_munmap:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_open:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_pipe:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_read:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_rmdir:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_select:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_stat:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_fstat:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_lstat:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_wait4:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		case __NR_write:
			printk(KERN_INFO MODULE_NAME /* sycall pid tid args.. */
				"%lu %d %d args 0x%lu '%s' %d\n", regs->ax, current->pid, current->tgid,
				(uintptr_t)regs->di, (char*)regs->di, (int)regs->si);
			break;
		default:
			ret = -1;
			break;
	}
	return ret;
}

static void sysmon_intercept_after(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
	    /* Here you could capture the return code if you wanted. */
}

int probe_creator(void){
	int i;
	for(i=0; i<NUM_SYSCALL_MONITORED; i++)
	{
		probe[i].symbol_name = syscalls[i];
		probe[i].pre_handler = sysmon_intercept_before; /* called prior to function */
		probe[i].post_handler = sysmon_intercept_after; /* called on function return */
		if (register_kprobe(&probe[i])) {
			printk(KERN_ERR MODULE_NAME "register_kprobe failed\n");
			return -EFAULT;
		}
	}
	return 0;
}

int sysmon_uid_read(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){

	memcpy(buffer, uid_monitored_string, UID_MONITORED_STRING_SIZE);

        return UID_MONITORED_STRING_SIZE;
}

int sysmon_toggle_read(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data){

	if(offset < 0)							// offset should be checked for negative value. This was a bug earlier
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
	if(offset < 0)
		return 0;



	return 0;
}

int sysmon_uid_write(struct file *file, const char *buffer, unsigned long count, void *data){

	int i, dummy;
	char *tempBuffer;

	strncpy(uid_monitored_string, "", UID_MONITORED_STRING_SIZE);

	if(count > SYSMON_UID_MAXSIZE)
			count = SYSMON_UID_MAXSIZE;

	tempBuffer = (char *) kmalloc(sizeof(char)*count, GFP_KERNEL);
	if(!tempBuffer)
		return -ENOMEM;
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
	sysmon_log_Entry->size = SYSMON_LOG_MAXSIZE * sizeof(char);

	return 0;

}

int init_log(void){
	
	log_ptr = (char *)kmalloc(SIZE_OF_LOG_BUFFER * sizeof(char), GFP_KERNEL);
	if(!log_ptr)
		return -ENOMEM;
	memset(log_ptr, 0, sizeof(char)*count);
	return 0;
}

int init_module()
{
	proc_creator();
	probe_creator();
	init_log();
	return 0;
}

void cleanup_module()
{
	int i;

	free(log_ptr);

	for(i=0; i<NUM_SYSCALL_MONITORED; i++)
		unregister_kprobe(&probe[i]);	
	remove_proc_entry(sysmon_uid, NULL);
	remove_proc_entry(sysmon_toggle, NULL);
	remove_proc_entry(sysmon_log, NULL);
}
