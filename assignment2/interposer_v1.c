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
#define MAX_LOG_LINES			5
#define MAX_LOG_LINE_SIZE		200

MODULE_LICENSE("GPL");

//Global variables
int uid_monitored_int;
char uid_monitored_string[UID_MONITORED_STRING_SIZE] = "0\n" ;
int toggle_monitored_int;

//Proc File Entries
struct proc_dir_entry *sysmon_uid_Entry;
struct proc_dir_entry *sysmon_toggle_Entry;
struct proc_dir_entry *sysmon_log_Entry;

char log_ptr[MAX_LOG_LINES][MAX_LOG_LINE_SIZE];
int log_offset;
int log_cycle_flag;
int looper;

static struct kprobe probe[NUM_SYSCALL_MONITORED];

//*************************************************************************************************************//
// Function Definitions

static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{
	int ret = 0;

	//printk(KERN_INFO "----------------------------%d val monitored ------------------------------", uid_monitored_int);

	//printk(KERN_INFO "----------------------------%d uid monitored ------------------------------", current_uid());

	//printk(KERN_INFO "Value of toggle is %d.", toggle_monitored_int);
	if ( !toggle_monitored_int || (current_uid() != uid_monitored_int))
		return 0;

	if(!looper++){

		if(log_offset == MAX_LOG_LINES){
			log_offset = 0;
			log_cycle_flag = 1;
		}

		switch (regs->ax) {
		
			case __NR_access:
			case __NR_brk:
			case __NR_chdir:
			case __NR_chmod:
			case __NR_clone:
			case __NR_close:
			case __NR_dup:
			case __NR_dup2:
			case __NR_execve:
			case __NR_exit_group:
			case __NR_fcntl:
			case __NR_fork:
			case __NR_getdents:
			case __NR_getpid:
			case __NR_gettid:
			case __NR_ioctl:
			case __NR_lseek:
			case __NR_mkdir:
			case __NR_mmap:
			case __NR_munmap:
			case __NR_open:
			case __NR_pipe:
			case __NR_read:
			case __NR_rmdir:
			case __NR_select:
			case __NR_stat:
			case __NR_fstat:
			case __NR_lstat:
			case __NR_wait4:
			case __NR_write:
				sprintf(log_ptr[log_offset++], "%lu %d %d: User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
							regs->ax, current->pid, current->tgid, current_uid(), regs->ax, current->pid, current->tgid); 
				break;
			default:
				break;
		}
	}

	return ret;
}

static void sysmon_intercept_after(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
	    /* Here you could capture the return code if you wanted. */
	if ( !toggle_monitored_int || (current_uid() != uid_monitored_int))
		return;

	looper--;

	return;
}

int probe_creator(void){
	int i;

	probe[1].symbol_name = "sys_access";
	probe[2].symbol_name = "sys_brk";
	probe[3].symbol_name = "sys_chdir";
	probe[4].symbol_name = "sys_chmod";
	probe[5].symbol_name = "sys_clone";
	probe[6].symbol_name = "sys_close";
	probe[7].symbol_name = "sys_dup";
	probe[8].symbol_name = "sys_dup2";
	probe[9].symbol_name = "sys_execve";
	probe[10].symbol_name = "sys_exit_group";
	probe[11].symbol_name = "sys_fcntl";
	probe[12].symbol_name = "sys_fork";
	probe[13].symbol_name = "sys_getdents";
	probe[14].symbol_name = "sys_getpid";
	probe[15].symbol_name = "sys_gettid";
	probe[16].symbol_name = "sys_ioctl";
	probe[17].symbol_name = "sys_lseek";
	probe[18].symbol_name = "sys_mkdir";
	probe[19].symbol_name = "sys_mmap";
	probe[20].symbol_name = "sys_munmap";
	probe[21].symbol_name = "sys_open";
	probe[22].symbol_name = "sys_pipe";
	probe[23].symbol_name = "sys_read";
	probe[24].symbol_name = "sys_rmdir";
	probe[25].symbol_name = "sys_select";
	probe[26].symbol_name = "sys_stat";
	probe[27].symbol_name = "sys_fstat";
	probe[28].symbol_name = "sys_lstat";
	probe[29].symbol_name = "sys_wait4";
	probe[0].symbol_name = "sys_write";

	for(i=0; i<NUM_SYSCALL_MONITORED; i++)
	{
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

int sysmon_log_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data){

	 int ret, i = 0;
	// char *temp_log_buffer;

         if(offset < 0)
                 return 0;

	//temp_log_buffer = (char *)kmalloc(sizeof(char) * MAX_LOG_LINES * MAX_LOG_LINE_SIZE);

//	if(temp_log_buffer)
//	{
//		printk(KERN_INFO "***********************Couldn't get mem**********************");
//		return 0;
//	}

	memset(buffer, 0, (sizeof(char)*MAX_LOG_LINES*MAX_LOG_LINE_SIZE));
	
	printk(KERN_INFO "Got till if....\n");

	if(log_cycle_flag)
		i = log_offset;

	for (; i< MAX_LOG_LINES; i++){
		strcat(buffer, log_ptr[i]);
	}

	printk(KERN_INFO "Got after first for....\n");


	if(log_cycle_flag){	
		for(i=0; i<log_offset; i++){
			strcat(buffer, log_ptr[i]);
		}
	}
			
//	 memcpy(buffer, temp_log_buffer, sizeof(char)*MAX_LOG_LINES * MAX_LOG_LINE_SIZE);
         ret = (sizeof(char)*MAX_LOG_LINES*MAX_LOG_LINE_SIZE);
         return ret;
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

	dummy = kstrtoint(uid_monitored_string, 10, &uid_monitored_int);
	printk(KERN_INFO "@@@@@@@@@@@@@@@@@@@@@@@The int converted is %d", uid_monitored_int);

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

int init_module()
{
	proc_creator();
	probe_creator();
	return 0;
}

void cleanup_module()
{
	int i;

	for(i=0; i<NUM_SYSCALL_MONITORED; i++)
		unregister_kprobe(&probe[i]);	
	remove_proc_entry(sysmon_uid, NULL);
	remove_proc_entry(sysmon_toggle, NULL);
	remove_proc_entry(sysmon_log, NULL);
}
