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

//*************************************************************************************************************//
// Function Definitions

static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{
	int ret = 0;
	char temp_print[500] = {0};
	//printk(KERN_INFO "Value of toggle is %d.", toggle_monitored_int);
	if (!toggle_monitored_int || (current_uid() != uid_monitored_int))
		return 0;

	switch (regs->ax) {
		
		case __NR_access:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);								
//			//check for overflow first TODO
			break;
		case __NR_brk:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_chdir:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_chmod:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_clone:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_close:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_dup:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_dup2:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_execve:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_exit_group:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_fcntl:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_fork:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_getdents:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_getpid:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_gettid:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_ioctl:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_lseek:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_mkdir:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_mmap:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_munmap:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_open:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_pipe:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_read:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_rmdir:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_select:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_stat:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_fstat:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_lstat:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_wait4:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		case __NR_write:
			sprintf(temp_print, "User --> %d fired monitored system call --> %lu. Current pid --> %d. Current tgid --> %d\n",
					current_uid(), regs->ax, current->pid, current->tgid); 
			strcat(log_ptr, temp_print);	
			break;
		default:
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
	if(offset < 0)
		return 0;
	if(offset > SIZE_OF_LOG_BUFFER)
		offset = 0;					//default offset to 0 if exceed the max size
	if((offset + buffer_length)> SIZE_OF_LOG_BUFFER)
		buffer_length = SIZE_OF_LOG_BUFFER - offset;

	memcpy(buffer, log_ptr+offset, buffer_length);

	return buffer_length;
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
	memset(log_ptr, 0, sizeof(char)*SIZE_OF_LOG_BUFFER);
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

	kfree(log_ptr);

	for(i=0; i<NUM_SYSCALL_MONITORED; i++)
		unregister_kprobe(&probe[i]);	
	remove_proc_entry(sysmon_uid, NULL);
	remove_proc_entry(sysmon_toggle, NULL);
	remove_proc_entry(sysmon_log, NULL);
}
