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
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/time.h>

#define MODULE_NAME 			"interposer_beta"

#define sysmon_uid 			"sysmon_uid"
#define sysmon_toggle 			"sysmon_toggle"
#define sysmon_log 			"sysmon_log"

#define	SYSMON_UID_MAXSIZE		4096
#define	SYSMON_TOGGLE_MAXSIZE		4096
#define	SYSMON_LOG_MAXSIZE		1048576
#define UID_MONITORED_STRING_SIZE	10
#define NUM_SYSCALL_MONITORED		30

#define MAX_LOG_LINES			40
#define MAX_LOG_LINE_SIZE		70

#define THRESHOLD			1000
#define TIMEOUT				300000000000

MODULE_LICENSE("GPL");

//TODO on each read return 40 lines only

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
//int num_calls;
//char **log_ptr2



typedef struct _CallNode{
	unsigned int count;
	unsigned long total_count;
	int flag;
	char recent_log[MAX_LOG_LINE_SIZE];
	struct timespec ts;
}CallNode;

CallNode callNodeArray[30];

static struct kprobe probe[NUM_SYSCALL_MONITORED];

//*************************************************************************************************************//
// Function Definitions

void hash_table_printer(void){
	
	int i;

	for(i=0; i<30; i++){
		printk(KERN_INFO "Node index -- %d\n", i);
		printk(KERN_INFO "Node.count -- %u\n", callNodeArray[i].count);	
		printk(KERN_INFO "Node.total_count -- %lu\n", callNodeArray[i].total_count);
		printk(KERN_INFO "Node.flag -- %d\n", callNodeArray[i].flag);
		printk(KERN_INFO "Node.recent_log -- %s\n", callNodeArray[i].recent_log);
	}
}

static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{
	int ret = 0;
	int hash_index = -1;

	struct timespec tempts, diffts;

	//if(!num_calls++)
	//	printk(KERN_INFO "SOMETHING %lu", regs->ax);

	//printk(KERN_INFO "----------------------------%d val monitored ------------------------------", uid_monitored_int);
	//printk(KERN_INFO "----------------------------%d uid monitored ------------------------------", current_uid());
	//printk(KERN_INFO "Value of toggle is %d.", toggle_monitored_int);
	
	if ( !toggle_monitored_int || (current_uid() != uid_monitored_int))
		return 0;

		if(log_offset == MAX_LOG_LINES){
			log_offset = 0;
			log_cycle_flag = 1;
		}

		switch (regs->ax) {
		
			case __NR_access:
				hash_index = 0;
				break;
			case __NR_brk:
				hash_index = 1;
				break;
			case __NR_chdir:
				hash_index = 2;
				break;
			case __NR_chmod:
				hash_index = 3;
				break;
			case __NR_clone:
				hash_index = 4;
				break;
			case __NR_close:
				hash_index = 5;
				break;
			case __NR_dup:
				hash_index = 6;
				break;
			case __NR_dup2:
				hash_index = 7;
				break;
			case __NR_execve:
				hash_index = 8;
				break;
			case __NR_exit_group:
				hash_index = 9;
				break;		
			case __NR_fcntl:
				hash_index = 10;
				break;		
			case __NR_fork:
				hash_index = 11;
				break;		
			case __NR_getdents:
				hash_index = 12;
				break;	
			case __NR_getpid:
				hash_index = 13;
				break;
			case __NR_gettid:
				hash_index = 14;
				break;
			case __NR_ioctl:
				hash_index = 15;
				break;
			case __NR_lseek:
				hash_index = 16;
				break;
			case __NR_mkdir:
				hash_index = 17;
				break;
			case __NR_mmap:
				hash_index = 18;
				break;
			case __NR_munmap:
				hash_index = 19;
				break;
			case __NR_open:
				hash_index = 20;
				break;
			case __NR_pipe:
				hash_index = 21;
				break;
			case __NR_read:
				hash_index = 22;
				break;
			case __NR_rmdir:
				hash_index = 23;
				break;
			case __NR_select:
				hash_index = 24;
				break;
			case __NR_stat:
				hash_index = 25;
				break;
			case __NR_fstat:
				hash_index = 26;
				break;
			case __NR_lstat:
				hash_index = 27;
				break;
			case __NR_wait4:
				hash_index = 28;
				break;
			case __NR_write:
				hash_index = 29;
				break;
			default:
				return 0;
		}

		callNodeArray[hash_index].total_count++;

		if(callNodeArray[hash_index].flag){
			getnstimeofday(&tempts);
			diffts = timespec_sub(tempts, callNodeArray[hash_index].ts);

			if(timespec_to_ns(&diffts) > TIMEOUT){
				callNodeArray[hash_index].flag = 0;
				callNodeArray[hash_index].count	= 0;
			}
		}

		if(callNodeArray[hash_index].count++ > THRESHOLD){
			callNodeArray[hash_index].flag = 1;
			getnstimeofday(&callNodeArray[hash_index].ts);
		}
		else{
			sprintf(log_ptr[log_offset++], "%lu %d %d| User: %d Syscall: %lu PID: %d TGID: %d\n", 
				regs->ax, current->pid, current->tgid, current_uid(), regs->ax, current->pid, current->tgid);
		}

		sprintf(callNodeArray[hash_index].recent_log, "%lu %d %d| User: %d Syscall: %lu PID: %d TGID: %d\n", 
			regs->ax, current->pid, current->tgid, current_uid(), regs->ax, current->pid, current->tgid);

		return ret;
}

static void sysmon_intercept_after(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
	/* Here you could capture the return code if you wanted. */
}

int probe_creator(void){
	int i;

	probe[0].symbol_name = "sys_write";
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

	if(offset < 0)		// offset should be checked for negative value. This was a bug earlier
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

       	if(offset < 0)
		return 0;

	printk(KERN_INFO "********************************Buffer length %d***********************\n", buffer_length);
	//The buffer length is always 3072
	memset(buffer, 0, (sizeof(char)*MAX_LOG_LINES*MAX_LOG_LINE_SIZE));

	if(log_cycle_flag)
		i = log_offset;

	for (; i< MAX_LOG_LINES; i++){
		strcat(buffer, log_ptr[i]);
	}

	if(log_cycle_flag){	
		for(i=0; i<log_offset; i++){
			strcat(buffer, log_ptr[i]);
		}
	}
			
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
//	int i;

//	log_ptr2 = (char **)vmalloc(MAX_LOG_LINES*(sizeof(char *)));

//	for(i=0; i<MAX_LOG_LINES; i++){
//		log_ptr2[i] = (char *)vmalloc(MAX_LOG_LINE_SIZE * (sizeof(char)));
//		memset(log_ptr2[i], 0, MAX_LOG_LINE_SIZE* sizeof(char));
//	}

	proc_creator();
	probe_creator();
	return 0;
}

void cleanup_module()
{
	int i;
//	printk(KERN_INFO "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%d", num_calls);

//	for(i=0; i<MAX_LOG_LINES; i++)
//		vfree(log_ptr2[i]);

//	vfree(log_ptr2);

	for(i=0; i<NUM_SYSCALL_MONITORED; i++)
		unregister_kprobe(&probe[i]);	
	remove_proc_entry(sysmon_uid, NULL);
	remove_proc_entry(sysmon_toggle, NULL);
	remove_proc_entry(sysmon_log, NULL);
}
