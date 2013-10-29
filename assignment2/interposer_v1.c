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
#define sysmon_flags			"sysmon_flags"

#define	SYSMON_UID_MAXSIZE		4096
#define	SYSMON_TOGGLE_MAXSIZE		4096
#define	SYSMON_LOG_MAXSIZE		1048576
#define SYSMON_FLAGS_MAXSIZE		102400
#define UID_MONITORED_STRING_SIZE	10
#define NUM_SYSCALL_MONITORED		30

#define MAX_LOG_LINES			40000
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
int log_offset_read=-1;
int log_cycle_flag;

int lines_returnable = 3072/MAX_LOG_LINE_SIZE;
int log_looped;
int num_calls;
char mybuffer[100000];

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


int sysmon_flag_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data){

	int i;
	char tempBuffer[100]="";

	if(offset > 0)
		return 0;
	
	memset(buffer, 0, buffer_length);
	for(i=0; i<30; i++){
		sprintf(tempBuffer, "Node index -- %2d | ", i);
		strcat(mybuffer, tempBuffer);
		memset(tempBuffer, 0, 100);
		sprintf(tempBuffer, "Node.count -- %4u | ", callNodeArray[i].count);	
		strcat(mybuffer, tempBuffer);
		memset(tempBuffer, 0, 100);
		sprintf(tempBuffer,"Node.total_count -- %6lu | ", callNodeArray[i].total_count);
		strcat(mybuffer, tempBuffer);
		memset(tempBuffer, 0, 100);
		sprintf(tempBuffer, "Node.flag -- %d\n", callNodeArray[i].flag);
		strcat(mybuffer, tempBuffer);
		memset(tempBuffer, 0, 100);
		sprintf(tempBuffer, "Node.recent_log -- %s\n", callNodeArray[i].recent_log);
		strcat(mybuffer, tempBuffer);
		memset(tempBuffer, 0, 100);
	}
	*buffer_location = mybuffer;
	*eof = 1;
	return 5000;
}

static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{
	int ret = 0;
	int hash_index = -1;

	struct timespec tempts, diffts;
	
	struct timeval t;
	unsigned int ts, s, m, h;
	char temp_log[MAX_LOG_LINE_SIZE] = "";


	if ( !toggle_monitored_int || (current_uid() != uid_monitored_int))
		return 0;

	if(log_offset == MAX_LOG_LINES){
		log_offset = 0;
		log_cycle_flag = 1;
	}
		
	num_calls++;

	do_gettimeofday(&t);
	ts = t.tv_sec;
	s = ts%60;
	ts /= 60;
	m = ts%60;
	ts /= 60;
	h = ts%24;

	switch (regs->ax) {   //CHANGE MICRO SECOND TO 6 DIGITS AND REG->AX TO 3 DIGITS
		
		case __NR_access:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|access U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 0;
			break;
		case __NR_brk:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|brk    U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 1;
			break;
		case __NR_chdir:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|chdir  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 2;
			break;
		case __NR_chmod:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|chmod  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 3;
			break;
		case __NR_clone:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|clone  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 4;
			break;
		case __NR_close:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|close  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 5;
			break;
		case __NR_dup:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|dup    U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 6;
			break;
		case __NR_dup2:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|dup2   U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 7;
			break;
		case __NR_execve:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|execve U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 8;
			break;
		case __NR_exit_group:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|exit_g U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 9;
			break;		
		case __NR_fcntl:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|fcntl  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 10;
			break;		
		case __NR_fork:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|fork   U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 11;
			break;		
		case __NR_getdents:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|gdents U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 12;
			break;	
		case __NR_getpid:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|getpid U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 13;
			break;
		case __NR_gettid:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|gettid U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 14;
			break;
		case __NR_ioctl:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|ioctl  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 15;
			break;
		case __NR_lseek:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|lseek  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 16;
			break;
		case __NR_mkdir:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|mkdir  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 17;
			break;
		case __NR_mmap:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|mmap   U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 18;
			break;
		case __NR_munmap:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|munmap U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 19;
			break;
		case __NR_open:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|open   U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 20;
			break;
		case __NR_pipe:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|pipe   U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 21;
			break;
		case __NR_read:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|read   U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 22;
			break;
		case __NR_rmdir:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|rmdir  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 23;
			break;
		case __NR_select:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|select U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 24;
			break;
		case __NR_stat:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|stat   U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 25;
			break;
		case __NR_fstat:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|fstat  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 26;
			break;
		case __NR_lstat:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|lstat  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 27;
			break;
		case __NR_wait4:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|wait4  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
			hash_index = 28;
			break;
		case __NR_write:
			sprintf(temp_log, "%02d:%02d:%02d:%06d|write  U: %04d S: %03lu PID: %05d TGID: %05d\n", 
				h, m, s, (int)t.tv_usec, current_uid(), regs->ax, current->pid, current->tgid);
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
		memcpy(log_ptr[log_offset++], temp_log, MAX_LOG_LINE_SIZE);
	}

	memcpy(callNodeArray[hash_index].recent_log, temp_log, MAX_LOG_LINE_SIZE);

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

	int ret, i = 0, logs_sent = 0, temp;
	
	printk("@@@@@@@@@ NUM_SYS: %d, log_offset_read: %d, log_offset: %d, flag: %d\n", 
			num_calls, log_offset_read, log_offset, log_cycle_flag);


       	if(offset < 0 || offset == buffer_length)
		return 0;

	if(log_offset_read == -1){
		if(log_cycle_flag)
			log_offset_read = log_offset;
		else
			log_offset_read = 0;
	}

	if(log_offset_read >= log_offset && (!log_cycle_flag||(log_cycle_flag && log_looped))){
		log_looped = 0;
		log_offset_read = -1;
		printk("!!!!!!!!! RESET\n");
		*eof = 1;
		return 0;
	}

	//The buffer length is always 3072
	memset(buffer, 0, buffer_length);


	//DETERMINE LINES_RETURNABLE
	if(log_cycle_flag) {
		if(log_looped) {
			if((temp = log_offset - log_offset_read) < lines_returnable)
				lines_returnable = temp;
		}
		else {
			if(!(temp = lines_returnable + log_offset_read) > MAX_LOG_LINES) {
				if((temp = temp-MAX_LOG_LINES) > log_offset)
					lines_returnable = temp - (temp-log_offset);
			}
		}
	}
	else {
		if((temp = log_offset - log_offset_read) < lines_returnable)
			lines_returnable = temp;
	}


	//START SENDING
	for (i=log_offset_read; i< MAX_LOG_LINES; i++){
		if((logs_sent++ > lines_returnable))
			break;
		strcat(buffer, log_ptr[i]);
	}


	//SEND IF LOOP
	if(log_cycle_flag){
		log_looped = 1;
		for(i=0; i<log_offset; i++){
			if(logs_sent++ > lines_returnable)
				break;
			strcat(buffer, log_ptr[i]);
		}
	}

	logs_sent--;

	log_offset_read = log_offset_read +  logs_sent;
	if(log_offset_read > MAX_LOG_LINES){
		log_offset_read -= MAX_LOG_LINES;
	}
	
//	*eof = 1;

	printk("########## Num_Sent: %d ###############\n", logs_sent);

        ret = buffer_length;
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

	//Flag File
	sysmon_log_Entry = create_proc_entry(sysmon_flags, 0600, NULL);
	if(sysmon_log_Entry == NULL){
		remove_proc_entry(sysmon_flags, NULL);
		return -ENOMEM;
	}

	sysmon_log_Entry->read_proc = sysmon_flag_read;
	sysmon_log_Entry->mode = S_IFREG | S_IRUGO;
	sysmon_log_Entry->uid = 0;
	sysmon_log_Entry->gid = 0;
	sysmon_log_Entry->size = SYSMON_FLAGS_MAXSIZE;

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
	remove_proc_entry(sysmon_flags, NULL);
}
