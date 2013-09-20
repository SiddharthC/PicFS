/* create a "file" in /proc */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>

#define procfs_name "helloworld"
#define procfs_userdir "__usernames"

/*structure to hold information about /proc file */

struct proc_dir_entry *Test_Proc_File;
struct proc_dir_entry *Username_Proc_File;


int procfile_read(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data)
{
	int ret;

	printk(KERN_INFO "procfile_read (/proc/%s) called\n", procfs_name);

	if(offset > 0)
	{
		ret=0;
	}
	else
	{
		ret = sprintf(buffer, "HelloWorld!\n");
	}
	return ret;
}

int procfile_dir_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{

	int ret;

	printk(KERN_INFO "procfile_read (/proc/%s) called\n", procfs_userdir);

	if(offset > 0)
	{
		
		ret=0;
	}

	return ret;

}

void username_file_creation(){

	username_file_creation();

	Username_Proc_File = create_proc_entry(procfs_userdir, 0664, NULL);

	if (Username_Proc_File == NULL)
	{
		remove_proc_entry (procfs_userdir, NULL);
		printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", procfs_userdir);
		return -ENOMEM;
	}

	add

	Username_Proc_File->read_proc = procfile_dir_read;
	Username_Proc_File->mode = S_IFREG | S_IRUGO;
	Username_Proc_File->uid = 0;
	Username_Proc_File->gid = 0;
	Username_Proc_File->size = 1024;

	printk(KERN_INFO "/proc/%s created\n", procfs_userdir);

}

int init_module()
{
	

	Test_Proc_File = create_proc_entry(procfs_name, 0644, NULL);

	if (Test_Proc_File == NULL)
	{
		remove_proc_entry (procfs_name, NULL);
		printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", procfs_name);
		return -ENOMEM;
	}

	Test_Proc_File->read_proc = procfile_read;
	Test_Proc_File->mode = S_IFREG | S_IRUGO;
	Test_Proc_File->uid = 0;
	Test_Proc_File->gid = 0;
	Test_Proc_File->size = 37;

	printk(KERN_INFO "/proc/%s created\n", procfs_name);
	return 0;
}

void cleanup_module()
{
	remove_proc_entry(procfs_name, NULL);
	printk(KERN_INFO "/proc/%s removed\n", procfs_name);
}
