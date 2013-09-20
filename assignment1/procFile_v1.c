/* Joe Greubel and Siddharth Choudhary - Key Pair User Lookup System - Sept 19, 2013 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>

#define userdir "__usernames"
#define MAX_USERS 1000
#define USERNAME_MAX_LENGTH 20

/* 20 character long usernames + null terminator */
char usernamelist[MAX_USERS][USERNAME_MAX_LENGTH + 1];
int num_users = 0;

struct proc_dir_entry *procFileList[MAX_USERS];
struct proc_dir_entry *usernameProcFile;

int procfileRead(char *buffer, char **buffer_location, off_t offset, int buffer_lenght, int *eof, void *data)
{
	int ret;

	//Get Current User and Get File Name

	if(offset > 0)
	{
		ret = 0;
	}
	else
	{
		//Check if Current_User == File_Username

		ret = sprintf(buffer, "HelloWorld!\n");
	}

	return ret;
}

int usernamesFileRead(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{

	int ret;

	if(offset > 0)
	{
		ret = 0;
	}
	else
	{
		char* usernameBuffer = "";
		int i;

		for(i=0; i<num_users; i++) {
			usernameBuffer += username_list[i];
			usernameBuffer += '\n'; 
		}
		ret = sprtinf(buffer, usernameBuffer); 
	}

	return ret;

}

int usernamesFileWrite(struct file *file, const char *buffer, unsigned long count, void *data) {

	int len = count;
	char* = writtenData;

	if(count > 8192) len = 8192;

	if(copy_from_user(writtenData, buffer, len))
		return -EINVAL;

	//SEE WHAT USER WROTE AND ACT ACCORDINGLY

	num_users++;
	return count;
}

void keyPairFileCreation(char* username) {

	procFileList[num_users] = create_proc_entry(username, 0444, NULL);

	if(keyFile == NULL)
	{
		remove_proc_entry(username, NULL);
		return -ENOMEM;
	}

	procFileList[num_users]->read_proc = procfs_read;
	procFileList[num_users]->write_proc = .....
	procFileList[num_users]->mode = S_IFREG | S_IRUGO;
	procFileList[num_users]->uid = 0;
	procFileList[num_users]->gid = 0;
	procFileList[num_users]->size = 4096;

	username_list[num_users] = username;
}

void usernamesFileCreation(){

	usernameProcFile = create_proc_entry(userdir, 0664, NULL);

	if (usernameProcFile == NULL)
	{
		remove_proc_entry(userdir, NULL);
		return -ENOMEM;
	}

	usernameProcFile->read_proc = usernamesFileRead;
	usernameProcFile->write_proc = .....
	usernameProcFile->mode = S_IFREG | S_IRUGO;
	usernameProcFile->uid = 0;
	usernameProcFile->gid = 0;
	usernameProcFile->size = 8192;
}

int init_module()
{
	usernamesFileCreation();
}

void cleanup_module()
{
	int i;
	for(i=0; i<num_users; i++) {
		char* username = username_list[i];
		remove_proc_entry(username, NULL);
	}
	remove_proc_entry(userdir, NULL);
}
