#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
//#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <sys/inotify.h>

int main(int argc, char *argv[]){

	char read_flag=0;
	FILE *infile=NULL, *outfile=NULL, *log_file=NULL;
	char tempBuffer[4000000]="";
	char tempBuffer2[4000]="";
	int i, temp;
	pid_t pid, sid; 	//process and session id.

	//Before demonizing phase. Read command line parameters for config.
	if(argc != 3)		//incorrect parameters print error
	{
		printf("ERROR: Incorrect parameters.\nUsage: deamon_interpos <input_file_to_be_read> <file_to_write_the_log>\n");
		return -1;
	}
	
	//Open file handlers.
	infile = fopen("/root/linux/assignment2/infile.txt", "w+");
	if(infile == NULL)
		exit(EXIT_FAILURE);

	outfile = fopen("outfile.txt", "w");
	if(outfile == NULL)
		exit(EXIT_FAILURE);

	log_file = fopen("/proc/sysmon_log", "r");
	if(log_file == NULL)
		exit(EXIT_FAILURE);

	pid = fork();		//fork from parent				//NOTE: Should double fork to avoid zombies
	if(pid < 0)
		exit(EXIT_FAILURE);
	if(pid > 0)		//Got a good pid so exit the parent
		exit(EXIT_SUCCESS);

	umask(0);		//change the file mode mask
	
	sid = setsid();		//create a SID for child process
	if(sid < 0)
		exit(EXIT_FAILURE);
	if((chdir("/")) < 0)
		exit(EXIT_FAILURE);

	//close standard files not accessible so closed
	close(STDIN_FILENO);	 
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

//**********************************************************************//
	while(1){
		read_flag = fgetc(infile);
		rewind(infile);

		if(read_flag == '1'){
			fputc('0', infile);
			rewind(infile);
			
			for (i=0; i<10; i++){					//Fix for complete buffer change to 1000
				fread(tempBuffer2, 1, 4000, log_file);
				strcat(tempBuffer, tempBuffer2);
				rewind(log_file);
//				if(tempBuffer2[0] == '\0')
//					break;
				memset(tempBuffer2, 0, 4000);
			}
			fwrite(tempBuffer, 1, 5000000, outfile);
			memset(tempBuffer, 0, 5000000);
		}
		sleep(5);
	}

	fclose(log_file);
	fclose(infile);
	fclose(outfile);
	exit(EXIT_SUCCESS);
}
