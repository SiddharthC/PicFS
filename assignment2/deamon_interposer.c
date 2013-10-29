#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>

int main(int argc, char *argv[]){

	char read_flag=0;
	FILE *infile, *outfile, *log_file;
	char tempBuffer[5000000]="";
	char tempBuffer2[4000]="";
	int i, temp;

	//Before demonizing phase. Read command line parameters for config.
	if(argc != 3)		//incorrect parameters print error
	{
		printf("ERROR: Incorrect parameters.\nUsage: deamon_interpos <input_file_to_be_read> <file_to_write_the_log>\n");
		return -1;
	}
	
	//Open file handlers.
	infile = fopen(argv[1], "w+");
	if(infile == NULL)
		exit(EXIT_FAILURE);
	
	outfile = fopen(argv[2], "w");
	if(outfile == NULL)
		exit(EXIT_FAILURE);

	pid_t pid, sid; 	//process and session id.

	pid = fork();		//fork from parent
				//NOTE: Should double fork to avoid zombies
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
	//close(STDIN_FILENO);	 
	//close(STDOUT_FILENO);
	//close(STDERR_FILENO);



//**********************************************************************//
	while(1){

		read_flag = fgetc(infile);
		rewind(infile);

		if(read_flag == '1'){

			fputc('0', infile);
			rewind(infile);
			
			for (i=0; i<1000; i++){

				log_file = fopen("/proc/sysmon_log", "r");
				if(!fread(tempBuffer2, 1, 4000, log_file))
					break;
				strcat(tempBuffer, tempBuffer2);
				memset(tempBuffer2, 0, 4000);
				fclose(log_file);
			}
			fwrite(tempBuffer, 1, 5000000, outfile);

			memset(tempBuffer, 0, 5000000);
			printf("PRINTED!\n");
			
		}

		sleep(5);
	}

	fclose(outfile);
	fclose(infile);
	exit(EXIT_SUCCESS);
}
