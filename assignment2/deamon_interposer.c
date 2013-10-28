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

	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	char read_flag=0;
	FILE *infile, *outfile, *log_file;

	char tempBuffer[50000];


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
	
	pid_t pid, sid; 	//process and session id.

	pid = fork();		//fork from parent
				//NOTE: Should double fork to avoid zomnies
	if(pid > 0)
		exit(EXIT_FAILURE);
	if(pid < 0)		//Got a good pid so exit the parent
		exit(EXIT_SUCCESS);

	umask(0);		//change the file mode mask
	
	//custom logging by deamon
	
	sid = setsid();		//create a SID for child process
	if(sid < 0)
		exit(EXIT_FAILURE);
	if((chdir("/")) < 0)
		exit(EXIT_FAILURE);

	close(STDIN_FILENO);	//close standard files not accessible so closed 
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	//Do deamon specific initialized

	//The main infinite loop
	while(1){
	
		//printf("Some print......\n");
		read_flag = fgetc(infile);
		rewind(infile);

		if(read_flag == '1'){

			fputc('0', infile);
			rewind(infile);

			outfile = fopen(argv[2], "w");
			if(outfile == NULL)
				exit(EXIT_FAILURE);

			log_file = fopen("/proc/sysmon_log", "r");
			
			fread(tempBuffer, 1, 50000, log_file);
			fwrite(tempBuffer, 1, 50000, outfile);

			fclose(log_file);

			fprintf(outfile, "Testing.....\n"); //TODO do all the log printing
			fclose(outfile);
		}

		//Do stuff
		sleep(10);	//sleep for some time to stop polling quickly
	}
	exit(EXIT_SUCCESS);
}
