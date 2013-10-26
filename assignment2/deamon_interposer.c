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

	//Before demonizing phase. Read command line parameters for config.
	if(argc != 3)		//incorrect parameters print error
	{
		printf("ERROR: Incorrect parameters.\nUsage: deamon_interpos <input_file_to_be_read> <file_to_write_the_log>");
		return -1;
	}

	//Open file handlers.
	FILE *infile = fopen(argv[1], "r");
	if(infile == NULL)
		exit(EXIT_FAILURE);
	
	FILE *outfile = fopen(argv[2], "w");
	if(outfile == NULL)
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

	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	//The main infinite loop
	while(1){
		if((read = getline(&line, &len, infile)) != -1){}

		//Do stuff

		
		sleep(30);	//sleep for some time to stop polling quickly
	}
	exit(EXIT_SUCCESS);
}
