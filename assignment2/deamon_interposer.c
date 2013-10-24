#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>

int main(void){
	
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
		//Do stuff
		
		sleep(30);	//sleep for some time to stop polling quickly
	}
	exit(EXIT_SUCCESS);
}
