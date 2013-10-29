#include <stdio.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#define REPEATS 100

int main(void){

	struct timeval start, end, timediff;
	FILE *dataforgraph, *dummy;
	int rc, i;
	long int temp=0;
	int buf[10];

	dummy = fopen("dummy", "w+");

	dataforgraph = fopen("dataforgraph.csv", "w");
	
	fprintf(dataforgraph, "Systemcall-access\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_access, "dummy", R_OK);	
		gettimeofday(&end, NULL);

		timersub(&start, &end, &timediff);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-write\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_write, buf, 10);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-brk\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");


	fprintf(dataforgraph, "Systemcall-chdir\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");


	fprintf(dataforgraph, "Systemcall-chmod\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-clone\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-close\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-dup\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-dup2\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-execve\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-exit_group\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-fcntl\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-fork\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-getdents\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-getpid\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-gettid\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-ioctl\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-lseek\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-mkdir\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-mmap\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");


	fprintf(dataforgraph, "Systemcall-munmap\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-open\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-pipe\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-read\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-rmdir\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}

	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-select\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}


	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-stat\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}


	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-fstat\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}


	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-lstat\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}


	fprintf(dataforgraph, "\n");

	fprintf(dataforgraph, "Systemcall-wait4\t");

	for(i=0; i<REPEATS; i++){
		gettimeofday(&start, NULL);
		rc = syscall(SYS_chmod, "dummy", 0444);	
		gettimeofday(&end, NULL);

		timersub(&timediff, &end, &start);
		temp = timediff.tv_sec * 1000 + timediff.tv_usec/1000;

		fprintf(dataforgraph, "%ld\t", temp);
	}


	fprintf(dataforgraph, "\n");

	return 0;
}
