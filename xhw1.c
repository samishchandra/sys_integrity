#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include "sys_integrity_args.h"

#define __NR_xintegrity	349	/* our private syscall number */
#define BUFLEN 16

#ifdef EXTRA_CREDIT
int execute_mode1(const char *filename, const char *algo)
#else
int execute_mode1(const char *filename)
#endif
{
	int retval;
	struct sys_integrity_args1 args1;
	args1.flag = '1';
	args1.filename = filename;
	args1.ibuf = (unsigned char*)malloc(sizeof(unsigned char) * BUFLEN);
	args1.ilen = BUFLEN;
	#ifdef EXTRA_CREDIT
		args1.algo = algo;
	#endif
	int i;

	retval = syscall(__NR_xintegrity, (void*) &args1);
	if (retval == 0) {
		printf("syscall returned %d\n", retval);
		printf("Integrity value: ");
		for(i=0;i<args1.ilen;i++)
			printf("%x", args1.ibuf[i]);
		printf("\n");
	}
	else {
		printf("syscall returned %d (errno=%d)\n", retval, errno);
		printf("%s\n", strerror(errno));
	}

	return retval;
}

#ifdef EXTRA_CREDIT
int execute_mode2(const char *filename, char *credbuf, const char *algo)
#else
int execute_mode2(const char *filename, char *credbuf)
#endif
{
	int retval;
	struct sys_integrity_args2 args2;
	args2.flag = '2';
	args2.filename = filename;
	args2.ibuf = (unsigned char*)malloc(sizeof(unsigned char) * BUFLEN);
	args2.ilen = BUFLEN;
	args2.credbuf = (unsigned char*)credbuf;
	args2.clen = strlen(credbuf);
	#ifdef EXTRA_CREDIT
		args2.algo = algo;
	#endif
	int i;

	retval = syscall(__NR_xintegrity, (void*) &args2);
	if (retval == 0) {
		printf("syscall returned %d\n", retval);
		printf("Integrity value: ");
		for(i=0;i<args2.ilen;i++)
			printf("%x", args2.ibuf[i]);
		printf("\n");		
	}
	else {
		printf("syscall returned %d (errno=%d)\n", retval, errno);
		printf("%s\n", strerror(errno));
	}

	return retval;
}

/* read from sample file */
void sample_read_file(int fd) {
	char ch;
	read(fd, &ch, sizeof(char));
	printf("%c\n", ch);
}

#ifdef EXTRA_CREDIT
int execute_mode3(const char *filename, const char *algo)
#else
int execute_mode3(const char *filename)
#endif
{
	int retval;
	struct sys_integrity_args3 args3;
	args3.flag = '3';
	args3.filename = filename;
	args3.oflag = O_CREAT;
	args3.mode = O_RDONLY;
	#ifdef EXTRA_CREDIT
		args3.algo = algo;
	#endif

	retval = syscall(__NR_xintegrity, (void*) &args3);
	if (retval > 0) {
		printf("syscall returned %d\n", retval);
		sample_read_file(retval);
		close(retval);
	}
	else {
		printf("syscall returned %d (errno=%d)\n", retval, errno);
		printf("%s\n", strerror(errno));
	}

	return retval;
}

int main(int argc, char *argv[])
{
	int retval;
	unsigned int flag;

	#ifdef EXTRA_CREDIT
		if(argc<4) {
			printf("Insufficient number of arguments!!\n");
			printf("Usage: ./[exe] [flag] [filename] [algo]\n");
			retval = -EINVAL;
			goto normal_exit;
		}

		flag = atoi(argv[1]);

		if(flag == 2 && argc < 5) {
			printf("Insufficient number of arguments!!\n");
			printf("Usage: ./[exe] [flag] [filename] [password] [algo]\n");
			retval = -EINVAL;
			goto normal_exit;
		}

		if(flag == 1)
			retval = execute_mode1(argv[2], argv[3]);
		else if(flag == 2)
			retval = execute_mode2(argv[2], argv[3], argv[4]);
		else if(flag == 3)
			retval = execute_mode3(argv[2], argv[3]);
		else {
			printf("Invalid Mode!!\n");
			printf("Modes allowed: 1, 2, 3\n");
			retval = -EINVAL;
			goto normal_exit;
		}
	#else
		if(argc<3) {
			printf("Insufficient number of arguments!!\n");
			printf("Usage: ./[exe] [flag] [filename]\n");
			retval = -EINVAL;
			goto normal_exit;
		}

		flag = atoi(argv[1]);

		if(flag == 2 && argc < 4) {
			printf("Insufficient number of arguments!!\n");
			printf("Usage: ./[exe] [flag] [filename] [password]\n");
			retval = -EINVAL;
			goto normal_exit;
		}

		if(flag == 1)
			retval = execute_mode1(argv[2]);
		else if(flag == 2)
			retval = execute_mode2(argv[2], argv[3]);
		else if(flag == 3)
			retval = execute_mode3(argv[2]);
		else {
			printf("Invalid mode!!\n");
			printf("Usage: ./[exe] [flag (1, 2, 3)] [filename] [password]\n");
			retval = -EINVAL;
			goto normal_exit;
		}

	#endif

normal_exit:
	exit(retval);
	
}

