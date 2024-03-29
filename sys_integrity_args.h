#define PASSWD "password"
#ifdef EXTRA_CREDIT
	#undef EXTRA_CREDIT
#endif
#define EXTRA_CREDIT

/* struct for mode1 */
typedef struct sys_integrity_args1 {
	unsigned char flag; // flags to set the mode (1, 2, 3, etc. per mode)
	const char *filename; // the name of the file to verify integrity
	unsigned char *ibuf; // the integrity value (e.g., MD5 value) buffer
	unsigned int ilen; // length of ibuf
#ifdef EXTRA_CREDIT
	const char *algo; // name of the crypto algorithm
#endif
} sys_integrity_args1;

/* struct for mode2 */
typedef struct sys_integrity_args2 {
	unsigned char flag; // flags to set the mode (1, 2, 3, etc. per mode)
	const char *filename; // the name of the file to compute integrity
	unsigned char *ibuf; // the integrity value (e.g., MD5 value) buffer
	unsigned int ilen; // length of ibuf
	unsigned char *credbuf; // credentials buffer
	unsigned int clen; // length of credbuf
#ifdef EXTRA_CREDIT
	const char *algo; // name of the crypto algorithm
#endif
} sys_integrity_args2;

/* struct for mode3 */
typedef struct sys_integrity_args3 {
	unsigned char flag; // flags to set the mode (1, 2, 3, etc. per mode)
	const char *filename; // the name of the file to open+verify
	int oflag; // open flags -- same as open(2)
	int mode; // create mode flags -- same as open(2)
#ifdef EXTRA_CREDIT
	const char *algo; // name of the crypto algorithm
#endif
} sys_integrity_args3;
