/* Author: Samish Chandra Kolli
 * Year: 2013
 * This file consists of the loadable kernel module. The function pointer 
 * which is hooked up to the system call is made to point to a function "xintegrity"
 * which consists of the implementation of the system call. This loadable 
 * kernel module can be loaded using "insmod".
 */

#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/slab.h> // for kmalloc from slab.h, GFP_KERNEL from gfp.h 
#include <linux/uaccess.h> // for VERIFY_READ, access_ok, copy_from_user
#include <linux/fs.h> // for getname, putname, filp_open
#include <linux/err.h> // for ISERR, PTR_ERR
#include <linux/xattr.h> // for vfs_getxattr, vfs_setxattr
#include <linux/scatterlist.h> // for scatterlist
#include <linux/crypto.h> // for crypto_alloc_hash, crypto_hash_update, crypto_hash_final, ...
#include <linux/file.h> // get_unused_fd
#include <asm/page.h> // for PAGE_SIZE
#include <asm/string.h> // strnlen_user
#include "sys_integrity_args.h"

/* Function pointer which hooks the system call and loadable kernel module */
asmlinkage extern long (*sysptr)(void *args);

#define MINFILENAME 2
#define MAXFILENAME 250

#define MINILEN 16
#define MAXILEN 50
#define CHUNKSIZE 10 // ??? replace with PAGE_SIZE
#define ATTRPREFIX "user."
#define DEFAULTALGO "md5"
#define ATTRALGO "user.algo"

/* Function to check the access to all arguments.
 * Input: pointer to struct passed by the user
 * Output: return 0 if all arguments are valid; else return respective -ERRNO
 * Following are the checks:
 * 1. check if the arguments are NULL and access_ok
 * 2. check the access to filename
 * 3. check the constraints on filename
 * 4. check the access to ibuf
 * 5. check the access to algo
 * 6. check the constraints on algo, strnlen_user is used to find the length of the string
 */
long check_access_args1(sys_integrity_args1 *args) {
	long retval = 0;
	unsigned int ilen;

	/* check whether args is a valid address in user space */
	if(args == NULL || !access_ok(VERIFY_READ, args, sizeof(sys_integrity_args1))) {
		printk("check_access_args1: cannot access sys_integrity_args1 *args\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	/* check access to filename */
	if(args->filename == NULL || 
		!access_ok(VERIFY_READ, args->filename, strnlen_user(args->filename, MAXFILENAME))) {
		printk("check_access_args1: cannot access args->filename\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	/* check whether length of filename matches the constraints */
	if((strnlen_user(args->filename, MAXFILENAME) < MINFILENAME) || 
		(strnlen_user(args->filename, MAXFILENAME) > MAXFILENAME)) {
		printk("check_access_args1: length of filename is too short or too long\n");
		retval = -ENAMETOOLONG;
		goto normal_exit;
	}

	/* read ilen from the user address */
	if(get_user(ilen, &(args->ilen))) {
		printk("check_access_args1: cannot read args->ilen\n");
		retval = -EINVAL;
		goto normal_exit;
	}

	/* check ilen against MINILEN */
	if(ilen < MINILEN || ilen > MAXILEN) {
		printk("check_access_args1: ilen too short or too long\n");
		retval = -EINVAL;
		goto normal_exit;
	}

	/* check access to ibuf */
	if(args->ibuf == NULL || 
		!access_ok(VERIFY_WRITE, args->ibuf, ilen)) {
		printk("check_access_args1: cannot access args->ibuf\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	/* check access to ibuf */
	if(args->ibuf == NULL || 
		!access_ok(VERIFY_WRITE, args->ibuf, ilen)) {
		printk("check_access_args1: cannot access args->ibuf\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	#ifdef EXTRA_CREDIT
	/* check access to algo */
	if(args->algo == NULL || 
		!access_ok(VERIFY_READ, args->algo, strnlen_user(args->algo, CRYPTO_MAX_ALG_NAME))) {
		printk("check_access_args1: cannot access args->algo\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	/* check whether length of algo matches the constraints */
	if(strnlen_user(args->algo, CRYPTO_MAX_ALG_NAME) > CRYPTO_MAX_ALG_NAME) {
		printk("check_access_args1: length of algo too long\n");
		retval = -ENAMETOOLONG;
		goto normal_exit;
	}
	#endif

normal_exit:
	return retval;
}

/* Function to copy the arguments from user address-space to kernel address-space.
 * Input: pointer to address of kernel struct args, pointer to the user struct args
 * Output: return 0 if copy is successful; else return respective -ERRNO
 * Following are the steps:
 * 1. allocate memory for kernel args (kargs)
 * 2. copy from user args to kernel kargs
 * 3. copy from user filename to kernel filename using getname
 * 4. allocate memory for ibuf in kernel space
 * 5. copy from user ibuf to kernel ibuf
 * 6. copy from user algo to kernel algo using getname
 * 7. free allocated memory accordingly
 */
long copy_from_user_args1(sys_integrity_args1 **kargs, sys_integrity_args1 *args) {
	long retval = 0;
	
	/* allocate memory for kargs */
	*kargs = (sys_integrity_args1 *)kmalloc(sizeof(sys_integrity_args1), GFP_KERNEL);
	if(!(*kargs)) {
		printk("copy_from_user_args1: out of memory for kargs\n");
		retval = -ENOMEM;
		goto normal_exit;
	}

	/* copy user args to kernel kargs */
	if(copy_from_user((*kargs), args, sizeof(sys_integrity_args1))) {
		printk("copy_from_user_args1: cannot copy_from_user for kargs\n");
		retval = -EFAULT;
		goto free_kargs;
	}

	/* copy filename to kernel address space */
	(*kargs)->filename = getname(args->filename);
	if(!(*kargs)->filename || IS_ERR((*kargs)->filename)) {
		printk("copy_from_user_args1: cannot getname for kargs->filename\n");
		retval = PTR_ERR((*kargs)->filename);
		goto free_filename;
	}

	/* allocate memory for ibuf */
	(*kargs)->ibuf = (unsigned char *)kmalloc((*kargs)->ilen, GFP_KERNEL);
	if(!(*kargs)->ibuf) {
		printk("copy_from_user_args1: out of memory for kargs->ibuf\n");
		retval = -ENOMEM;
		goto free_filename;
	}

	/* copy args->ibuf to kargs->ibuf */
	if(copy_from_user((*kargs)->ibuf, args->ibuf, (*kargs)->ilen)) {
		printk("copy_from_user_args1: cannot copy_from_user for kargs->ibuf\n");
		retval = -EFAULT;
		goto free_ibuf;
	}

	#ifdef EXTRA_CREDIT
	/* copy algo to kernel address space */
	(*kargs)->algo = getname(args->algo);
	if(!(*kargs)->algo || IS_ERR((*kargs)->algo)) {
		printk("copy_from_user_args1: cannot getname for kargs->algo\n");
		retval = PTR_ERR((*kargs)->algo);
		goto free_ibuf;
	}
	#endif

	goto normal_exit;

free_ibuf:
	kfree((*kargs)->ibuf);
free_filename:
	putname((*kargs)->filename);
free_kargs:
	kfree((*kargs));
normal_exit:
	return retval;

}

/* Core method used for executing mode1 system call
 * Input: filename, buffer to store integrity value, size of integrity value, algo to be used
 * Output: return 0 if the all steps are successful; else return respective -ERRNO
 * Following are the steps:
 * 1. open the file using filp_open
 * 2. check if the read permissions exist
 * 3. allocate memory to manufacture attribute name
 * 4. use vfs_getxattr to fill the appropriate extended attribute value
 * 5. free the allocated memory accordingly
 */
long get_integrity(const char *filename, unsigned char *ibuf, unsigned int ilen, const char *algo) {
	long retval = 0;
	char *attrname;
    struct file *filp;

    filp = filp_open(filename, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
    	printk("get_integrity: cannot open file\n");
    	retval = (int) PTR_ERR(filp);
		goto normal_exit;
    }

    /* check whether read is available on the file */
    if (!filp->f_op->read) {
	   printk("get_integrity: cannot read the file\n");
		retval = -ENOENT;
		goto filp_exit;
	}

	/* fabricate the xattribute name */
	attrname = (char *)kmalloc(strlen(ATTRPREFIX) + strlen(algo), GFP_KERNEL);
	if(!attrname) {
		printk("get_integrity: out of memory for attrname\n");
		retval = -ENOMEM;
		goto filp_exit;
	}

	strcpy(attrname, ATTRPREFIX);
	strcat(attrname, algo);
    
    retval = vfs_getxattr(filp->f_path.dentry, attrname, ibuf, ilen);
    if(retval<0) {
    	printk("get_integrity: not able to fetch existing integrity value\n");
    	goto free_attrname;
    }

    retval = 0;

free_attrname:
	kfree(attrname);
filp_exit:
    filp_close(filp, NULL);
normal_exit:
	return retval;
}

/* Wrapper method for executing mode1 system call
 * Fetch the existing integrity value of file from xattr
 * Input: pointer to user args passed to the system call
 * Output: return 0 if the all steps are successful; else return respective -ERRNO
 * Following are the steps:
 * 1. check the access the user args
 * 2. copy the user args to kernel kargs
 * 3. check if the crypto api supports the algo
 * 4. call get_integrity to get the integrity of the file using the given algo
 * 5. copy the kernel buffer containing the integrity value back to user buffer
 * 6. free the allocated memory accordingly, also free  memory allocated using copy_from_user_args1
 */
long find_integrity(sys_integrity_args1 *args) {
	long retval = 0;
	sys_integrity_args1 *kargs = NULL;

	/* check access to args */
	retval = check_access_args1(args);
	if(retval<0)
		goto normal_exit;

	/* copy args from user to kernel */
	retval = copy_from_user_args1(&kargs, args);
	if(retval<0)
		goto normal_exit;
	printk("Successfully copied args1 to kargs\n");
	printk("filename = %s\n", kargs->filename);
	printk("ilen = %d\n", kargs->ilen);

	#ifdef EXTRA_CREDIT
		retval = crypto_has_alg(kargs->algo, 1, 1);
		if(!retval) {
			printk("find_integrity: crypto algo is not supported\n");
			retval = -EINVAL;
			goto free_args;
		}
		retval = get_integrity(kargs->filename, kargs->ibuf, kargs->ilen, kargs->algo);
	#else
		retval = get_integrity(kargs->filename, kargs->ibuf, kargs->ilen, DEFAULTALGO);
	#endif
	
	if(retval<0)
		goto free_args;
	
	/* copy the existing integrity value to user address space */
	if(copy_to_user(args->ibuf, kargs->ibuf, kargs->ilen)) {
		retval = -EFAULT;
		goto free_args;
	}

free_args:
#ifdef EXTRA_CREDIT
	putname(kargs->algo);
#endif
	kfree(kargs->ibuf);
	putname(kargs->filename);
	kfree(kargs);
normal_exit:
	return retval;
}

/* Function to check the access to all arguments.
 * Input: pointer to struct passed by the user
 * Output: return 0 if all arguments are valid; else return respective -ERRNO
 * Following are the checks:
 * 1. check if the arguments are NULL and access_ok
 * 2. check the access to filename
 * 3. check the constraints on filename
 * 4. check the access to ibuf
 * 5. check the access to credbuf
 * 6. check the access to algo
 * 7. check the constraints on algo, strnlen_user is used to find the length of the string
 */
long check_access_args2(sys_integrity_args2 *args) {
	long retval = 0;
	unsigned int ilen;
	unsigned int clen;

	/* check whether args is a valid address in user space */
	if(args == NULL || !access_ok(VERIFY_READ, args, sizeof(sys_integrity_args2))) {
		printk("check_access_args2: cannot access sys_integrity_args2 *args\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	/* check access to filename */
	if(args->filename == NULL || 
		!access_ok(VERIFY_READ, args->filename, strnlen_user(args->filename, MAXFILENAME))) {
		printk("check_access_args2: cannot access args->filename\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	/* check whether length of filename matches the constraints */
	if((strnlen_user(args->filename, MAXFILENAME) < MINFILENAME) || 
		(strnlen_user(args->filename, MAXFILENAME) > MAXFILENAME)) {
		printk("check_access_args2: length of filename is too short or too long\n");
		retval = -ENAMETOOLONG;
		goto normal_exit;
	}

	/* read ilen from the user address */
	if(get_user(ilen, &(args->ilen))) {
		printk("check_access_args2: cannot read args->ilen\n");
		retval = -EINVAL;
		goto normal_exit;
	}

	/* check ilen against MINILEN */
	if(ilen < MINILEN || ilen > MAXILEN) {
		printk("check_access_args2: ilen too short or too long\n");
		retval = -EINVAL;
		goto normal_exit;
	}

	/* check access to ibuf */
	if(args->ibuf == NULL || 
		!access_ok(VERIFY_WRITE, args->ibuf, ilen)) {
		printk("check_access_args2: cannot access args->ibuf\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	/* read clen from the user address */
	if(get_user(clen, &(args->clen))) {
		printk("check_access_args2: cannot read args->clen\n");
		retval = -EINVAL;
		goto normal_exit;
	}

	/* check clen against MINILEN */
	if(clen <= 0) {
		printk("check_access_args2: clen too short\n");
		retval = -EINVAL;
		goto normal_exit;
	}

	/* check access to credbuf */
	if(args->credbuf == NULL || 
		!access_ok(VERIFY_READ, args->credbuf, clen)) {
		printk("check_access_args2: cannot access args->credbuf\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	#ifdef EXTRA_CREDIT
	/* check access to algo */
	if(args->algo == NULL || 
		!access_ok(VERIFY_READ, args->algo, strnlen_user(args->algo, CRYPTO_MAX_ALG_NAME))) {
		printk("check_access_args1: cannot access args->algo\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	/* check whether length of algo matches the constraints */
	if(strnlen_user(args->algo, CRYPTO_MAX_ALG_NAME) > CRYPTO_MAX_ALG_NAME) {
		printk("check_access_args1: length of algo too long\n");
		retval = -ENAMETOOLONG;
		goto normal_exit;
	}
	#endif

normal_exit:
	return retval;
}

/* Function to copy the arguments from user address-space to kernel address-space.
 * This function also checks whether passwords match or not.
 * Input: pointer to address of kernel struct args, pointer to the user struct args
 * Output: return 0 if copy is successful; else return respective -ERRNO
 * Following are the steps:
 *  1. allocate memory for kernel args (kargs)
 *  2. copy from user args to kernel kargs
 *  3. allocate memory for credbuf in kernel space
 *  4. copy from user credbuf to kernel credbuf
 *  5. check if the passwords match, else return -EACCES
 *  6. copy from user filename to kernel filename using getname
 *  7. allocate memory for ibuf in kernel space
 *  8. copy from user ibuf to kernel ibuf
 *  9. copy from user algo to kernel algo using getname
 * 10. free allocated memory accordingly
 */
long copy_from_user_args2(sys_integrity_args2 **kargs, sys_integrity_args2 *args) {
	long retval = 0;
	
	/* allocate memory for kargs */
	*kargs = (sys_integrity_args2 *)kmalloc(sizeof(sys_integrity_args2), GFP_KERNEL);
	if(!(*kargs)) {
		printk("copy_from_user_args2: out of memory for kargs\n");
		retval = -ENOMEM;
		goto normal_exit;
	}

	/* copy user args to kernel kargs */
	if(copy_from_user((*kargs), args, sizeof(sys_integrity_args2))) {
		printk("copy_from_user_args2: cannot copy_from_user for kargs\n");
		retval = -EFAULT;
		goto free_kargs;
	}

	/* allocate memory for credbuf */
	(*kargs)->credbuf = (unsigned char *)kmalloc((*kargs)->clen, GFP_KERNEL);
	if(!(*kargs)->credbuf) {
		printk("copy_from_user_args2: out of memory for kargs->credbuf\n");
		retval = -ENOMEM;
		goto free_kargs;
	}

	/* copy args->credbuf to kargs->credbuf */
	if(copy_from_user((*kargs)->credbuf, args->credbuf, (*kargs)->clen)) {
		printk("copy_from_user_args2: cannot copy_from_user for kargs->credbuf\n");
		retval = -EFAULT;
		goto free_credbuf;
	}

	(*kargs)->credbuf[(*kargs)->clen] = '\0';
	printk("PASSWD: %s\n", (*kargs)->credbuf);

	/* error if passwords doesn't match */
	if(strcmp((*kargs)->credbuf, PASSWD)) {
		retval = -EACCES;
		goto free_credbuf;
	}

	/* copy filename to kernel address space */
	(*kargs)->filename = getname(args->filename);
	if(!(*kargs)->filename || IS_ERR((*kargs)->filename)) {
		printk("copy_from_user_args2: cannot getname for kargs->filename\n");
		retval = PTR_ERR((*kargs)->filename);
		goto free_filename;
	}

	/* allocate memory for ibuf */
	(*kargs)->ibuf = (unsigned char *)kmalloc((*kargs)->ilen, GFP_KERNEL);
	if(!(*kargs)->ibuf) {
		printk("copy_from_user_args2: out of memory for kargs->ibuf\n");
		retval = -ENOMEM;
		goto free_filename;
	}

	/* copy args->ibuf to kargs->ibuf */
	if(copy_from_user((*kargs)->ibuf, args->ibuf, (*kargs)->ilen)) {
		printk("copy_from_user_memory: cannot copy_from_user for kargs->ibuf\n");
		retval = -EFAULT;
		goto free_ibuf;
	}

	#ifdef EXTRA_CREDIT
	/* copy algo to kernel address space */
	(*kargs)->algo = getname(args->algo);
	if(!(*kargs)->algo || IS_ERR((*kargs)->algo)) {
		printk("copy_from_user_args1: cannot getname for kargs->algo\n");
		retval = PTR_ERR((*kargs)->algo);
		goto free_ibuf;
	}
	#endif

	goto normal_exit;

free_ibuf:
	kfree((*kargs)->ibuf);
free_filename:
	putname((*kargs)->filename);
free_credbuf:
	kfree((*kargs)->credbuf);
free_kargs:
	kfree((*kargs));
normal_exit:
	return retval;
}

long update_md5(const char *src, unsigned int len, struct hash_desc *desc) {
	long retval = 0;
	struct scatterlist sg;

	sg_init_one(&sg, src, len);
    retval = crypto_hash_update(desc, &sg, len);
	if(retval) {
		printk("Error updating crypto hash\n");
		goto normal_exit;
	}
   
normal_exit:
	return retval;
}

/* Core method used for executing mode2 system call
 * Input: filename, buffer to store integrity value, size of integrity value, 
 	flag to tell whether to update the integrity value, algo to be used
 * Output: return 0 if the all steps are successful; else return respective -ERRNO
 * Following are the steps:
 * 1. allocate for crypto transform
 * 2. initialize the crypto hash
 * 3. open the file using filp_open
 * 4. check if the read/write permissions exist
 * 5. allocate memory for temp buffer to store the chunks of the file
 * 6. read CHUNKSIZE bytes from the file and update the hash value
 * 7. finalize the hash value and write it to ibuf
 * 3. allocate memory to manufacture attribute name
 * 4. use vfs_setxattr to set the appropriate extended attribute value
 * 5. free the allocated memory accordingly
 */
long compute_integrity(const char *filename, unsigned char *ibuf, unsigned int ilen, 
	unsigned int flag, const char *algo) {
	long retval = 0;
	char *attrname; /* attrname to be stored */
	struct file *filp; /* for opening the file */
    mm_segment_t oldfs; /* used to restore fs */
    int bytes; 
    char *buffer; /* to store a chunk of a file */
    struct hash_desc desc; /* to compute and update integrity value */
    // int i;
	
	desc.flags = 0;
	desc.tfm = crypto_alloc_hash(algo, 0, CRYPTO_ALG_ASYNC);
	if(IS_ERR(desc.tfm)) {
		printk("set_integrity: error attempting to allocate crypto context\n");
		retval = PTR_ERR(desc.tfm);         
		goto normal_exit;
	}
	
	/* initialize the crypto hash */
    retval = crypto_hash_init(&desc);
	if(retval) {
		printk("set_integrity: error initializing crypto hash\n");
		goto free_hash;
	}

	/* check whether ilen > integrity value len */
	if(crypto_hash_digestsize(desc.tfm) > ilen) {
		printk("set_integrity: buf length is too short to store integrity value\n");
		retval = -EINVAL;
		goto free_hash;
	}
	
    filp = filp_open(filename, O_RDWR, 0); // O_RDONLY
    if (!filp || IS_ERR(filp)) {
    	printk("set_integrity: cannot open file in O_RDWR mode\n");
    	retval = (int) PTR_ERR(filp);
		goto free_hash;
    }

    filp->f_pos = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	/* check whether read/write is available on the file */
    if (!filp->f_op->write) {
	   printk("get_integrity: cannot read/write the file\n");
		retval = -ENOENT;
		goto filp_exit;
	}

	buffer = (char *)kmalloc(CHUNKSIZE, GFP_KERNEL);
	if(!buffer) {
		printk("set_integrity: out of memory for buffer\n");
		retval = -ENOMEM;
		goto filp_exit;
	}

	/* read in chunks till the end and keep updating the hash */
	bytes =  filp->f_op->read(filp, buffer, CHUNKSIZE, &filp->f_pos);
	while(bytes>0) {
		retval = update_md5(buffer, bytes, &desc);
		if(retval)
			goto free_buffer;
		
		// buffer[bytes] = '\0';
		// printk("%s\n", buffer);
		bytes =  filp->f_op->read(filp, buffer, CHUNKSIZE, &filp->f_pos);
	}

	/* finalize the integrity value */
	retval = crypto_hash_final(&desc, ibuf);
	if(retval) {
		printk("set_integrity: error finalizing crypto hash\n");
		goto free_buffer;
	}

	// for(i=0;i<ilen;i++)
	// 	printk("%x", ibuf[i]);

	/* fabricate the xattribute name */
	attrname = (char *)kmalloc(strlen(ATTRPREFIX) + strlen(algo), GFP_KERNEL);
	if(!attrname) {
		printk("set_integrity: out of memory for attrname\n");
		retval = -ENOMEM;
		goto free_buffer;
	}
	strcpy(attrname, ATTRPREFIX);
	strcat(attrname, algo);

	//* update the integrity value if flag is set */
	if(flag) {
		/* set the xattr, if there exists one already replace it */
		/* vfs_setxattr will take care of mutex lock on the inode */
		retval = vfs_setxattr(filp->f_path.dentry, attrname, ibuf, ilen, XATTR_CREATE);
	    if(retval<0) {
	    	if(retval == -EEXIST) {
	    		printk("xattr already exists, replacing the value\n");
	    		retval = vfs_setxattr(filp->f_path.dentry, attrname, ibuf, ilen, XATTR_REPLACE);
	    		if(retval<0){
		    		printk("set_integrity: not able to replace integrity value\n");
		    		goto free_attrname;
		    	}
	    	}
	    	else {
	    		printk("set_integrity: not able to set integrity value\n");
	    		goto free_attrname;
	    	}
	    }

	    #ifdef EXTRA_CREDIT
		retval = vfs_setxattr(filp->f_path.dentry, ATTRALGO, algo, strlen(algo), XATTR_CREATE);
		if(retval<0) {
			if(retval == -EEXIST) {
				printk("xattr already exists for algo, replacing the value\n");
				retval = vfs_setxattr(filp->f_path.dentry, ATTRALGO, algo, strlen(algo), XATTR_REPLACE);
				if(retval<0){
		    		printk("set_integrity: not able to replace integrity value for algo\n");
		    		goto free_attrname;
		    	}
			}
			else {
	    		printk("set_integrity: not able to set integrity value for algo\n");
	    		goto free_attrname;
	    	}
		}
		#endif
	}

    retval = 0;

free_attrname:
	kfree(attrname);
free_buffer:
	kfree(buffer);
filp_exit:
	set_fs(oldfs);
    filp_close(filp, NULL);
free_hash:
    crypto_free_hash(desc.tfm);
normal_exit:
	return retval;
}

long set_integrity(const char *filename, unsigned char *ibuf, unsigned int ilen, const char *algo) {
	/* call compute_integrity with update flag */
	return compute_integrity(filename, ibuf, ilen, 1, algo);
}

/* Wrapper method for executing mode2 system call
 * Compute integrity of the file and store it in xattr
 * Input: pointer to user args passed to the system call
 * Output: return 0 if the all steps are successful; else return respective -ERRNO
 * Following are the steps:
 * 1. check the access the user args
 * 2. copy the user args to kernel kargs
 * 3. check if the crypto api supports the algo
 * 4. call set_integrity to set the integrity of the file using the given algo
 * 5. copy the kernel buffer containing the integrity value back to user buffer
 * 6. free the allocated memory accordingly, also free  memory allocated using copy_from_user_args2
 */
long update_integrity(sys_integrity_args2 *args) {
	long retval = 0;
	sys_integrity_args2 *kargs = NULL;

	/* check access to args */
	retval = check_access_args2(args);
	if(retval<0)
		goto normal_exit;

	/* copy args from user to kernel */
	retval = copy_from_user_args2(&kargs, args);
	if(retval<0)
		goto normal_exit;
	printk("Successfully copied args2 to kargs\n");
	printk("filename = %s\n", kargs->filename);
	printk("ilen = %d\n", kargs->ilen);

	#ifdef EXTRA_CREDIT
		retval = crypto_has_alg(kargs->algo, 1, 1);
		if(!retval) {
			printk("update_integrity: crypto algo is not supported\n");
			retval = -EINVAL;
			goto free_args;
		}
		retval = set_integrity(kargs->filename, kargs->ibuf, kargs->ilen, kargs->algo);
	#else
		retval = set_integrity(kargs->filename, kargs->ibuf, kargs->ilen, DEFAULTALGO);
	#endif
	
	if(retval<0)
		goto free_args;

	/* copy the existing integrity value to user address space */
	if(copy_to_user(args->ibuf, kargs->ibuf, kargs->ilen)) {
		retval = -EFAULT;
		goto free_args;
	}

free_args:
#ifdef EXTRA_CREDIT
	putname(kargs->algo);
#endif
	kfree(kargs->ibuf);
	putname(kargs->filename);
	kfree(kargs->credbuf);
	kfree(kargs);
normal_exit:
	return retval;
}

/* Function to check the access to all arguments.
 * Input: pointer to struct passed by the user
 * Output: return 0 if all arguments are valid; else return respective -ERRNO
 * Following are the checks:
 * 1. check if the arguments are NULL and access_ok
 * 2. check the access to filename
 * 3. check the constraints on filename
 * 4. check the access to algo
 * 5. check the constraints on algo, strnlen_user is used to find the length of the string
 */
long check_access_args3(sys_integrity_args3 *args) {
	long retval = 0;
	
	/* check whether args is a valid address in user space */
	if(args == NULL || !access_ok(VERIFY_READ, args, sizeof(sys_integrity_args3))) {
		printk("check_access_args3: cannot access sys_integrity_args3 *args\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	/* check access to filename */
	if(args->filename == NULL || 
		!access_ok(VERIFY_READ, args->filename, strnlen_user(args->filename, MAXFILENAME))) {
		printk("check_access_args3: cannot access args->filename\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	/* check whether length of filename matches the constraints */
	if((strnlen_user(args->filename, MAXFILENAME) < MINFILENAME) || 
		(strnlen_user(args->filename, MAXFILENAME) > MAXFILENAME)) {
		printk("check_access_args3: length of filename is too short or too long\n");
		retval = -ENAMETOOLONG;
		goto normal_exit;
	}

	#ifdef EXTRA_CREDIT
	/* check access to algo */
	if(args->algo == NULL || 
		!access_ok(VERIFY_READ, args->algo, strnlen_user(args->algo, CRYPTO_MAX_ALG_NAME))) {
		printk("check_access_args1: cannot access args->algo\n");
		retval = -EFAULT;
		goto normal_exit;
	}

	/* check whether length of algo matches the constraints */
	if(strnlen_user(args->algo, CRYPTO_MAX_ALG_NAME) > CRYPTO_MAX_ALG_NAME) {
		printk("check_access_args1: length of algo too long\n");
		retval = -ENAMETOOLONG;
		goto normal_exit;
	}
	#endif

normal_exit:
	return retval;
}

/* Function to copy the arguments from user address-space to kernel address-space.
 * Input: pointer to address of kernel struct args, pointer to the user struct args
 * Output: return 0 if copy is successful; else return respective -ERRNO
 * Following are the steps:
 * 1. allocate memory for kernel args (kargs)
 * 2. copy from user args to kernel kargs
 * 3. copy from user filename to kernel filename using getname
 * 4. copy from user algo to kernel algo using getname
 * 5. free allocated memory accordingly
 */
long copy_from_user_args3(sys_integrity_args3 **kargs, sys_integrity_args3 *args) {
	long retval = 0;
	
	/* allocate memory for kargs */
	*kargs = (sys_integrity_args3 *)kmalloc(sizeof(sys_integrity_args3), GFP_KERNEL);
	if(!(*kargs)) {
		printk("copy_from_user_args3: out of memory for kargs\n");
		retval = -ENOMEM;
		goto normal_exit;
	}

	/* copy user args to kernel kargs */
	if(copy_from_user((*kargs), args, sizeof(sys_integrity_args3))) {
		printk("copy_from_user_args3: cannot copy_from_user for kargs\n");
		retval = -EFAULT;
		goto free_kargs;
	}

	/* copy filename to kernel address space */
	(*kargs)->filename = getname(args->filename);
	if(!(*kargs)->filename || IS_ERR((*kargs)->filename)) {
		printk("copy_from_user_args3: cannot getname for kargs->filename\n");
		retval = PTR_ERR((*kargs)->filename);
		goto free_filename;
	}

	#ifdef EXTRA_CREDIT
	/* copy algo to kernel address space */
	(*kargs)->algo = getname(args->algo);
	if(!(*kargs)->algo || IS_ERR((*kargs)->algo)) {
		printk("copy_from_user_args3: cannot getname for kargs->algo\n");
		retval = PTR_ERR((*kargs)->algo);
		goto free_filename;
	}
	#endif

	goto normal_exit;

free_filename:
	putname((*kargs)->filename);
free_kargs:
	kfree((*kargs));
normal_exit:
	return retval;
}

/* Function does exactly similar to sys_open
 * Input: filename, flags and mode to open the file
 * Output: return file descriptor if success else return -ERRNO
 */
int secure_open(const char *filename, int flags, int mode) {
	int fd;
	struct file *filp; /* for opening the file */

	filp = filp_open(filename, flags, mode);
	if (!filp || IS_ERR(filp)) {
		printk("secure_open: cannot open file\n");
		fd = (int) PTR_ERR(filp);
		goto normal_exit;
	}
	
	/* get an unused fd */
	fd = get_unused_fd();
	if (fd < 0) {
        printk("secure_open: cannot get unused fd\n");
        goto free_filp;
	}

    fd_install(fd, filp);
    goto normal_exit;

free_filp:
	filp_close(filp, NULL);
normal_exit:
    return fd;
}


/* Function checks whether two integrity values match nor not.
 * Input: pointer to first integrity value, pointer to second integrity value
 * Output: return 1 if integrity values match; else return 0
 */
int compare_integrity(unsigned char *ibuf1, unsigned char *ibuf2, unsigned int ilen) {
	unsigned int rc = 1;
	int i;
	for(i=0;i<ilen;i++) {
		if(ibuf1[i] != ibuf2[i]) {
			rc = 0;
			break;
		}
	}
	return rc;
}


/* Wrapper method for executing mode3 system call
 * Compare integrity value with already existing integrity value, if they both match return
 *  filedescriptor like open else return respective -ERRNO
 * Input: pointer to user args passed to the system call
 * Output: return 0 if the all steps are successful; else return respective -ERRNO
 * Following are the steps:
 * 1. check the access the user args
 * 2. copy the user args to kernel kargs
 * 3. check if the crypto api supports the algo
 * 4. call get_integrity to get the existing integrity of the file
 * 5. call compute_integrity to compute integrity of the file now
 * 6. compare integrity values: if match return fd; else return -EPERM
 * 6. free the allocated memory accordingly, also free  memory allocated using copy_from_user_args3
 */
long open_with_integrity(sys_integrity_args3 *args) {
	long retval = 0;
	sys_integrity_args3 *kargs = NULL;
	unsigned char *ibuf1;
	unsigned char *ibuf2;

	/* check access to args */
	retval = check_access_args3(args);
	if(retval<0)
		goto normal_exit;

	/* copy args from user to kernel */
	retval = copy_from_user_args3(&kargs, args);
	if(retval<0)
		goto normal_exit;
	printk("Successfully copied args3 to kargs\n");
	printk("filename = %s\n", kargs->filename);

	/* allocate memory for ibuf1 */
	ibuf1 = (unsigned char*)kmalloc(MAXILEN, GFP_KERNEL);
	if(!ibuf1) {
		printk("open_with_integrity: out of memory for ibuf1\n");
		retval = -ENOMEM;
		goto free_args;
	}
	memset(ibuf1, '\0', MAXILEN);

	/* get the existing integrity */
	#ifdef EXTRA_CREDIT
		retval = crypto_has_alg(kargs->algo, 1, 1);
		if(!retval) {
			printk("open_with_integrity: crypto algo is not supported\n");
			retval = -EINVAL;
			goto free_args;
		}
		retval = get_integrity(kargs->filename, ibuf1, MAXILEN, kargs->algo);
	#else
		retval = get_integrity(kargs->filename, ibuf1, MAXILEN, DEFAULTALGO);
	#endif
	if(retval<0) {
		if(retval == -ENODATA) {
			printk("open_with_integrity: integrity value doesn't exist\n");
			// printk("Good to go with Open!!\n");
			// retval = secure_open(kargs->filename, kargs->oflag, kargs->mode);
		}
		else if(retval == -ENOENT && (kargs->flag|O_CREAT)) {
			printk("open_with_integrity: File doesn't exist, creating file\n");
			retval = secure_open(kargs->filename, kargs->oflag, kargs->mode);
		}
		else
			printk("open_with_integrity: get integrity failed\n");
		goto free_ibuf1;
	}

	/* allocate memory for ibuf2 */
	ibuf2 = (unsigned char*)kmalloc(MAXILEN, GFP_KERNEL);
	if(!ibuf2) {
		printk("open_with_integrity: out of memory for ibuf2\n");
		retval = -ENOMEM;
		goto free_ibuf1;
	}
	memset(ibuf2, '\0', MAXILEN);

	/* compute the integrity of the file */
	/* call compute_integrity with no update flag */
	#ifdef EXTRA_CREDIT
		retval = compute_integrity(kargs->filename, ibuf2, MAXILEN, 0, kargs->algo);
	#else
		retval = compute_integrity(kargs->filename, ibuf2, MAXILEN, 0, DEFAULTALGO);
	#endif
	if(retval<0)
		goto free_ibuf2;

	// for(i=0;i<ilen;i++)
	// 	printk("%x", ibuf[i]);

	// for(i=0;i<ilen;i++)
	// 	printk("%x", ibuf[i]);

	/* compare the integrity */
	if(compare_integrity(ibuf1, ibuf2, MAXILEN)) {
		printk("Good to go with Open!!\n");
		retval = secure_open(kargs->filename, kargs->oflag, kargs->mode);
	}		
	else {
		printk("Integrity check failed\n");
		retval = -EPERM;
	}

free_ibuf2:
	kfree(ibuf2);
free_ibuf1:
	kfree(ibuf1);
free_args:
#ifdef EXTRA_CREDIT
	putname(kargs->algo);
#endif
	putname(kargs->filename);
	kfree(kargs);
normal_exit:
	return retval;
}

/* dummy function to test whether integrity value is calculated correctly */
int calculate_integrity(char *dest, char *src, int len)
{
    struct scatterlist sg;
    struct hash_desc desc;
    int retval = 0;

    if(crypto_has_alg("md5", 1, 1)) {
    	printk("Algo exists!!\n");
    }

    desc.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
    if(IS_ERR(desc.tfm)) {
        printk("Error attempting to allocate crypto context\n");
        retval= PTR_ERR(desc.tfm);
        goto normal_exit;
    }

    desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
    sg_init_one(&sg, (u8 *)src, len);

    retval= crypto_hash_init(&desc);
    if(retval) {
        printk("Error initializing crypto hash\n");
        goto normal_exit;
    }
     
    retval= crypto_hash_update(&desc, &sg, len);
    if(retval) {
        printk("Error updating crypto hash\n");
        goto normal_exit;
    }
     
    retval= crypto_hash_final(&desc, dest);
    if(retval) {
        printk("Error finalizing crypto hash\n");
        goto normal_exit;
    }

normal_exit:
    return retval;
}


/* Implementation of sys_integrity() system call
 * Wrapper method for the complete system call
 * Reads the first field from the user args and call appropriate stubs to execute in that mode
 * Input: user struct containing the args
 * Output: return 0 if the all steps are successful; else return respective -ERRNO
 */
asmlinkage long xintegrity(void *args) {
	long retval = 0;
	unsigned char flag;
	
	// int i;
	// char *src = "hello world";
	// unsigned char *dest;
    // unsigned char *dest = (unsigned char *)kmalloc(MAXILEN, GFP_KERNEL);
    // memset(dest, '\0', MAXILEN);
    // retval = calculate_integrity(dest, src, strlen(src));
    // for(i=0;i<20;i++)
    // 	printk("%x", dest[i]);
    // kfree(dest);
    // printk("\n");

	printk("==========================================\n");

	/* check whether args is a valid address in user space */
	if(args == NULL || !access_ok(VERIFY_READ, (unsigned char *)args, sizeof(unsigned char))) {
		printk("Address of args not OK");
		retval = -EINVAL;
		goto normal_exit;
	}

	/* read the first field from the args */
	if(get_user(flag, (unsigned char *)args)) {
		printk("Cannot read mode flag");
		retval = -EINVAL;
		goto normal_exit;
	}

	printk("Mode flag = %c\n", flag);
	if(flag == '1') {
		/* execute in mode1 */
		retval = find_integrity((sys_integrity_args1 *)args);
	}
	else if(flag == '2') {
		/* execute in mode2 */
		retval = update_integrity((sys_integrity_args2 *)args);
	}
	else if(flag == '3') {
		/* execute in mode3 */
		retval = open_with_integrity((sys_integrity_args3 *)args);
	}
	else {
		printk("Invalid mode flag");
		retval = -EINVAL;
	}

normal_exit:
	return retval;
}

/* Init for module */
static int __init init_sys_xintegrity(void) {
	printk("installed new sys_xintegrity module\n");
	if (sysptr == NULL)
		sysptr = xintegrity;
	return 0;
}

/* Exit for module */
static void  __exit exit_sys_xintegrity(void) {
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xintegrity module\n");
}
module_init(init_sys_xintegrity);
module_exit(exit_sys_xintegrity);
MODULE_LICENSE("GPL");
