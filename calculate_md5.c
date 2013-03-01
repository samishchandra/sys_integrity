#include <stdio.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>

#define LEN 16

int calculate_md5(char *dst, char *src, int len)
{
     struct scatterlist sg[2];
     struct crypto_hash *tfm;
     struct hash_desc desc;
     int retval = 0;
 
     sg_init_one(&sg, (u8 *)src, len);
     tfm = crypto_alloc_hash('md5', 0, CRYPTO_ALG_ASYNC);
     if (IS_ERR(tfm)) {
         printk("Error attempting to allocate crypto context\n");
        retval= PTR_ERR(tfm);         
         goto normal_exit;
     }
     
     desc.tfm = tfm;
     desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;

    retval= crypto_hash_init(&desc);
     if (rc) {
         printk("Error initializing crypto hash");
         goto normal_exit;
     }
     
    retval= crypto_hash_update(&desc, &sg, len);
     if (rc) {
         printk("Error updating crypto hash");
         goto normal_exit;
     }
     
    retval= crypto_hash_final(&desc, dst);
     if (rc) {
         printk("Error finalizing crypto hash");
         goto normal_exit;
     }

normal_exit:
     return retval;
}

int main(int argc, char const *argv[])
{
	char *src = "hello world";
	char *dest = (char *)malloc(LEN);

	calculate_md5(dest, src, LEN);
	printf("%s\n", dest);
	return 0;
}