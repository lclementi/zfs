/*
 * Copyright (c) Luca Clementi <luca.clementi@gmail.com>
 *
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *
 */

#include <linux/crypto.h>
#include <crypto/hash.h>
#include <sys/zio.h>
#include <sys/zio_checksum.h>
#include <crypto/sha.h>



#define RUN_AND_TEST(fun, error) if (fun < 0) printk(KERN_ERR error);

struct crypto_shash *tfm;

void
crypto_zio_checksum_SHA256(const void *buf, uint64_t size, zio_cksum_t *zcp)
{
	uint64_t hash[4];
        struct sdesc{
        	struct shash_desc desc;
                char ctx[sizeof(struct sha256_state)];
        } sdesc;

        sdesc.desc.flags = 0;
	sdesc.desc.tfm = tfm;
	//RUN_AND_TEST(crypto_shash_init(&sdesc.desc), "---- init failed ----");
	//RUN_AND_TEST(crypto_shash_update(&sdesc.desc, buf, size), "---- crypto finup ----");
        //RUN_AND_TEST(crypto_shash_final(&sdesc.desc, (u8 *) hash), "---- crypto final ----");
	crypto_shash_init(&sdesc.desc);
	crypto_shash_update(&sdesc.desc, buf, size);
        crypto_shash_final(&sdesc.desc, (u8 *) hash);
        ZIO_SET_CHECKSUM(zcp,
                cpu_to_be64(hash[0]),
                cpu_to_be64(hash[1]),
                cpu_to_be64(hash[2]),
                cpu_to_be64(hash[3]));

        /*
        hash[0] = cpu_to_be64(hash[0]);
        hash[1] = cpu_to_be64(hash[1]);
	hash[2] = cpu_to_be64(hash[2]);
        hash[3] = cpu_to_be64(hash[3]);

	if (sdesc.desc.tfm)
		crypto_free_shash(sdesc.desc.tfm);
              
        if ( (zcp)->zc_word[0] != hash[0] || (zcp)->zc_word[1] != hash[1] || 
        	(zcp)->zc_word[2] != hash[2] || (zcp)->zc_word[3] != hash[3] ){
	        printk(KERN_ERR "Failed hash with buf %p and size %llu\n", buf, size);

		printk(KERN_ERR "Crypto hash %llx:%llx:%llx:%llx\n", zcp->zc_word[0], 
			zcp->zc_word[1], zcp->zc_word[2], zcp->zc_word[3]);

		printk(KERN_ERR "Zio    hash %llx:%llx:%llx:%llx\n", hash[0], 
			hash[1], hash[2], hash[3]);
	}*/

}



static int __init init_zcrypto(void){

	printk(KERN_ERR "zcrypto loaded\n");
	//TODO move this in an init function
	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "Failed to load transform for sha256");
		tfm = NULL;
		return 1;
	}
	printk(KERN_ERR "Loaded module %s\n", crypto_shash_alg(tfm)->base.cra_driver_name );
	return 0;
}


static void __exit exit_zcrypto(void){
	if (tfm)
		crypto_free_shash(tfm);
}

module_init(init_zcrypto);
module_exit(exit_zcrypto);

MODULE_DESCRIPTION("Hash and compression functions for zfs");
MODULE_AUTHOR(ZFS_META_AUTHOR);
MODULE_LICENSE("GPL");
MODULE_VERSION(ZFS_META_VERSION "-" ZFS_META_RELEASE);

EXPORT_SYMBOL(crypto_zio_checksum_SHA256);

