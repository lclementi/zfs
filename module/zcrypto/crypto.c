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

struct shash_desc desc;

void
crypto_zio_checksum_SHA256(const void *buf, uint64_t size, zio_cksum_t *zcp)
{
	uint64_t hash[4];

	if (desc.tfm){
		crypto_shash_init(&desc);
		crypto_shash_update(&desc, buf, size);
		crypto_shash_final(&desc, (u8 *) hash);


		ZIO_SET_CHECKSUM(zcp,
			cpu_to_be64(hash[0]),
			cpu_to_be64(hash[1]),
			cpu_to_be64(hash[2]),
			cpu_to_be64(hash[3]));

		/*
		printk(KERN_ERR "Crypto hash %llx:%llx:%llx:%llx\n", zcp->zc_word[0], 
			zcp->zc_word[1], zcp->zc_word[2], zcp->zc_word[3]);

		zio_checksum_SHA256(buf, size, zcp);

		printk(KERN_ERR "Zio    hash %llx:%llx:%llx:%llx\n", zcp->zc_word[0], 
			zcp->zc_word[1], zcp->zc_word[2], zcp->zc_word[3]);
			*/

	} else {
		zio_checksum_SHA256(buf, size, zcp);
		return;
	}
}



static int __init init_zcrypto(void){

	struct crypto_shash *tfm;
	//TODO move this in an init function
	tfm =    crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "Failed to load transform for sha256");
		desc.tfm = NULL;
		return -1;
	}
	desc.tfm = tfm;
	desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP; //TODO check this
	return 0;
}


static void __exit exit_zcrypto(void){
	if (desc.tfm)
		crypto_free_shash(desc.tfm);

}

module_init(init_zcrypto);
module_exit(exit_zcrypto);

MODULE_DESCRIPTION("Hash and compression functions for zfs");
MODULE_AUTHOR(ZFS_META_AUTHOR);
MODULE_LICENSE("GPL");
MODULE_VERSION(ZFS_META_VERSION "-" ZFS_META_RELEASE);

EXPORT_SYMBOL(crypto_zio_checksum_SHA256);

