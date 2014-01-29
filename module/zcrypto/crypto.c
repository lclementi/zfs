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
	uint32_t hash[8];

	if (desc.tfm){
		crypto_shash_init(&desc);
		crypto_shash_update(&desc, buf, size);
		crypto_shash_final(&desc, (u8 *) hash);

	ZIO_SET_CHECKSUM(zcp,
	    (uint64_t)hash[0] << 32 | hash[1],
	    (uint64_t)hash[2] << 32 | hash[3],
	    (uint64_t)hash[4] << 32 | hash[5],
	    (uint64_t)hash[6] << 32 | hash[7]);

	//printk(KERN_ERR "Crypto hash %x:%x:%x:%x:%x:%x:%x:%x ------- %x:%x:%x:%x:%x:%x:%x:%x\n", 
	//			hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], 
	//			H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);

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

