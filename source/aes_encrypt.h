/*
 * aes_encrypt.h
 *
 *  Created on: Feb 18, 2020
 *      Author: dev
 */

#ifndef AES_ENCRYPT_H_
#define AES_ENCRYPT_H_

int aes_init();
int aes_encrypt_file(const char* infile, const char* outfile);
int aes_decrypt_file(const char* infile, const char* outfile);



#endif /* AES_ENCRYPT_H_ */
