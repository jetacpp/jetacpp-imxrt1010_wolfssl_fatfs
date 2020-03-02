#include <stdlib.h>
#include <stdio.h>

#include <wolfssl/wolfcrypt/aes.h>
#include "ff.h"

#define BITS_TO_BYTES(x)        ( ( x ) / 8 )

#define MAX_KEY_BITS            ( 256 )
#define MAX_KEY_LENGTH          BITS_TO_BYTES( MAX_KEY_BITS )

byte aes_key[MAX_KEY_LENGTH];
byte aes_iv[MAX_KEY_LENGTH];

static Aes g_aes_encrypt;
static Aes g_aes_decrypt;

static const int g_key_length = BITS_TO_BYTES(128);
static const int g_block_size = BITS_TO_BYTES(128);


int aes_init()
{
    // generate aes_key and aes_iv.
    for (int i = 0; i < g_key_length; i++)
    {
        aes_key[i] = (byte) i;
        aes_iv[i] = (byte) i;
    }

    if (wc_AesSetKeyDirect(&g_aes_encrypt, (const byte *)aes_key, g_key_length, (const byte *)aes_iv, AES_ENCRYPTION))
    {
        return -1;
    }
    if (wc_AesSetKeyDirect(&g_aes_decrypt, (const byte *)aes_key, g_key_length, (const byte *)aes_iv, AES_DECRYPTION))
    {
        return -1;
    }
    return 0;
}

int aes_get_block_size()
{
    return g_block_size;
}


int aes_encrypt_block(char* original_data, char* encrypted_data)
{
    wc_AesEncryptDirect(&g_aes_encrypt, encrypted_data, original_data);
    return 0;
}

int aes_decrypt_block(char* encrypted_data, char* decrypted_data)
{
    wc_AesDecryptDirect(&g_aes_decrypt, decrypted_data, encrypted_data);
    return 0;
}


int aes_encrypt_file(const char* infile, const char* outfile)
{
	FRESULT ret;
	FIL in, out;
	ret = f_open(&in, infile, FA_READ);
    if (ret == 0) {
    	ret = f_open(&out, outfile, FA_CREATE_ALWAYS | FA_WRITE);
        if (ret == 0) {
            int block_size = aes_get_block_size();
            char* data = malloc(block_size * 2);
            if (data) {
                size_t nRead = 0, fsize, read;

                fsize = f_size(&in);

                // write actual file size to block
                memcpy(data, &fsize, sizeof(block_size));
                f_write(&out, data, block_size, NULL);

                // encrypt data blocks
                while ((0 == f_read(&in, data, block_size, &read)) && read) {
                    aes_encrypt_block(data, data + block_size);
                    f_write(&out, data + block_size, block_size, NULL);
                }

                free(data);
            }
            f_sync(&out);
            f_close(&out);
        }
        f_close(&in);
    }
    return 0;
}

#if 1
int aes_decrypt_file(const char* infile, const char* outfile)
{
	FRESULT ret;
	FIL in, out;
	ret = f_open(&in, infile, FA_READ);
    if (ret == 0) {
    	ret = f_open(&out, outfile, FA_CREATE_ALWAYS | FA_WRITE);
        if (ret == 0) {
            int block_size = aes_get_block_size();
            char* data = malloc(block_size * 2);
            if (data) {
                size_t nRead = 0, read, fsize;
                // read file size
                nRead = f_read(&in, data, block_size, &read);
                fsize = *(size_t*)data;

                nRead = 0;
                while ((0 == f_read(&in, data, block_size, &read)) && read ) {

                    aes_decrypt_block(data, data + block_size);
                    if (fsize - nRead >= block_size)
                        f_write(&out, data + block_size, block_size, NULL);
                    else
                        f_write(&out, data + block_size, fsize - nRead, NULL);
                    nRead += read;
                }

                free(data);
            }
            f_sync(&out);
            f_close(&out);
        }
        f_close(&in);
    }
    return 0;
}
#endif


