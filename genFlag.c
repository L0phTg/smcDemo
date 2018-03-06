#include <stdio.h>
#include <stdlib.h>
#include "sm4.h"

#define MAX_LENGTH  (0xc6+0xce)
#define offset_of_startSM4enc 0x1AA5


int main(int argc, char *argv[])
{
    FILE *fp;
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}; 
    sm4_context ctx;

    if ((fp = fopen("smcDemo-final", "rb+")) == NULL) {
        printf("File cannot be opened\n");
        exit(0);
    }

    fseek(fp, offset_of_startSM4enc, SEEK_SET);            // set to addr of sm4_encrypt

    unsigned char buf[MAX_LENGTH+16];
    unsigned char buf_encrypt[MAX_LENGTH+16];
    unsigned char buf_decrypt[MAX_LENGTH+16];

    fread(buf, sizeof(unsigned char), MAX_LENGTH, fp);

    for (int i = 0; i < MAX_LENGTH; i++) {
        printf("%02x, ", buf[i]);
    }
    printf("\n");
//      printf("0x%x", MAX_LENGTH);
//
      sm4_setkey_enc(&ctx, key);
      sm4_crypt_ecb(&ctx, 1, MAX_LENGTH, buf, buf_encrypt);

    for (int i = 0; i < MAX_LENGTH; i++) {
        printf("%02x, ", buf_encrypt[i]);
    }
    printf("\n");

    sm4_setkey_dec(&ctx, key);
    sm4_crypt_ecb(&ctx, 0, MAX_LENGTH, buf_encrypt, buf_decrypt);

    for (int i = 0; i < MAX_LENGTH; i++) {
        printf("%02x, ", buf_decrypt[i]);
    }
    printf("\n");

    fseek(fp, offset_of_startSM4enc, SEEK_SET);
    fwrite(buf_encrypt, sizeof(unsigned char), MAX_LENGTH, fp);
    
    return 0;
}
