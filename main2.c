#include <stdio.h>
#include <openssl/des.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

unsigned int hextobin(unsigned char *code);

unsigned char toHex(unsigned char i);

void dead(void);

int checkPad(unsigned char *rcode, unsigned int length);

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    int i;
    char flag[100];
    int ret;

    unsigned char *code = malloc(2048);
    unsigned char *rcode = malloc(1024);
    unsigned int length;
    int (*check)(char *) = (int (*)(char *)) rcode;
    unsigned char *iv = malloc(16);
    unsigned char key[8];// = "\x0d\xe7\x5c\xec\x76\xbe\x00\xbe";
    DES_key_schedule *ks = malloc(sizeof(DES_key_schedule));
	FILE * fp = fopen("/home/pwn/pwn/key","r");
	if(fp == NULL) {
		puts("cat find key");
	}
	fgets(key,9,fp);
    DES_set_key_unchecked(key, ks);
	
	while(1){
		bzero(code, 2048);
		bzero(iv, 16);
		puts("so give me you code first");
		read(STDIN_FILENO, iv, 16);
		read(STDIN_FILENO, code, 2048);
		hextobin(iv);
		code[strlen(code) - 1] = 0;
		if (strlen(code) % 16) {
			printf("no code, no game");
			dead();
		}

		length = hextobin(code);

		DES_ncbc_encrypt((const unsigned char *) code, rcode, length, ks, iv, DES_DECRYPT);
		if (checkPad(rcode, length)){
			break;
		}
	}
	printf("Now, input you password");
	ret = (int) read(STDIN_FILENO, flag, 99);
	flag[ret - 1] = 0;
	if (strlen(flag) != 22) {
		dead();
	}
	
    if (check(flag)) {
        printf("Now you have half part of flag. Where is the other?\n");
    }
    else {
        printf("Try again\n");
    }


}

int checkPad(unsigned char *rcode, unsigned int length) {
    int i;
    if (rcode[length - 1] > 8 || rcode[length - 1] == 0) {
        return 0;
    }
    for (i = 0; i < rcode[length - 1]; i++) {
        if (rcode[length - 1] != rcode[length - 1 - i]) {
            return 0;
        }
    }
	return 1;
}

void inline dead(void) {
	exit(0);
}

unsigned char toHex(unsigned char i) {
    char *hexTable = "0123456789ABCDEF";
    char *p = strchr(hexTable, i);
    if (p) {
        return (unsigned char) (p - hexTable);
    } else {
        dead();
    }
}

unsigned int hextobin(unsigned char *code) {
    unsigned int i;
    int len = (int) strlen((const char *) code);
    for (i = 0; i < len / 2; i++) {
        code[i] = (toHex(code[i * 2]) << 4) + toHex(code[i * 2 + 1]);
    }
    return i;
}


