#include <stdio.h>      
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <asm/unistd.h>
#include <ctype.h>
#include "sm4.h"

#define s_long (sizeof(long))
#define brk_addr  0x402007
#define sm4_encrypt_start 0x401AA5
#define len_of_2encrypt_func 0xc6+0xce

//#define jmp_key_code  0xe9bb306000
#define jmp_key_code  0x333333ccecdc1825L // 0xcccccccccccccccc ^ jmp key_code
#define jmp_encrypt "\xE9\x1b\xea\xdf\xff\xff\xff\xff"           // jmp (addr(0x401B6B) - 0x60314B)

// 0x6031A0
char flag[0x40];
// Study_ptrace_is_very_excited_hha

// __asm(
//    "xor eax, 0xaskldjf"          --> 使后面jne全部成立.
//    "push rdx"           
//    "pop  rdi"
//    "jnz ____"
//    ...... junk
//    "jnz ____"
//    ...... junk
//    "jnz (jmp_encrypt)"
//    ...... junk
//    "jmp encrypt"
 
 
 
 

//char macbook[] = " "jmp_encrypt;
// 0x6030E0
char jmp_to_cmp_code[] = "5xV44R_u0111111111111111111111111111111111111111111111111u011111111111111111111111111111111111111111111111\x00" jmp_encrypt;

unsigned char flag_enc[] = {0x9e, 0xf8, 0x7b, 0xfa, 0x47, 0xbf, 0x7c, 0x14, 0x40, 0xb7, 0x0d, 0x1a, 0x6c, 0x5a, 0x0f, 0x7f, 0xdd, 0x85, 0xbd, 0xf9, 0xbc, 0x90, 0x43, 0x78, 0xcf, 0x39, 0x5d, 0x39, 0xb2, 0x84, 0x18, 0x83 };


union u {
	long val;
	char chars[s_long];
};


// getdata
// 将addr处的str, 拷贝到dst地址处
// PEEKDATA 读取数据
void get_data(pid_t pid, long addr, char *dst, int len)
{        
	int i, j;
	union u data;
	for (i = 0; i < len / s_long; i++)
	{
		data.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * s_long, NULL);
		memcpy(dst + i * s_long, data.chars, s_long);
	}

	data.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * s_long, NULL);
	memcpy(dst + i * s_long, data.chars, len % s_long);    
	dst[len] = 0;
}

// senddata
// 将
// POKEDATA 改变进程中的变量值
void send_data(pid_t pid, long addr, char *dst, int len)
{
	int i;
	union u data;
	for (i = 0; i < len / s_long; i++)
	{
		memcpy(data.chars, dst + i * s_long, s_long);
		ptrace(PTRACE_POKEDATA, pid, addr + i * s_long, data.val);
	}
	data.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * s_long, NULL);
	memcpy(data.chars, dst + i * s_long, len % s_long);
	ptrace(PTRACE_POKEDATA, pid, addr + i * s_long, data.val);
}

void sm4_decrypt(unsigned char *input, unsigned char *output, int len)
{

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe,
     0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};  
    sm4_context ctx;
    unsigned long i;
    sm4_setkey_dec(&ctx, key);
    sm4_crypt_ecb(&ctx, 0, len, input, output);
}

void decrypt_data(pid_t pid, long addr, int len)
{
	char *tmp_str = (char *)malloc(len + 1);
	get_data(pid, addr, tmp_str, len);
    sm4_decrypt(tmp_str, tmp_str, len);	
	send_data(pid, addr, tmp_str, len);
}

void sm4_encrypt(unsigned char *input, unsigned char *output, int len)
{
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe,
     0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};  
    sm4_context ctx;
    unsigned long i;
    sm4_setkey_enc(&ctx, key);
    sm4_crypt_ecb(&ctx, 1, len, input, output);

}


// 加密操作, 将input_flag通过sm4加密
// 0x401A5B
void encrypt(char *input_flag)
{
    int i = 0;
    int cmp = 0;
    uint8_t c[0x20];
    //puts("hahaha");
    //printf("%s\n", input_flag);

    while(i < 2) { // 将32位的输入, 分两组进行加密. 然后通过memcmp进行比较.
        sm4_encrypt(input_flag + (i * 16), c + (i * 16), 16);
        cmp |= memcmp(c + (i * 16), flag_enc + (i * 16), 16);   // flag_enc 为加密后的值
        i++; }
//  for (int i = 0; i < 32; i++)
//      printf("%d ", c[i]);
//  printf("\n");

    if (!cmp) {
        puts("You got it!");
        exit(0);
    }


    //puts("hihihi");
    puts("Try Again :(");
    puts("Please continue study smc!");
    exit(0);
}

int main(int argc, char *argv[])
{
	setbuf(stdin, 0);            // 使程序无缓冲
	setbuf(stdout, 0);           

    if (argc == 1) {

        pid_t child;
        pid_t parent_pid = getpid();
        char dbg_pid[0x20];
        sprintf(dbg_pid, "%d", parent_pid);
        char *new_argv[] = {argv[0], dbg_pid, 0};

        child = fork();

        if (child == 0) {       // 子进程
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            if (execve(argv[0], new_argv, NULL) == -1) 
            {
                return 0;
            }

        } else {                // 父进程
            struct user_regs_struct regs;
            int read_num = 0;
            int status;

            while(1)  {
                waitpid(child, &status, 0);
                //puts("hihihiads");

                if (WIFEXITED(status))
                    break;

                ptrace(PTRACE_GETREGS, child, NULL, &regs);

                // puts函数会导致 write调用
                if (regs.orig_rax == __NR_write && regs.rdx != 1)    // ptrace write
                {
                    //decrypt_data(child, regs.rsi, regs.rdx);       // pid, addr, length     解密字符串
                }

                // 
                if (regs.orig_rax == __NR_close && regs.rsi == 1)    // ptrace close
                {


                }

                // scanf函数会导致 read调用
                if (regs.orig_rax == __NR_read && regs.rdx == 1)     // ptrace read  
                {
                    //read_num = regs.rax-1;
                    //printf("%d\n", read_num);

                    if (!read_num) {

                    } else if(read_num/2 > 65) {
                          puts("Try again :(");
                          puts("please continue study smc!");
                          kill(child, SIGTERM);
                          exit(0);
                    } else if (read_num/2 == 32) {
                       long op;
                        // brk_addr为 执行完read调用后的 指令地址
                        op = ptrace(PTRACE_PEEKDATA, child, brk_addr, NULL);
                        ptrace(PTRACE_POKEDATA, child, brk_addr, 0xcccccccccccccccc);

                        decrypt_data(child, sm4_encrypt_start, len_of_2encrypt_func);   // 解密两个encrypt函数
                        //printf("decrypt Ok");
                        ptrace(PTRACE_CONT, child, NULL, NULL);
                        wait(&status);

                        op = ptrace(PTRACE_PEEKDATA, child, brk_addr, NULL);

                        op ^= jmp_key_code;
                        // op = 0xcccccccccccccccc ^ jmp_key_code = jmp (0x6030E0-brk_addr) 

                        // 修改地址为 指令: jmp addr(jmp_code)
                        ptrace(PTRACE_POKEDATA, child, brk_addr, op);
                        ptrace(PTRACE_GETREGS, child, NULL, &regs);

                        regs.rip--;
                        regs.rdx = (long long)flag;

                        ptrace(PTRACE_SETREGS, child, NULL, &regs);

                        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
                        //printf("%d\n", read_num/2 - 1);

                    }
                    read_num++;
                }
                ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            }
        }
    }
    else {
            printf("please input flag: ");	
            scanf("%48s", flag);
            puts("Try again :(");
            puts("please continue study smc!");
    }

	return 0;
}
