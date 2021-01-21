## Assignment #5.1: Shellcode `linux/x64/exec` Dissection
---
---
### Introduction
---
The first `msfvenom` shellcode that is going to be dessected in functionality is the `linux/x64/exec` payload.

Let's see it's options:
```bash
SLAE64>  msfvenom -p linux/x64/exec --list-options
Options for payload/linux/x64/exec:
=========================

       Name: Linux Execute Command
     Module: payload/linux/x64/exec
   Platform: Linux
       Arch: x64
Needs Admin: No
 Total size: 40
       Rank: Normal

Provided by:
    ricky

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
CMD                    yes       The command string to execute

Description:
  Execute an arbitrary command
  
**_REMOVED THE REST_**
```
The payload is only 40 bytes and it requires a parameter in the `CMD` option, that's the command to execute. 

### Creating the Shellcode
---
Will execute the `ls -l` command. Decided to use a command that can receive options to check how the payload handles it. Also added the full path to make the command string a 7 bytes length only. Let's generate the payload:
```bash
SLAE64> msfvenom -p linux/x64/exec CMD="/bin/ls -l" -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 50 bytes
Final size of c file: 236 bytes
unsigned char buf[] = 
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x0b\x00"
"\x00\x00\x2f\x62\x69\x6e\x2f\x6c\x73\x20\x2d\x6c\x00\x56\x57"
"\x48\x89\xe6\x0f\x05";
SLAE64> 

```
The generated payload size is 50 bytes, it increased it's size. This increase from 40 bytes is because the 10 bytes of `/bin/ls -l` string. Interesting.

### Run Shellcode. The C Template
---
To run the shellcode, will use of the `shellcode.c` template renamoed to `Payload_01.c`. The shellcode is placed in the `code[]` string:
```c
#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x0b\x00"
"\x00\x00\x2f\x62\x69\x6e\x2f\x6c\x73\x20\x2d\x6c\x00\x56\x57"
"\x48\x89\xe6\x0f\x05";

void main()
{
        printf("ShellCode Lenght: %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```
Now it can be compiled:
```bash
gcc -fno-stack-protector -z execstack Payload_01.c -o Payload_01
```
When it's run, it shows the files of the directory:

<img src="https://galminyana.github.io/img/A051_Shellcode_Run.png" width="75%" height="75%">

### `objdump`: First Approach
---
Once we get the executable, will use `objdump` to disassemble the ASM code. As `objdump` disassembles the code by sections, the one of interest is the `<code>` section. Is the one containing the shellcode:

```bash
SLAE64> objdump -M intel -D Payload_01

**_REMOVED_**

0000000000004060 <code>:
    4060:	6a 3b                	push   0x3b
    4062:	58                   	pop    rax
    4063:	99                   	cdq    
    4064:	48 bb 2f 62 69 6e 2f 	movabs rbx,0x68732f6e69622f
    406b:	73 68 00 
    406e:	53                   	push   rbx
    406f:	48 89 e7             	mov    rdi,rsp
    4072:	68 2d 63 00 00       	push   0x632d
    4077:	48 89 e6             	mov    rsi,rsp
    407a:	52                   	push   rdx
    407b:	e8 0b 00 00 00       	call   408b <code+0x2b>
    4080:	2f                   	(bad)  
    4081:	62                   	(bad)  
    4082:	69 6e 2f 6c 73 20 2d 	imul   ebp,DWORD PTR [rsi+0x2f],0x2d20736c
    4089:	6c                   	ins    BYTE PTR es:[rdi],dx
    408a:	00 56 57             	add    BYTE PTR [rsi+0x57],dl
    408d:	48 89 e6             	mov    rsi,rsp
    4090:	0f 05                	syscall 
	...

**_REMOVED_**

SLAE64> 
```
Interesting that `objdump` detects some instructions as `(bad)`. Will have to check it.

### The Fun: GDB Analysis
---
After opening the file in `gdb` and set the `set disassembly-flavor intel`, a breakpoint is placed in `*&code` address. This is where the shellcode is placed and can start debugging just from there. Once the breakpoint is `set`, the `run` comand execs the code until reaching theit. Now if `disassemble` the code will show the payload code:
```bash
SLAE64> gdb ./Payload_01
GNU gdb (Debian 8.2.1-2+b3) 8.2.1

**_REMOVED_**

Reading symbols from ./Payload_01...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) break *&code
Breakpoint 1 at 0x4060
(gdb) run
Starting program: /root/SLAE64/Exam/Assignment05/Payload_01 
ShellCode Lenght: 13

Breakpoint 1, 0x0000555555558060 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
=> 0x0000555555558060 <+0>:	push   0x3b
   0x0000555555558062 <+2>:	pop    rax
   0x0000555555558063 <+3>:	cdq    
   0x0000555555558064 <+4>:	movabs rbx,0x68732f6e69622f          <==
   0x000055555555806e <+14>:	push   rbx
   0x000055555555806f <+15>:	mov    rdi,rsp
   0x0000555555558072 <+18>:	push   0x632d                        <==
   0x0000555555558077 <+23>:	mov    rsi,rsp
   0x000055555555807a <+26>:	push   rdx
   0x000055555555807b <+27>:	call   0x55555555808b <code+43>     
   0x0000555555558080 <+32>:	(bad)  
   0x0000555555558081 <+33>:	(bad)  
   0x0000555555558082 <+34>:	imul   ebp,DWORD PTR [rsi+0x2f],0x2d20736c
   0x0000555555558089 <+41>:	ins    BYTE PTR es:[rdi],dx
   0x000055555555808a <+42>:	add    BYTE PTR [rsi+0x57],dl
   0x000055555555808d <+45>:	mov    rsi,rsp
   0x0000555555558090 <+48>:	syscall 
   0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) 
```
In the code, can see that some hex values are stored in registers and then in the stack. Let's convert all those hex values to get any clue of what the shellcode does. For that Python is used to convert and reverse values:
```python
>>> "68732f6e69622f".decode('hex')[::-1]
'/bin/sh'
>>> "632d".decode('hex')[::-1]
'-c'
>>> 
```
Those values from lines +4 and +18 of the code are the command that the payload uses to execute the defined `CMD` command. Still have to find where the choosen command is stored. Let's review the content of memory positions for the `(bad)` instructions. Those instructions are in positions `0x0000555555558080` and `0x0000555555558081`. Let's get the contents with `gdb`:
```bash
   0x000055555555807b <+27>:	call   0x55555555808b <code+43>
   0x0000555555558080 <+32>:	(bad)                                        <==
   0x0000555555558081 <+33>:	(bad)                                        <==
   0x0000555555558082 <+34>:	imul   ebp,DWORD PTR [rsi+0x2f],0x2d20736c   
   0x0000555555558089 <+41>:	ins    BYTE PTR es:[rdi],dx
   0x000055555555808a <+42>:	add    BYTE PTR [rsi+0x57],dl
   0x000055555555808d <+45>:	mov    rsi,rsp
   0x0000555555558090 <+48>:	syscall 
   0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) x/xg 0x0000555555558080
0x555555558080 <code+32>:	0x20736c2f6e69622f
(gdb) x/2xg 0x0000555555558080
0x555555558080 <code+32>:	0x20736c2f6e69622f	0xe689485756006c2d
(gdb) 
```
Let's check what's this hex values `0x20736c2f6e69622f` and `0xe689485756006c2d` are:
```python
>>> "20736c2f6e69622f".decode('hex')[::-1]
'/bin/ls '
>>> "e689485756006c2d".decode('hex')[::-1]
'-l\x00VWH\x89\xe6'
>>> 
```
Here is the command `/bin/ls -l` stored in 10 bytes plus a NULL for the end of the string. Found it, it's stored in the `.text` section when the payload is created by `msfvenom`. The rest of the contents, `\x00VWH\x89\xe6` are the code instructions. With this, discovered why the mess in the code with the `(bad)` as it's for storing the command. 

> At this point we know that `/bin/sh -c` is stored in the stack, and the `/bin/ls -l` in the `.text` section in the 

Going further, a `syscall` instruction is made. Let's get which one is and what are it's parameters. Reviewing the code, the instructions at +0 and +2 assigns the `0x3b` value to RAX, the register to define the syscall number. This value is decimal 59 that stands for the `execve` syscall:
```bash
Dump of assembler code for function code:
=> 0x0000555555558060 <+0>:	push   0x3b   <==  Syscall Number
   0x0000555555558062 <+2>:	pop    rax    <==
   0x0000555555558063 <+3>:	cdq    
**_REMOVED_**
   0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) 
```
From `execve` manpage:
```c
int  execve  (const  char  *filename,  const  char *argv [], const char *envp[]);
```
In assembly, params for this syscall are mapped to the following registers:
- RDI for `const  char  *filename`. This has to be the pointer to the `/bin/sh` command that's stored in the stack.
- RSI for `const  char *argv []`. The pointer to the address of the parameters for the command, in this case parameters are `/bin/sh` itself and `-c`.
- RDX for `const char *envp[]`. This value will be NULL (`0x0000000000000000`).
This is done in the following line codes:
```asm
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x0000555555558063 <+3>:	cdq                 <== RDX <- 0x00
   0x0000555555558064 <+4>:	movabs rbx,0x68732f6e69622f
   0x000055555555806e <+14>:	push   rbx          <== Stores /bin/sh
   0x000055555555806f <+15>:	mov    rdi,rsp      <== RSP has the pointer to /bin/sh, puts it in RDI
   0x0000555555558072 <+18>:	push   0x632d
   0x0000555555558077 <+23>:	mov    rsi,rsp      <== Second parameter
**_REMOVED_**
End of assembler dump.
(gdb) 
```














### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment05) for this assignment contains the following files:

- [Payload_01.c](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Payload_01.c) : The C file cloned from `shellcode.c` to execute the `linux/x64/exec` shellcode
- [Payload_02.c](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Payload_02.c) : The C file cloned from `shellcode.c` to execute the shellcode
- [Payload_03.c](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Payload_03.c) : The C file cloned from `shellcode.c` to execute the shellcode

### The End
---
This pages have been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html).

Student ID: PA-14628
 
