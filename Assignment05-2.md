## Assignment #5.1: Shellcode `linux/x64/exec` Dissection
---
---
### Introduction
---
The first `msfvenom` shellcode that is going to be dissected in functionality is the `linux/x64/exec` payload.

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
```
The payload is only 40 bytes and it requires a parameter in the `CMD` option, that's the command to execute. 

### Creating the Shellcode
---
Will execute the `ls -l` command. Decided to use a command that can receive options to check how the payload handles it. Also added the full path to make the command string a 7 bytes length only. Let's generate the payload:
```c
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

```asm
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
















### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment05) for this assignment contains the following files:

- [Payload_01.c](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Payload_01.c) : The C file cloned from `shellcode.c` to execute the `linux/x64/exec` shellcode.
- [Shellcode_01.txt](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Shellcode_01.txt) : The rax shellcode in hex into a text file.

### The End
---
This pages have been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html).

Student ID: PA-14628
 
