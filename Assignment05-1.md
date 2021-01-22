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
After opening the file in `gdb` and set the `set disassembly-flavor intel`, a breakpoint is placed in `*&code` address. This is where the shellcode is placed and can start debugging just from there. Once the breakpoint is `set`, the `run` comand execs the code until reaching theit. Now if `disassemble` the code will show the payload code:
```asm
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
In the code, can see that some hex values are stored in registers and then in the stack. Let's convert all those hex values, to get any clue and idea of what the shellcode does. For that, Python is used to convert and reverse values:
```python
>>> "68732f6e69622f".decode('hex')[::-1]
'/bin/sh'
>>> "632d".decode('hex')[::-1]
'-c'
>>> 
```
Those values from lines +4 and +18 of the code, are the command that the payload has to execute and been defined in the `CMD` option. Still have to find where the choosen command is stored. Let's review the content of memory positions for the `(bad)` instructions. Those instructions are in positions `0x0000555555558080` and `0x0000555555558081`. Let's get the contents with `gdb`:
```asm
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

Going further, a `syscall` instruction is made. Let's get which one is and what are it's parameters. Reviewing the code, the instructions at +0 and +2 assigns the `0x3b` value to RAX, the register to define the syscall number. This value is decimal 59, that stands for the `execve` syscall:
```asm
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
- RSI for `const  char *argv []`. The pointer to the address of the parameters for the command, in this case parameters are `/bin/sh` itself, `-c` and `/bin/ls -l".
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
At this point just something not so clear, the second parameter. Let's think about the `call` instruction on +27. How does `call` work:

1. Stores de Address of next instruction in the stack
2. Increments RSP
3. Jumps to the address

This means that once the instruction at +27 (`call 0x55555555808b <code+43>`) executes, the address of the parameters (`/bin/ls -l`) for the `execve` syscall are stored in the Stack and pointed by RSP. Hence why the instruction at +43 (`mov rsi,rsp`) is just before the `syscall`, to place the value of the adress containing the adress for the parameters:
```asm
(gdb) disassemble
**_REMOVED_**
0x000055555555807a <+26>:	push   rdx
0x000055555555807b <+27>:	call   0x55555555808b <code+43>     <== Pushes in stack the address of second parameter
0x0000555555558080 <+32>:	(bad)  
0x0000555555558081 <+33>:	(bad)  
0x0000555555558082 <+34>:	imul   ebp,DWORD PTR [rsi+0x2f],0x2d20736c
0x0000555555558089 <+41>:	ins    BYTE PTR es:[rdi],dx
0x000055555555808a <+42>:	add    BYTE PTR [rsi+0x57],dl
0x000055555555808d <+45>:	mov    rsi,rsp                      <== RSI <- Address of address containing the parameter string
0x0000555555558090 <+48>:	syscall 
**_REMOVED_^^
(gdb)
```
The call jumps to +43 (`0x55555555808b`), and there, the code does "something" to continue and finally end at +45 to execute the `mov rsi, rsp` to definitelly place the second parameter into RSI for the syscall. Here `gdb` probably is not properly disassembling, because the `call` goes to +43 while at +42 there is an `add`. 

One step more, run the code step by step and see what we can find out. Will do the following steps to get the info about register status during the execution and see if it's values are the right ones and match with the values of them just before `syscall`: 

1. Get the original value of **RSP** when the shellcode begins, and take well note of it: **`0x7fffffffe758`**
```asm
(gdb) disassemble 
Dump of assembler code for function code:
=> 0x0000555555558060 <+0>:	push   0x3b
**_REMOVED_** 
   0x0000555555558090 <+48>:	syscall 
   0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) info registers rsp
rsp            0x7fffffffe758      0x7fffffffe758
(gdb) 
```
2. `stepi`'ing instructions at +0 and +2, **RAX** gets the syscall number as it's value, **`0x3b`**. This value has to be the same just before the syscall. Also at +3 **RDX** gets value **0x00** by the `cdq`.
```asm
(gdb) stepi
0x0000555555558062 in code ()
(gdb) stepi
0x0000555555558063 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
   0x0000555555558060 <+0>:	push   0x3b
   0x0000555555558062 <+2>:	pop    rax
=> 0x0000555555558063 <+3>:	cdq    
**_REMOVED_**
End of assembler dump.
(gdb) info registers rax
rax            0x3b                59
(gdb) 
```
3. `stepi`'ing +4 and +14 pushes the `"/bin/sh",0x00` string in the stack. Here the original **RSP** would decrease 8 positions it's value to **`0x7fffffffe750`** (the 8 bytes pushed in the string). 
```asm
(gdb) stepi
0x000055555555806f in code ()
(gdb) disassemble 
**_REMOVED_**
   0x0000555555558064 <+4>:	movabs rbx,0x68732f6e69622f
   0x000055555555806e <+14>:	push   rbx                  <== "/bin/sh",0x00 o the stack
=> 0x000055555555806f <+15>:	mov    rdi,rsp              
**_REMOVED__*
End of assembler dump.
(gdb) info registers rsp
rsp            0x7fffffffe750      0x7fffffffe750
(gdb) x/1xg $rsp
0x7fffffffe750:	0x0068732f6e69622f
(gdb) x/s $rsp
0x7fffffffe750:	"/bin/sh"
(gdb) 
```` 
4. **RDI** register gets the address **`0x7fffffffe750`**, that is the memory position storing the `/bin/sh` command string first parameter of `execve`). The **RDI** value has to be **`0x7fffffffe750`**. _The value of RDI should not change anymore_. Everything looks fine by now:
```asm
(gdb) disassemble 
**_REMOVED_**
   0x000055555555806e <+14>:	push   rbx
   0x000055555555806f <+15>:	mov    rdi,rsp
=> 0x0000555555558072 <+18>:	push   0x632d
**_REMOVED_**
End of assembler dump.
(gdb) info registers rsp
rsp            0x7fffffffe750      0x7fffffffe750
(gdb) info registers rdi
rdi            0x7fffffffe750      140737488349008
(gdb) x/s $rsp
0x7fffffffe750:	"/bin/sh"
(gdb) 
```
5. Next, the `-c` string as the command parameter has to be also stacked. **RSP** updates to point now to **`0x7fffffffe748`**, and the top of the stack contains the string `"-c"`:
```asm
(gdb) stepi
0x0000555555558077 in code ()
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x0000555555558072 <+18>:	push   0x632d
=> 0x0000555555558077 <+23>:	mov    rsi,rsp
**_REMOVED_**
End of assembler dump.
(gdb) info registers rsp 
rsp            0x7fffffffe748      0x7fffffffe748
(gdb) x/s $rsp
0x7fffffffe748:	"-c"
(gdb) 
```
6. Next instruction, saves the value of **RSP** into **RSI**. Now **RSI** has te value **`0x7fffffffe748`**, pointing to the address of the first parameter for the command:
```asm
(gdb) stepi
0x000055555555807a in code ()
(gdb) disassemble 
**_REMOVED_**
   0x0000555555558077 <+23>:	mov    rsi,rsp
=> 0x000055555555807a <+26>:	push   rdx
**_REMOVED_**
End of assembler dump.
(gdb) info registers rsp rsi
rsp            0x7fffffffe748      0x7fffffffe748
rsi            0x7fffffffe748      140737488349000
(gdb) x/s $rsi
0x7fffffffe748:	"-c"
(gdb) 
```
7. **RDX** that contains a NULL is also `push`'ed, updating **RSP** value to **`0x7fffffffe740`**
```asm
(gdb) stepi
0x000055555555807b in code ()
(gdb) disassemble 
**_REMOVED_**
   0x000055555555807a <+26>:	push   rdx
=> 0x000055555555807b <+27>:	call   0x55555555808b <code+43>
**_REMOVED_**
End of assembler dump.
(gdb) info registers rsp
rsp            0x7fffffffe740      0x7fffffffe740
(gdb) x/xg $rsp
0x7fffffffe740:	0x0000000000000000
(gdb) 
```
8. Now go to the `call` instruction. After executes, **`0x0000555555558080`** should be stacked and **RSP** updated -8 positions, to **`0x7fffffffe738`**:
```asm
(gdb) stepi                                         <= stepi
0x000055555555808b in code ()                       <== Something strange done by gdb :-/
                                                     == But it's the address pointed by CALL
(gdb) info registers rsp 
rsp            0x7fffffffe738      0x7fffffffe738   <== RSP Updated
(gdb) x/x $rsp
0x7fffffffe738:	0x0000555555558080                  <== CALL saves the next instruction address in the stack. 
                                                     == For us is the address pointing to /bin/ls -l
(gdb) 
```
  This address **`0x0000555555558080`** stacked, is the string defined as the program to execute for the payload, that in the `execve` call would be the 3th parameter. Let's check if this address really points to the `"/bin/ls -l"` string:
  ```asm
  (gdb) x/s 0x0000555555558080
  0x555555558080 <code+32>:	"/bin/ls -l"
  (gdb)
  ```
9. Now we define a `hook-stop` to follow up the values of **RSP** and **RSI** as this last one is the register that still does not have the right value before the syscall. Now have to `stepi` blindly as `gdb` does not show the instruction when disassembles:

```asm
(gdb) define hook-stop
Type commands for definition of "hook-stop".
End with a line saying just "end".
>info registers rsi rsp
>x/xg $rsp
>end
(gdb) stepi                                           <== Another stepi
rsi            0x7fffffffe748      140737488349000    <== Still points to '-c'
rsp            0x7fffffffe730      0x7fffffffe730     <== 64 bits been pushed in the stack updating RSP
0x7fffffffe730:	0x00007fffffffe748
0x000055555555808c in code ()
(gdb) x/s $rsi
0x7fffffffe748:	"-c"                                  <== $RDI contais '-c'
(gdb) stepi                                           <== Another stepi
rsi            0x7fffffffe748      140737488349000
rsp            0x7fffffffe728      0x7fffffffe728     <== 64 bits more been pushed in the stack updating RSP
0x7fffffffe728:	0x00007fffffffe750
0x000055555555808d in code ()
(gdb) 
```
  At this point `gdb` recovered and next instruction to execute will be +45 `mov rsi, rsp`. 
  ```asm
  (gdb) disassemble 
  Dump of assembler code for function code:
     0x0000555555558060 <+0>:	push   0x3b
     0x0000555555558062 <+2>:	pop    rax
     0x0000555555558063 <+3>:	cdq    
     0x0000555555558064 <+4>:	movabs rbx,0x68732f6e69622f
     0x000055555555806e <+14>:	push   rbx
     0x000055555555806f <+15>:	mov    rdi,rsp
     0x0000555555558072 <+18>:	push   0x632d
     0x0000555555558077 <+23>:	mov    rsi,rsp
     0x000055555555807a <+26>:	push   rdx
     0x000055555555807b <+27>:	call   0x55555555808b <code+43>
     0x0000555555558080 <+32>:	(bad)  
     0x0000555555558081 <+33>:	(bad)  
     0x0000555555558082 <+34>:	imul   ebp,DWORD PTR [rsi+0x2f],0x2d20736c
     0x0000555555558089 <+41>:	ins    BYTE PTR es:[rdi],dx
     0x000055555555808a <+42>:	add    BYTE PTR [rsi+0x57],dl
  => 0x000055555555808d <+45>:	mov    rsi,rsp
     0x0000555555558090 <+48>:	syscall 
     0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
  End of assembler dump.
  (gdb) 
  ```
##### Let's do a break in the debugging...
...to check every register and stack contents, for everything looks as it should. 
As had to blindly `stepi` by two instructions, need to ensure that values for the registers are the ones that should be for the analysis being done until now. All are correct:

- **RAX** : `0x3b`

```asm
(gdb) info registers rax 
rax            0x3b                59
(gdb) 
```

- **RDI** : `0x7fffffffe750`  ==> Address of /bin/sh

```asm
(gdb) info registers rax 
rax            0x3b                59
(gdb) info registers rdi
rdi            0x7fffffffe750      140737488349008
(gdb) x/s $rdi
0x7fffffffe750:	"/bin/sh"
(gdb) 
```

- **RSI** : `0x7fffffffe748`  ==> Address of '-c' in the stack

```asm
(gdb) info registers rsi
rsi            0x7fffffffe748      140737488349000
(gdb) x/s $rsi
0x7fffffffe748:	"-c"
(gdb) 
```

- **RDX** : 0x00

```asm
(gdb) info registers rdx
rdx            0x0                 0
(gdb) 
```
##### End break
All looks good, the part where had to `stepi` blindly, didnt change the original values of the registers. But also, in that blind code, some values been pushed in the stack in the right order required by the stack technique for `execve` syscall:
- **`0x00007fffffffe750`**  that's the memory address for `/bin/sh` :
```asm
(gdb) x/x $rsp
0x7fffffffe728:	0x00007fffffffe750
(gdb) x/s 0x00007fffffffe750
0x7fffffffe750:	"/bin/sh"
(gdb) 
```
- **`0x00007fffffffe748`** that's the memory address for  `-c` :
```asm
(gdb) x/xg 0x7fffffffe730
0x7fffffffe730:	0x00007fffffffe748
(gdb) x/s 0x00007fffffffe748
0x7fffffffe748:	"-c"
(gdb) 
```
By the operations done in the blind code and the actual values of the registers, what has to be done is:
```asm
push rsi    <== the @ for "-c"
push rdi    <== the @ for //bin/sh"
```

9. Let's `stepi`, this is where definitelly **RSI** get's the pointer to the second parameter for the `execve` syscall.
```asm
(gdb) stepi
0x0000555555558090 in code ()
(gdb) disassemble 
**_REMOVED__**
   0x000055555555808d <+45>:	mov    rsi,rsp
=> 0x0000555555558090 <+48>:	syscall 
   0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) info registers rsi rsp
rsi            0x7fffffffe728      140737488348968        <== Same value as RSP
rsp            0x7fffffffe728      0x7fffffffe728
(gdb) 
```
Let's review the status of the stack:
```markdown
  Stack Address      Value pointing a sting    String pointed 
|------------------|------------------------|------------------|
|  0x7fffffffe728  |   0x00007fffffffe750   | "/bin/sh"        |
|  0x7fffffffe730  |   0x00007fffffffe748   | "-c"             |
|  0x7fffffffe738  |   0x0000555555558080   | "/bin/ls -l"     |
|  0x7fffffffe740  |   0x0000000000000000   | n/a              |
|------------------------------------------ -------------------|
```

At this point, the **`const  char *argv []`** is referenced by **RSI** that got the value of **RSP** (`0x7fffffffe728`). From there, the rest of the required params are also in order in the stack. With everything looking in order, can go into the syscall, that will finally execute the `/bin/ls` comand:

```asm
(gdb) disassemble 
Dump of assembler code for function code:
**_REMOVED_**
   0x000055555555808d <+45>:	mov    rsi,rsp
=> 0x0000555555558090 <+48>:	syscall 
   0x0000555555558092 <+50>:	add    BYTE PTR [rax],al
End of assembler dump.
(gdb) stepi
process 1123 is executing new program: /usr/bin/dash

[1]+  Stopped                gdb ./Payload_01
SLAE64> 
```
Everything worked as expected!

### Thoughts
---
The following handicaps been found:

- `gdb` not showing properly those blind instructions. Making it a bit more complicated to debug having to guess which instructions should been executed. This been resolved per the results on the stack and guessing which values should be stacked.
- the `call` technique used, combined with the parameters for the payload stored in the code in the `.text` section had to be understood. Per how this is done, some shellcodes should have been added because the strings that `gdb` probably interprets wrongly

The payload uses a mix of Stack and a new Technique using the `call` that results in a very interesting shellcode to review.

#### `CALL` Trick Analysis. What about the _gdb_ issue
If we check again the `objdump` output for the program:
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
The `call` does replace **RIP** value to jump to the instruction at `0x408b`. Reviewing this opcodes:

- Opcode 0x56: Stands for `push rsi`
- Opcode 0x57: Stands for `push rdi`

Notice that if we take the shellcode from the `0x4080` to `0x408a` adresses and convert it to a string, the `"/bin/ls -l",0x00` is stored on there:
```python
>>> "2f62696e2f6c73202d6c00".decode('hex')
'/bin/ls -l\x00'
>>> 
```
Results in the string we defined as the comand to execute in the payload. Now everything makes sense :-)

This shows that `msfvenom` when constructs the payload, has to take care to make the `call` function to jump to the first instruction after the length of the command string.

This **`call`** technique used to store the `CMD` parameter during the payload generation, is interesting:
- It allows to have any string stored in the `.text` section
- Does not matter the size of the string. Does not need to be a multiple of 8, and add extra chars to it (avoids the use of strings like `/bin**//**ls` adding a extra "/" to make it multiple of 8).



### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment05) for this assignment contains the following files:

- [Payload_01.c](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Payload_01.c) : The C file cloned from `shellcode.c` to execute the `linux/x64/exec` shellcode.
- [Shellcode_01.txt](https://github.com/galminyana/SLAE64/blob/main/Assignment05/Shellcode_01.txt) : The rax shellcode in hex into a text file.

### The End
---
This pages have been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html).

Student ID: PA-14628
 
