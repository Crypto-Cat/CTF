#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

int decrypt(void* buffer, int buffer_len, char* IV, char* key, int key_len) {
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);

  if( buffer_len % blocksize != 0 ){ 
    return 1;
  }
  
  mcrypt_generic_init(td, key, key_len, IV);
  mdecrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

int main(int argc, char* argv[]) // gcc src.c -o dec -lmcrypt -ggdb
{
  char* IV = "AAAAAAAAAAAAAAAA";
  char *key = "VXISlqY>Ve6D<{#F";
  int keysize = 16;
  char* buffer;
  int buffer_len = 16;

  int x, numRead;
  FILE *fp = fopen("core", "rb");
  fseek(fp, 0, SEEK_END);
  int fileSize = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  for(x = 0; x < fileSize; x += 16) {
      void* ciphertext = malloc(buffer_len);
      fread(ciphertext, 1, 16, fp);
      printf("Ciphertext contents: %s\n", ciphertext);
      decrypt(ciphertext, buffer_len, IV, key, keysize);
      if (strncmp(ciphertext, "HTB{", 4) == 0){
        printf("Decrypted contents: %s\n", ciphertext);
        fclose(fp);
        return 0;
      }
  }
  fclose(fp);
  return 0;
}

