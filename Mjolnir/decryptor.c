#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "mpi.h"

// Code example uses partail code from: http://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl
// Mostly in the ctr_ state, and init_ctr functions. 

struct ctr_state 
{ 
	unsigned char ivec[AES_BLOCK_SIZE];	 
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
}; 

FILE *readFile;
FILE *writeFile;
AES_KEY key; 
int rank, size, bufsize, nints, bytes_read, bytes_written;	 
unsigned char indata[AES_BLOCK_SIZE]; 
unsigned char outdata[AES_BLOCK_SIZE];
unsigned char iv[AES_BLOCK_SIZE];
struct ctr_state state;	 

int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{		 
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);

    /* Initialise counter in 'ivec' to 0 */
	memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
	memcpy(state->ivec, iv, 8);
}
/*
void fencrypt(char* read, char* write, const unsigned char* enc_key)
{ 
	if(!RAND_bytes(iv, AES_BLOCK_SIZE))
	{
		fprintf(stderr, "Could not create random bytes.");
		exit(1);    
	}

	readFile = fopen(read,"rb"); // The b is required in windows.
	writeFile = fopen(write,"wb");
	
	if(readFile==NULL) 	
	{
		fprintf(stderr, "Read file is null."); 
		exit(1);
	}
	
	if(writeFile==NULL)
	{
		fprintf(stderr, "Write file is null."); 
		exit(1);
	}
	
	fwrite(iv, 1, 8, writeFile); // IV bytes 1 - 8
    fwrite("\0\0\0\0\0\0\0\0", 1, 8, writeFile); // Fill the last 4 with null bytes 9 - 16
    printf("IV Write: %s\n", iv);
	//Initializing the encryption KEY
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
    	fprintf(stderr, "Could not set encryption key.");
    	exit(1); 
    }

	init_ctr(&state, iv); //Counter call
	//Encrypting Blocks of 16 bytes and writing the output.txt with ciphertext	
	while(1) 	
	{
		bytes_read = fread(indata, 1, AES_BLOCK_SIZE, readFile); 
		AES_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);

		bytes_written = fwrite(outdata, 1, bytes_read, writeFile); 
		if (bytes_read < AES_BLOCK_SIZE)
		{
			break;
		}
	}
	
	fclose(writeFile);
	fclose(readFile);
}
*/
void fdecrypt(char* read, char* iv, char* write, const unsigned char* enc_key)
{	

	printf("Started %d\n", rank);
	readFile=fopen(read,"rb"); // The b is required in windows.
	FILE *ivr = fopen(iv, "r");
	writeFile=fopen(write,"wb");
	
	if(readFile==NULL)
	{
		fprintf(stderr,"Read file is null."); 
		exit(1);
	}
	
	if(writeFile==NULL)	
	{
		fprintf(stderr, "Write file is null."); 
		exit(1);
	}
	
	fread(iv, 1, AES_BLOCK_SIZE, ivr); 
	fclose(ivr);
	//Initializing the encryption KEY
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
	{
		fprintf(stderr, "Could not set decryption key.");
		exit(1);
	}

	init_ctr(&state, iv);//Counter call
	//Encrypting Blocks of 16 bytes and writing the output.txt with ciphertext
	printf("IV Read: %s\n", iv);		 
	while(1) 	
	{
		bytes_read = fread(indata, 1, AES_BLOCK_SIZE, readFile);	
		AES_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);
		printf("outdata : %s\n", outdata);

		bytes_written = fwrite(outdata, 1, bytes_read, writeFile); 
		if (bytes_read < AES_BLOCK_SIZE) 
		{
			break;
		}
	}
	fclose(writeFile); 
	fclose(readFile); 
}
/*void getProcessName(char element[], char root[], char rank[])
{
	strcpy(element, root);
	strcat(element, rank);
	strcat(element, ".txt");
}*/
int main(int argc, char *argv[])
{
	//fencrypt("lorem.txt", "enced.txt", (unsigned const char*)"1234567812345678");
	printf("Decryption initiated.\n");
	MPI_Init(NULL,NULL);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	char blockname[11], ivname[7], destination[9], rankChar[1];
	int i = 0;
	rankChar[0] = (char)(((int)'0')+rank);
	// getProcessName(blockname,"block",rankChar);
	// getProcessName(ivname,"iv",rankChar);
	// getProcessName(destination,"decr",rankChar);    
	sprintf(blockname, "block%d.txt", rank);
	sprintf(ivname, "iv%d.txt", rank);
	sprintf(destination, "decr%d.txt", rank);
	printf("Process %d decrypting %s %s %s\n", rank, blockname, ivname, destination);
	fdecrypt(blockname,ivname,destination, (unsigned const char*)"1234567812345678");
	printf("Done.\n");
	MPI_Finalize();
	return 0;

}