#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "mpi.h"
struct ctr_state 
{ 
	unsigned char ivec[AES_BLOCK_SIZE];	 
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
}; 
AES_KEY key; 
MPI_File readFile, writeFile;
MPI_Status status;
int rank, size, sz, bufsize, nints, bytes_read, bytes_written;	 
unsigned char indata[AES_BLOCK_SIZE]; 
unsigned char outdata[AES_BLOCK_SIZE];
unsigned char iv[AES_BLOCK_SIZE];
struct ctr_state state;	 
int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{		 
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);
	memset(state->ivec + 8, 0, 8);
	memcpy(state->ivec, iv, 8);
}
void fdecrypt(const unsigned char* enc_key)
{	
	FILE *rFile = fopen("iv.txt","r");
	fread(iv, 1, AES_BLOCK_SIZE, rFile); 
	printf("IV Read Done : %s\n", iv);
	init_ctr(&state, iv);
	fclose(rFile);
	MPI_Init(NULL,NULL);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	if(rank == 0) {
		
		FILE *fp = fopen("loremenc.txt", "r");
		fseek(fp, 0L, SEEK_END);
		sz = ftell(fp);
		// printf("Size of enc : %d\n", sz);
		fclose(fp);
	}
	if (AES_set_decrypt_key(enc_key, 128, &key) < 0)
	{
		fprintf(stderr, "Could not set decryption key.");
		exit(1);
	}

	MPI_File_open(MPI_COMM_WORLD,"loremenc.txt",MPI_MODE_RDONLY,MPI_INFO_NULL,&readFile);
	MPI_File_open(MPI_COMM_WORLD,"loremdec.txt",MPI_MODE_CREATE|MPI_MODE_WRONLY,MPI_INFO_NULL,&writeFile);
	int numblocks = (sz/AES_BLOCK_SIZE);
	int partition = (numblocks/size);
	int i = 0;
	int j;
	for(i = 0; i <= partition*AES_BLOCK_SIZE; i += AES_BLOCK_SIZE)
	{
		MPI_File_read_at(readFile, ((rank)*partition*AES_BLOCK_SIZE)+i, indata, AES_BLOCK_SIZE, MPI_CHAR, &status);
		printf("indata : %s\n", indata);
		AES_ctr128_encrypt(indata, outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
		printf("outdata : %s\n", outdata);
		MPI_File_write_at(writeFile, ((rank)*partition*AES_BLOCK_SIZE)+i, outdata, AES_BLOCK_SIZE, MPI_CHAR, &status);
	}
	MPI_File_close(&writeFile);
	MPI_File_close(&readFile);
	MPI_Finalize();
}
int main(int argc, char **argv){
	unsigned const char* enc_key = "1234567812345678";
	fdecrypt(enc_key);
	return 0;
}
