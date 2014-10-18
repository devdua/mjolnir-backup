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
void init_IV()
{
	if(!RAND_bytes(iv, AES_BLOCK_SIZE))
	{
		fprintf(stderr, "Could not create random bytes.");
		exit(1);    
	}
	FILE *wFile = fopen("iv.txt","w");
	fwrite(iv, 1, 8, wFile); // IV bytes 1 - 8
    fwrite("\0\0\0\0\0\0\0\0", 1, 8, wFile); // Fill the last 4 with null bytes 9 - 16
    printf("IV Write Done : %s\n", iv);
    fclose(wFile);
}
void fdecrypt(const unsigned char* enc_key)
{	
	if(rank == 0) {
		FILE *rFile = fopen("iv.txt","r");
		fread(iv, 1, AES_BLOCK_SIZE, rFile); 
		printf("IV Read Done : %s\n", iv);
		init_ctr(&state, iv);
	//fclose(rFile);
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
	// printf("MPI File done\n");
	//init_ctr(&state, iv); //Counter call
	int numblocks = (sz/AES_BLOCK_SIZE);
	int partition = (numblocks/size);
	int i = 0;
	int j;
	for(i = 0; i <= partition*AES_BLOCK_SIZE; i += AES_BLOCK_SIZE)
	{
		MPI_File_read_at(readFile, ((rank)*partition*AES_BLOCK_SIZE)+i, indata, AES_BLOCK_SIZE, MPI_CHAR, &status);
		printf("indata : %s\n", indata);
		AES_ctr128_encrypt(indata, outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
		MPI_File_write_at(writeFile, ((rank)*partition*AES_BLOCK_SIZE)+i, outdata, AES_BLOCK_SIZE, MPI_CHAR, &status);
	}
	MPI_File_close(&writeFile);
	MPI_File_close(&readFile);
}
void fencrypt(const unsigned char* enc_key)
{ 
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
	{
		fprintf(stderr, "Could not set encryption key.");
		exit(1); 
	}
	FILE *fp = fopen("lorem.txt", "r");
	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	fclose(fp);
	MPI_Init(NULL,NULL);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	if (rank == 0)
	{
		init_IV();
		init_ctr(&state, iv);
	}
	MPI_File_open(MPI_COMM_WORLD,"lorem.txt",MPI_MODE_RDONLY,MPI_INFO_NULL,&readFile);
	MPI_File_open(MPI_COMM_WORLD,"loremenc.txt",MPI_MODE_CREATE|MPI_MODE_WRONLY,MPI_INFO_NULL,&writeFile);
	//init_ctr(&state, iv); //Counter call
	
	int numblocks = (sz/AES_BLOCK_SIZE);
	int partition = (numblocks/size);
	// printf("PARTITION SIZE : %d\n", partition);
	int i = 0;
	int j;
	for(i = 0; i < partition*AES_BLOCK_SIZE; i += AES_BLOCK_SIZE)
	{
		MPI_File_read_at(readFile, ((rank)*partition*AES_BLOCK_SIZE)+i, indata, AES_BLOCK_SIZE, MPI_CHAR, &status);
		printf("%s", indata);
		AES_ctr128_encrypt(indata, outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
		MPI_File_write_at(writeFile, ((rank)*partition*AES_BLOCK_SIZE)+i, outdata, AES_BLOCK_SIZE, MPI_CHAR, &status);
	}
	MPI_File_close(&writeFile);
	MPI_File_close(&readFile);
}
int main(int argc, char **argv){
	unsigned const char* enc_key = "1234567812345678";
	fencrypt(enc_key);
	if (rank == 0)
	{
		printf("Encoded : \n");
		printf("\n");
	}
	//fdecrypt(enc_key);
	MPI_Finalize();
	return 0;
}
