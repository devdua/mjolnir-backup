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

FILE *readFile;
FILE *writeFile;
AES_KEY key; 
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
char *substring(char *string, int position, int length) 
{
	char *pointer;
	int c;

	pointer = malloc(length+1);

	if (pointer == NULL)
	{
		printf("Unable to allocate memory.\n");
		exit(EXIT_FAILURE);
	}

	for (c = 0 ; c < position -1 ; c++) 
		string++; 

	for (c = 0 ; c < length ; c++)
	{
		*(pointer+c) = *string;      
		string++;   
	}

	*(pointer+c) = '\0';

	return pointer;
}
void fdecrypt(const unsigned char* enc_key)
{	
	FILE *rFile = fopen("iv.txt","r");
	fread(iv, 1, AES_BLOCK_SIZE, rFile); 
	init_ctr(&state, iv);
	fclose(rFile);
	if (AES_set_decrypt_key(enc_key, 128, &key) < 0)
	{
		fprintf(stderr, "Could not set decryption key.");
		exit(1);
	}
	MPI_Status status;
	MPI_File readFile, writeFile;
	MPI_File_open(MPI_COMM_WORLD,"loremenc.txt",MPI_MODE_RDONLY,MPI_INFO_NULL,&readFile);
	MPI_File_open(MPI_COMM_WORLD,"loremdec.txt",MPI_MODE_CREATE|MPI_MODE_WRONLY,MPI_INFO_NULL,&writeFile);
    init_ctr(&state, iv); //Counter call
    int numblocks = sz/size;
	// //printf("numblocks : %d, Times : %d, Size : %d\n", AES_BLOCK_SIZE,times,sz);
    int i = 0;
    int times = (numblocks/AES_BLOCK_SIZE)+ceil(numblocks/AES_BLOCK_SIZE);
    if (size == 1)
    {
    	rank = 1;	
    }
    int j;
    char* subbuff;
    MPI_File_read_at(readFile, (rank)*numblocks, indata, numblocks, MPI_CHAR, &status);
    //AES_ctr128_encrypt(indata, outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);

	//printf("indata : %s\n", indata);
	// for (i = 0; i < numblocks; i = i+AES_BLOCK_SIZE)
	// {
	// 	subbuff = substring(indata, i+1, AES_BLOCK_SIZE);
	// 	//printf("subbuff : %s\n", subbuff);
	// 	AES_ctr128_encrypt(subbuff, outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
    MPI_File_write_at(writeFile, (rank)*numblocks, outdata, (numblocks), MPI_UNSIGNED_CHAR, &status);
	// MPI_File_write_at(writeFile, ((rank)*AES_BLOCK_SIZE)+i, outdata, (AES_BLOCK_SIZE), MPI_UNSIGNED_CHAR, &status);
	// }
    MPI_File_close(&writeFile);
    MPI_File_close(&readFile);
    //MPI_Finalize();
}
void fencrypt(const unsigned char* enc_key)
{ 
	if(!RAND_bytes(iv, AES_BLOCK_SIZE))
	{
		fprintf(stderr, "Could not create random bytes.");
		exit(1);    
	}
	FILE *wFile = fopen("iv.txt","w");
	fwrite(iv, 1, 8, wFile); // IV bytes 1 - 8
    fwrite("\0\0\0\0\0\0\0\0", 1, 8, wFile); // Fill the last 4 with null bytes 9 - 16
    printf("Write Done\n");
    fclose(wFile);
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
    	fprintf(stderr, "Could not set encryption key.");
    	exit(1); 
    }
    MPI_Init(NULL,NULL);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    MPI_Status status;
    MPI_File readFile, writeFile;
    MPI_File_open(MPI_COMM_WORLD,"lorem.txt",MPI_MODE_RDONLY,MPI_INFO_NULL,&readFile);
    MPI_File_open(MPI_COMM_WORLD,"loremenc.txt",MPI_MODE_CREATE|MPI_MODE_WRONLY,MPI_INFO_NULL,&writeFile);
    printf("MPI File done\n");
	init_ctr(&state, iv); //Counter call
	int numblocks = (sz/AES_BLOCK_SIZE);
	// //printf("numblocks : %d, Times : %d, Size : %d\n", AES_BLOCK_SIZE,times,sz);
	int i = 0;
	// printf("numblocks : %d, times : %d\n", numblocks,times);
	// char processor_name[MPI_MAX_PROCESSOR_NAME];
	// int name_len;
	// MPI_Get_processor_name(processor_name, &name_len);
	int j;
	char* subbuff;
	for(i = 0; i < sz; i += AES_BLOCK_SIZE){
		MPI_File_read_at(readFile, (rank)*numblocks+i, indata, numblocks, MPI_UNSIGNED_CHAR, &status);
		printf("indata : %s\n", indata);
		AES_ctr128_encrypt(indata, outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
		MPI_File_write_at(writeFile, (rank)*numblocks+i, outdata, (numblocks), MPI_UNSIGNED_CHAR, &status);
	}
    //AES_ctr128_encrypt(indata, outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
	// for (i = 0; i < numblocks; i = i+AES_BLOCK_SIZE)
	// {
	// 	subbuff = substring(indata, i+1, AES_BLOCK_SIZE);
	// 	//printf("subbuff : %s\n", subbuff);
	// 	AES_ctr128_encrypt(subbuff, outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
	// MPI_File_write_at(writeFile, (rank)*numblocks, outdata, (numblocks), MPI_UNSIGNED_CHAR, &status);
	/*
	int j;
	char* subbuff;
	MPI_File_read_at(readFile, (rank)*numblocks, indata, numblocks, MPI_CHAR, &status);
	printf("indata : %s\n", indata);
	for (i = 0; i < numblocks; i = i+AES_BLOCK_SIZE)
	{
		subbuff = substring(indata, i+1, AES_BLOCK_SIZE);
		printf("subbuff : %s\n", subbuff);
		AES_ctr128_encrypt(subbuff, outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
		
		MPI_File_write_at(writeFile, ((rank)*AES_BLOCK_SIZE)+i, outdata, (AES_BLOCK_SIZE), MPI_UNSIGNED_CHAR, &status);
	}
	//printf("\ntime : %d, DATA : %s", t, indata);
	//AES_ctr128_encrypt(indata, outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
	//MPI_File_write_at(writeFile, (rank)*(times-t)*AES_BLOCK_SIZE, indata, (AES_BLOCK_SIZE), MPI_CHAR, &status);
	*/
	MPI_File_close(&writeFile);
	MPI_File_close(&readFile);
}
int main(int argc, char **argv){
	FILE *fp = fopen("lorem.txt", "r");
	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	fclose(fp);
	fencrypt((unsigned const char*)"1234567812345678");
	
	fp = fopen("loremenc.txt", "r");
	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	printf("Size of enc : %d\n", sz);
	fclose(fp);
	printf("Read Encoded File\n");
	fdecrypt((unsigned const char*)"1234567812345678");
	
	printf("\n");
	MPI_Finalize();
	return 0;
}
