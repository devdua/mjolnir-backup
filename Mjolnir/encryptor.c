#include <openssl/crypto.h>
#include "modes_lcl.h"
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "mpi.h"
#include <openssl/modes.h>
int rank, size, bufsize, nints, bytes_read, bytes_written;	 
struct ctr_state 
{ 
	unsigned char ivec[AES_BLOCK_SIZE];	 
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
};
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
/*
static void ctr128_inc(unsigned char *counter, int rank) {
	u32 n=16;
	u8  c;

	do {
		--n;
		c = counter[n];
		c = c + rank + size;
		counter[n] = c;
		if (c) return;
	} while (n);
}
void encrypt(const unsigned char *in, 
	unsigned char *out,
	size_t len, const void *key,
	unsigned char ivec[16], unsigned char ecount_buf[16],
	unsigned int *num, block128_f block, int rank)
{
	unsigned int n;
	size_t l=0;//16 bit int = 0L
	assert(in && out && key && ecount_buf && num);
	assert(*num < 16);
	n = *num;
	while (l<len) {
		if (n==0) {
			(*block)(ivec, ecount_buf, key);
			ctr128_inc(ivec,rank);
		}
		out[l] = in[l] ^ ecount_buf[n];
		++l;
		n = (n+size+rank) % 16;
	}
	*num=n;
}*/
static void ctr128_inc(unsigned char *counter, int rank) {
	u32 n=16;
	u8  c;

	do {
		--n;
		c = counter[n];
		c = c + 1;
		counter[n] = c;
		if (c) return;
	} while (n);
}
void encrypt(const unsigned char *in, 
	unsigned char *out,
	size_t len, const void *key,
	unsigned char ivec[16], unsigned char ecount_buf[16],
	unsigned int *num, block128_f block, int rank)
{
	unsigned int n;
	size_t l=0;//16 bit int = 0L
	assert(in && out && key && ecount_buf && num);
	assert(*num < 16);
	n = *num;
	while (l<len) {
		if (n==0) {
			(*block)(ivec, ecount_buf, key);
			ctr128_inc(ivec,rank);
		}
		out[l] = in[l] ^ ecount_buf[n];
		++l;
		n = (n+1) % 16;
	}
	*num=n;
}
MPI_File readFile, writeFile;
AES_KEY key;
MPI_Status status; 
unsigned char indata[AES_BLOCK_SIZE]; 
unsigned char outdata[AES_BLOCK_SIZE];
unsigned char iv[AES_BLOCK_SIZE];
static struct ctr_state state;	 
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
void init_IV()
{
	if(!RAND_bytes(iv, AES_BLOCK_SIZE))
	{
		fprintf(stderr, "Could not create random bytes.");
		exit(1);    
	}
	char fname[7], rankChar[1];
	rankChar[0] = (char)(((int)'0')+rank);
	strcpy(fname, "iv");
	strcat(fname, rankChar);
	strcat(fname, ".txt");
	FILE *wFile = fopen(fname,"w");
	fwrite(iv, 1, 8, wFile); // IV bytes 1 - 8
    fwrite("\0\0\0\0\0\0\0\0", 1, 8, wFile); // Fill the last 4 with null bytes 9 - 16
    printf("IV Write Done : %s\n", iv);
    fclose(wFile);
    // wFile = fopen("iv_slaves.txt","w");
    // fwrite(iv, 1, AES_BLOCK_SIZE, wFile);
    // fclose(wFile);
}
unsigned long int sz;
void fencrypt(char* read, char* write, const unsigned char* enc_key)
{ 
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
	{
		fprintf(stderr, "Could not set encryption key.");
		exit(1); 
	}
	FILE *fp = fopen(read, "r");
	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	fclose(fp);
	MPI_Init(NULL,NULL);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	int i = 0;
	char fname[11], rankChar[1];
	rankChar[0] = (char)(((int)'0')+rank);
	strcpy(fname, "block");
	strcat(fname, rankChar);
	strcat(fname, ".txt");
	printf("File Name : %s\n", fname);
	fp = fopen(fname,"w+");

	char writeBuffer[(sz/size)+1];
	//FILE *src = fopen("lorem.txt", "r");
	//int bytes = fread(writeBuffer,1,buf,src);
	/*if (rank == 0)
	{
		init_IV();
		init_ctr(&state, iv);
		if (size>1)
		{
			for (i = 1; i < size; ++i)
			{
				MPI_Send(&state, 1, MPI_INT, size - i, 0, MPI_COMM_WORLD);
				MPI_Send(&iv, 1, MPI_INT, size - i, 0, MPI_COMM_WORLD);
			}
		}
	}
	else{
		MPI_Recv(&state, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
		MPI_Recv(&iv, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
	}*/
	MPI_File_open(MPI_COMM_WORLD,read,MPI_MODE_RDONLY,MPI_INFO_NULL,&readFile);
	//MPI_File_open(MPI_COMM_WORLD,fname,MPI_MODE_CREATE|MPI_MODE_WRONLY,MPI_INFO_NULL,&writeFile);
	//init_ctr(&state, iv); //Counter call
	float blocksize = sz/size;
	//int numblocks = blocks*AES_BLOCK_SIZE;
	if (rank == 0)
	{
		printf("Size of file : %ld\n", sz);
	}
	printf("Blocksize : %f, numblocks : %d\n", blocksize, size);
	init_IV();
	init_ctr(&state, iv);
	unsigned long int partition = ((sz/AES_BLOCK_SIZE)/size);
	int blockOffset = partition*AES_BLOCK_SIZE;
	//printf("PARTITION SIZE : %d\n", partition);
	int j;
	MPI_File_read_at(readFile,(rank*blocksize),writeBuffer,(blocksize),MPI_CHAR,&status);
	//strcat(writeBuffer,"\0");
	unsigned long int b = 0;
	for (b = 0; b < blocksize; b += AES_BLOCK_SIZE)
	{
	encrypt(substring(writeBuffer,b,AES_BLOCK_SIZE), outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num,(block128_f)AES_encrypt,rank);
	fwrite(outdata,1,AES_BLOCK_SIZE,fp);
	}
	//MPI_File_write_at(writeFile, ((rank)*blocksize), writeBuffer, blocksize, MPI_CHAR, &status);
	printf("For process %d writeBuffer : %s\n", rank,writeBuffer);

	// if(rank != 0)
	// {
	// 	FILE *f = fopen("iv_slaves.txt", "r");
	// 	fread(iv, 1, AES_BLOCK_SIZE, f);
	// 	fclose(f);
	// }
	/*for(i = 0; i < blockOffset; i += AES_BLOCK_SIZE)
	{
		MPI_File_read_at(readFile, ((rank)*blockOffset)+i, indata, AES_BLOCK_SIZE, MPI_CHAR, &status);
		encrypt(indata, outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num,(block128_f)AES_encrypt,rank);
		//printf("ivec : %s, ecount : %s\n", state.ivec, state.ecount);
		MPI_File_write_at(writeFile, ((rank)*blockOffset)+i, outdata, AES_BLOCK_SIZE, MPI_CHAR, &status);
	}*/
	//MPI_File_close(&writeFile);
	MPI_File_close(&readFile);
}/*
void fdecrypt(const unsigned char* enc_key)
{	
	FILE *readFile, *writeFile;
	readFile=fopen("block1.txt","rb"); // The b is required in windows.
	FILE *ivr = fopen("iv1.txt", "r");
	writeFile=fopen("unenced.txt","wb");
	
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
        //printf("%i\n", state.num);
		AES_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);

		bytes_written = fwrite(outdata, 1, bytes_read, writeFile); 
		if (bytes_read < AES_BLOCK_SIZE) 
		{
			break;
		}
	}
	fclose(writeFile); 
	fclose(readFile); 
}*/
int main(int argc, char *argv[])
{
	fencrypt("lorem.txt", "enced.txt", (unsigned const char*)"1234567812345678");
	printf("Encrypted.\n");
	//fdecrypt((unsigned const char*)"1234567812345678");
	printf("Done.\n");
	MPI_Finalize();
	return 0;
}