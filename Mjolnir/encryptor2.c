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
double wtime;	 
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
	pointer = malloc(length);
	if (pointer == NULL)
	{
		printf("Unable to allocate memory.\n");
		exit(EXIT_FAILURE);
	}
	for (c = 0 ; c < position ; c++) 
		string++; 
	for (c = 0 ; c < length ; c++)
	{
		*(pointer+c) = *string;      
		string++;   
	}
	return pointer;
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
	char fname[7];
	sprintf(fname, "iv%d.txt", rank);
	FILE *wFile = fopen(fname,"w");
	fwrite(iv, 1, 8, wFile); // IV bytes 1 - 8
    fwrite("\0\0\0\0\0\0\0\0", 1, 8, wFile); // Fill the last 4 with null bytes 9 - 16
    // printf("IV Write Done : %s\n", iv);
    fclose(wFile);
}
void timestamp(void)
{
# define TIME_SIZE 40

	static char time_buffer[TIME_SIZE];
	const struct tm *tm;
	size_t len;
	time_t now;

	now = time ( NULL );
	tm = localtime ( &now );

	len = strftime ( time_buffer, TIME_SIZE, "%d %B %Y %I:%M:%S %p", tm );

	printf ( "MPI Job Started at %s\n", time_buffer );

	return;
# undef TIME_SIZE
}
int sz;
void fencrypt(char* read, const unsigned char* enc_key)
{ 
	FILE *fp = fopen(read, "r+");
	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	MPI_Init(NULL,NULL);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	if(!rank) timestamp();
	if ((sz)%AES_BLOCK_SIZE)
	{
		printf("Size not a multiple of AES_BLOCK_SIZE\n");
		int blocks = (sz)/AES_BLOCK_SIZE;
		printf("Existing blocks : %d\n", blocks);
		int bytes_to_be_written = ((blocks+1)*AES_BLOCK_SIZE)-(sz);
		printf("Number of 128bit blocks : %d, bytes to be written : %d\n", blocks, bytes_to_be_written);
		fseek(fp, sz, SEEK_SET);
		int extra_bytes = (size - 1)*AES_BLOCK_SIZE;
		bytes_to_be_written += extra_bytes;
		sz = sz + bytes_to_be_written;
		while(bytes_to_be_written--)
			fwrite("~",1,1,fp);
	}
	fclose(fp);
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
	{
		fprintf(stderr, "Could not set encryption key.");
		exit(1); 
	}
	
	int i = 0;
	char fname[11];
	sprintf(fname, "block%d.txt", rank);
	//printf("File Name : %s\n", fname);
	fp = fopen(fname,"w+");
	char writeBuffer[(sz/size)];
	MPI_File_open(MPI_COMM_WORLD,read,MPI_MODE_RDONLY,MPI_INFO_NULL,&readFile);
	float blocksize = sz/size;
	if (rank == 0)
	{
		printf("Size of file : %d\n", sz);
	}
	// printf("Blocksize : %f, numblocks : %d\n", blocksize, size);
	init_IV();
	init_ctr(&state, iv);
	int j;
	if (!rank)
	{
		wtime = MPI_Wtime ();
	}
	MPI_File_read_at(readFile,(rank*blocksize),writeBuffer,(blocksize),MPI_CHAR,&status);
	int b = 0;
	for (; b < blocksize; b += AES_BLOCK_SIZE)
	{
		AES_ctr128_encrypt(substring(writeBuffer,b,AES_BLOCK_SIZE), outdata, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
		fwrite(outdata,1,AES_BLOCK_SIZE,fp);
	}
	//printf("For process %d writeBuffer : %s\n", rank,writeBuffer);
	fclose(fp);
	if (!rank)
	{
		wtime = MPI_Wtime () - wtime;
		printf("Encryption took %f seconds.\n", wtime);
	}
	MPI_File_close(&readFile);
}
int main(int argc, char *argv[])
{
	fencrypt(argv[1], (unsigned const char*)"1234567812345678");
	if(!rank) printf("Encrypted.\n");
	MPI_Finalize();
	return 0;
}