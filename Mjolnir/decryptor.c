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
double wtime; 
int rank, size, bufsize, nints, bytes_read, bytes_written;	 
unsigned char indata[AES_BLOCK_SIZE]; 
unsigned char outdata[AES_BLOCK_SIZE];
unsigned char iv[AES_BLOCK_SIZE];
struct ctr_state state;	 
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
int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{		 
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);
	memset(state->ivec + 8, 0, 8);
	memcpy(state->ivec, iv, 8);
}
void fdecrypt(char* read, char* iv, char* write, const unsigned char* enc_key)
{	
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
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
	{
		fprintf(stderr, "Could not set decryption key.");
		exit(1);
	}
	if(!rank)
	{
		timestamp();
		wtime = MPI_Wtime ();
	}
	init_ctr(&state, iv);
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
void congregate(int size)
{
	char source[9];
	FILE *f = fopen("decrypted.txt", "w+");
	FILE *in;
	int i = 0;
	for (i = 0; i < size; ++i)
	{
		sprintf(source, "decr%d.txt", i);
		in = fopen(source, "r");
		while(1) 	
		{
			bytes_read = fread(indata, 1, AES_BLOCK_SIZE, in);
			bytes_written = fwrite(indata, 1, bytes_read, f); 
			if (bytes_read < AES_BLOCK_SIZE) 
			{
				break;
			}
		}
	}
}
int main(int argc, char *argv[])
{
	MPI_Init(NULL,NULL);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	if(!rank) printf("Decryption initiated.\n");
	char blockname[11], ivname[7], destination[9], rankChar[1];
	int i = 0;
	rankChar[0] = (char)(((int)'0')+rank);
	sprintf(blockname, "block%d.txt", rank);
	sprintf(ivname, "iv%d.txt", rank);
	sprintf(destination, "decr%d.txt", rank);
	fdecrypt(blockname,ivname,destination, (unsigned const char*)"1234567812345678");
	if (!rank)
	{
		if(!rank) printf("Done.\n");
		wtime = MPI_Wtime () - wtime;
		printf("Congregating...\n");
		congregate(size);
		printf("Decryption took %f seconds.\n", wtime);
	}
	MPI_Finalize();
	return 0;
}