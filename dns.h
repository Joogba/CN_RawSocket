#include <unistd.h>
#include <stdbool.h>
#include <string.h>

typedef struct dns_header { 
    unsigned short id;       // identification number 
    unsigned char rd :1;     // recursion desired 
    unsigned char tc :1;     // truncated message 
    unsigned char aa :1;     // authoritive answer 
    unsigned char opcode :4; // purpose of message 
    unsigned char qr :1;     // query/response flag 
    unsigned char rcode :4;  // response code 
    unsigned char cd :1;     // checking disabled 
    unsigned char ad :1;     // authenticated data 
    unsigned char z :1;      // its z! reserved 
    unsigned char ra :1;     // recursion available 
    unsigned short q_count;  // number of question entries
    unsigned short ans_count; // number of answer entries 
    unsigned short auth_count; // number of authority entries 
    unsigned short add_count; // number of resource entries
} DnsHeader;

typedef struct rdata
{
    unsigned short type;
    unsigned short recordClass;
    unsigned short TTL;
    unsigned short data_len;

} RData;


typedef struct dns_question {
    unsigned short qtype;
    unsigned short qclass;
} DnsQuestion;

typedef struct res_record {
    unsigned char * name;
    RData *resource;
    unsigned char *rdata;
}ResRecord;


typedef struct {

} DnsRes;

typedef struct {
    unsigned *name;
    DnsQuestion *ques;
} DnsQry;


u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}