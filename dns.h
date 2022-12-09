#include <unistd.h>
#include <stdbool.h>
#include <string.h>

typedef struct dns_header { 
    unsigned short id;       // identification number 
    unsigned char rp :1;     // recursion desired 
    unsigned char opcode :4;     // truncated message 
    unsigned char auth :1;     // authoritive answer 
    unsigned char tc :1; // purpose of message 
    unsigned char rd :1;     // query/response flag 
    unsigned char ra :1;  // response code 
    unsigned char z :1;     // checking disabled 
    unsigned char aa :1;     // authenticated data 
    unsigned char nad :1;      // its z! reserved 
    unsigned char rc :4;     // recursion available 
    unsigned short q_count;  // number of question entries
    unsigned short ans_count; // number of answer entries 
    unsigned short auth_count; // number of authority entries 
    unsigned short add_count; // number of resource entries
} DnsHeader;

typedef struct dns_question {
    unsigned short qtype;
    unsigned short qclass;
} DnsQuestion;

typedef struct { // 쿼리 필드 : 이름, 타입, 클래스
    unsigned *name;
    DnsQuestion *ques;
} DnsQry;


typedef struct rdata
{
    unsigned short type;
    unsigned short recordClass;
    unsigned short TTL;
    unsigned short data_len;

} RData;// anser필드에 들어갈결과 데이터 

// answer 결과 
typedef struct res_record {
    unsigned char * name;
    RData *resource;
    unsigned char *rdata;
}ResRecord;





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

void printDnsHeader(DnsHeader * buf, FILE* logfile)
{
    if(logfile ==NULL || buf == NULL)
        return;
    fprintf(logfile ," + Transaction ID       :%u\n",ntohs(buf->id));
    fprintf(logfile ,"   -- flags      \n");
    fprintf(logfile ," | Response 0=qry 1=rst :%d\n",(buf->rp));
    fprintf(logfile ," | Opcode               :%d\n",(buf->opcode));
    fprintf(logfile ," | Authoritative        :%d\n",(buf->auth));
    fprintf(logfile ," | Trucated             :%d\n",(buf->tc));
    fprintf(logfile ," | Recusion Desired     :%d\n",(buf->rd));
    fprintf(logfile ," | Recursion available  :%d\n",(buf->ra));
    fprintf(logfile ," | Z                    :%d\n",(buf->z));
    fprintf(logfile ," | Answer auth          :%d\n",(buf->aa));
    fprintf(logfile ," | Non-auth data        :%d\n",(buf->nad));
    fprintf(logfile ," | Reply Code           :%d\n",(buf->rc));
    fprintf(logfile ,"   ---------      \n");
    fprintf(logfile, " | DnsQuestion          : %u\n", ntohs(buf->q_count));
    fprintf(logfile, " | Answer               : %u\n", ntohs(buf->ans_count));
    fprintf(logfile, " | Authoritative Server : %u\n", ntohl(buf->auth_count));
    fprintf(logfile, " | Additional record    : %u\n", ntohl(buf->add_count));
}