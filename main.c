#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include "dns.h"

#define BUFFER_SIZE 65536

FILE *logfile;
int sock_raw;
struct sockaddr_in source, dest;
int myflag = 0;




void ProcessPacket(unsigned char *, int, char *);
void LogIpHeader(unsigned char *, int, char *);
void LogTcpPacket(unsigned char *, int, char *);
void LogUdpPacket(unsigned char *, int, char *);

// data payload데이터를 파싱해서 표시
// 
void LogHttpHeader(unsigned char *, int, char *);
void LogDnsHeader(unsigned char *, int, char *);

void LogData(unsigned char *, int);
void exit_capturing();


bool check_http(unsigned char *buffer);
bool check_udp();



void ProcessPacket(unsigned char *buffer, int size, char *pip_so)
{
    struct iphdr *iph = (struct iphdr*) (buffer + sizeof(struct ethhdr));

    switch (iph->protocol) 
    {
    case 6: // TCP 프로토콜
        if(!myflag){
            LogHttpHeader(buffer, size, pip_so);
            printf("Http 기록 중..\t\n");
        }
        printf("패킷 통과 중..");
        break;
    case 17: // UDP 프로토콜
        if(myflag){
            LogDnsHeader(buffer, size, pip_so);
            printf("dns 기록 중..\t\n");
        }
        printf("패킷 통과 중..");
        break;
    default:
        printf("tcp도 udp 도아님 \n");
    }
}
void LogHttpHeader(unsigned char *buffer, int size, char *pip_so)
{
    // 일단 http 데이터는 가변 길이이기 때문에 0d 0a 가 나올때까지 로깅 계속한다.
    //요청 get post 만 
    // 1. 요청 
    // 2. 헤더
    //응답 
    // 1. 상태
    // 2. 헤더
    // 3. 바디

    unsigned short iphdrlen;
    unsigned short tcphdrlen;
    int i;

    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct tcphdr *tcph = (struct tcphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
    tcphdrlen = header_size;

    if(!check_http(buffer+header_size))
    {
        return;
    }

    if((22!=ntohs(tcph->source))&&(22!=ntohs(tcph->dest))){

        fprintf(logfile, "\n\n- - - - - - - - - - - Http Packet - - - - - - - - - - - - \n");  

        //LogIpHeader(buffer, size, pip_so);

        LogTcpPacket(buffer, size, pip_so);

        i = header_size;
        

        fprintf(logfile, "HTTP Data\n + ");
        for(i = header_size ; i < size ; i++)
        {
            if(buffer[i]>=32 && buffer[i]<=128) 
                fprintf(logfile,"%c",(unsigned char)buffer[i]);
            else if(buffer[i] == 0x0a)
                fprintf(logfile,"\n | ");
            else 
            fprintf(logfile,".");

        }
        fprintf(logfile, "\n +");

        fprintf(logfile, "\nIP Header\n");
        LogData(buffer, iphdrlen);

        fprintf(logfile, "\nTCP Header\n");
        LogData(buffer + iphdrlen, tcph->doff * 4);

        fprintf(logfile, "\nData Payload\n");    
        LogData(buffer + header_size, size - header_size);

        fprintf(logfile, "\n- - - - - - - - - - - - - - - - - - - - - -");
    }
}

void LogDnsHeader(unsigned char *buffer, int size, char *pip_so)
{

    ResRecord answers[20], auth[20], addit[20];
    int i ,j ,s;

    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct udphdr *udph = (struct udphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));

    printf("s %d  , d %d\n", ntohs(udph->source), ntohs(udph->dest));
    if(ntohs(udph->source) != 53 && ntohs(udph->dest) != 53)
    {
        printf("not dns\n");
        return;
    }

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph; // dns 이전까지의 헤더 크기 

    printf("dns read start\n");
    unsigned char* dnsbuf = buffer + header_size;
    DnsHeader *dns  = (DnsHeader*)(dnsbuf);
    unsigned char *qname =(unsigned char*)&dnsbuf[sizeof(DnsHeader)];
    DnsQuestion *qinfo = NULL;
    unsigned char* reader = &dnsbuf[sizeof(DnsHeader) +(strlen((const char*)qname)+1)+sizeof(DnsQuestion)];

    printf("dns read end\n");
    int stop = 0 ;

    fprintf(logfile, "\n\n- - - - - - - - - - - - Dns Packet - - - - - - - - - - - - \n");

    LogUdpPacket(buffer, size, pip_so);


    fprintf(logfile, "\n");
    fprintf(logfile, "Dns Header\n");
    printDnsHeader(dns,logfile);
    

    printf("dns log1\n");
    for(i = 0 ; i<ntohs(dns->ans_count);i++)
    {
        answers[i].name = ReadName(reader,dnsbuf,&stop);
        reader = reader + stop;

        answers[i].resource = (RData*)reader;
        reader = reader + sizeof(RData);
        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
 
            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }
 
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
 
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader,dnsbuf,&stop);
            reader = reader + stop;
        }
    }
    printf("dns log2\n");
     for(i=0;i<ntohs(dns->auth_count);i++)
    {
        auth[i].name=ReadName(reader,dnsbuf,&stop);
        reader+=stop;
 
        auth[i].resource=(RData*)(reader);
        reader+=sizeof(RData);
 
        auth[i].rdata=ReadName(reader,dnsbuf,&stop);
        reader+=stop;
    }
    printf("dns log3\n");
    //read additional
    for(i=0;i<ntohs(dns->add_count);i++)
    {
        addit[i].name=ReadName(reader,dnsbuf,&stop);
        reader+=stop;
 
        addit[i].resource=(RData*)(reader);
        reader+=sizeof(RData);
 
        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            for(j=0;j<ntohs(addit[i].resource->data_len);j++)
            addit[i].rdata[j]=reader[j];
 
            addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
            reader+=ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata=ReadName(reader,dnsbuf,&stop);
            reader+=stop;
        }
    }

 
    printf("dns log4\n");
    //print answers
    
    fprintf(logfile, " | Answer Records       : %d \n" , ntohs(dns->ans_count) );
    for(i=0 ; i < ntohs(dns->ans_count) ; i++)
    {
        fprintf(logfile,"   Name : %s ",answers[i].name);
 
        if( ntohs(answers[i].resource->type) == 1) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            dest.sin_addr.s_addr=(*p); //working without ntohl
            fprintf(logfile,"   has IPv4 address : %s",inet_ntoa(dest.sin_addr));
        }
         
        if(ntohs(answers[i].resource->type)==5) 
        {
            //Canonical name for an alias
            fprintf(logfile,"has alias name : %s",answers[i].rdata);
        }
 
        fprintf(logfile,"\n");
    }
    printf("dns log5\n");
    //print authorities
    fprintf(logfile, " | Authoritive Records  : %d \n" , ntohs(dns->auth_count) );
    for( i=0 ; i < ntohs(dns->auth_count) ; i++)
    {
         
        fprintf(logfile,"   Name : %s ",auth[i].name);
        if(ntohs(auth[i].resource->type)==2)
        {
            fprintf(logfile,"   has nameserver : %s",auth[i].rdata);
        }
        fprintf(logfile,"\n");
    }
    printf("dns log6\n");
    //print additional resource records
    fprintf(logfile," | Additional Records   : %d \n" , ntohs(dns->add_count) );
    for(i=0; i < ntohs(dns->add_count) ; i++)
    {
        fprintf(logfile,"   Name : %s ",addit[i].name);
        if(ntohs(addit[i].resource->type)==1)
        {
            long *p;
            p=(long*)addit[i].rdata;
            dest.sin_addr.s_addr=(*p);
            fprintf(logfile,"   has IPv4 address : %s",inet_ntoa(dest.sin_addr));
        }
        fprintf(logfile,"\n");
    }
    

    printf("dns log7\n");
    fprintf(logfile, " --------- dump -------------------\n");

    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    LogData(buffer, iphdrlen);

    fprintf(logfile, "UDP Header\n");
    LogData(buffer + iphdrlen, sizeof udph);

    fprintf(logfile, "Data Payload\n");
    //문자열 값만큼 줄이면서 포인터 진행
    LogData(buffer + header_size, size - header_size);

    fprintf(logfile, "----------------------------------\n");

}

void LogTcpPacket(unsigned char *buffer, int size, char *pip_so)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct tcphdr *tcph = (struct tcphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
    if((22!=ntohs(tcph->source))&&(22!=ntohs(tcph->dest))){

        LogIpHeader(buffer, size, pip_so);

        fprintf(logfile, "\n");
        fprintf(logfile, "TCP Header\n");
        fprintf(logfile, " + Source Port          : %u\n", ntohs(tcph->source));
        fprintf(logfile, " | Destination Port     : %u\n", ntohs(tcph->dest));
        fprintf(logfile, " | Sequence Number      : %u\n", ntohl(tcph->seq));
        fprintf(logfile, " | Acknowledge Number   : %u\n", ntohl(tcph->ack_seq));
        fprintf(logfile, " | Header Length        : %d BYTES\n", (unsigned int) tcph->doff * 4);
        fprintf(logfile, " | Acknowledgement Flag : %d\n", (unsigned int) tcph->ack);
        fprintf(logfile, " | Finish Flag          : %d\n", (unsigned int) tcph->fin);
        fprintf(logfile, " + Checksum             : %d\n", ntohs(tcph->check));
        fprintf(logfile, "\n");
    }
}
void LogUdpPacket(unsigned char *buffer, int size, char *pip_so) {
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;


    LogIpHeader(buffer, size, pip_so);

    fprintf(logfile, "\nUDP Header\n");
    fprintf(logfile, " + Source Port      : %d\n", ntohs(udph->source));
    fprintf(logfile, " | Destination Port : %d\n", ntohs(udph->dest));
    fprintf(logfile, " | UDP Length       : %d\n", ntohs(udph->len));
    fprintf(logfile, " + UDP Checksum     : %d\n", ntohs(udph->check));
}

void LogIpHeader(unsigned char *buffer, int size, char * pip_so)
{
   unsigned short iphdrlen;

   struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
   iphdrlen = iph->ihl * 4;

   memset(&source, 0, sizeof(source));

   iph->saddr = inet_addr(pip_so);
	source.sin_addr.s_addr = iph->saddr;//ip를 받아온다.

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	fprintf(logfile, " + IP Version          : %d\n", (unsigned int)iph->version);
	fprintf(logfile, " | IP Header Length    : %d Bytes\n", ((unsigned int)(iph->ihl)) * 4);
	fprintf(logfile, " | Type Of Service     : %d\n", (unsigned int)iph->tos);
	fprintf(logfile, " | IP Total Length     : %d  Bytes (FULL SIZE)\n", ntohs(iph->tot_len));
	fprintf(logfile, " | TTL                 : %d\n", (unsigned int)iph->ttl);
	fprintf(logfile, " | Protocol            : %d\n", (unsigned int)iph->protocol);
	fprintf(logfile, " | Checksum            : %d\n", ntohs(iph->check));
	fprintf(logfile, " | Source IP           : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, " + Destination IP      : %s\n", inet_ntoa(dest.sin_addr));
}


void LogData(unsigned char *buffer, int size)
{
    int i, j;
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(buffer[j]>=32 && buffer[j]<=128)
                    fprintf(logfile,"%c",(unsigned char)buffer[j]); //if its a number or alphabet
                
                else fprintf(logfile,"."); //otherwise print a dot
            }
            fprintf(logfile,"\n");
        } 
        
        if(i%16==0) fprintf(logfile,"   ");
        fprintf(logfile," %02X",(unsigned int)buffer[i]);

        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces

                fprintf(logfile,"         ");
            
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(buffer[j]>=32 && buffer[j]<=128) fprintf(logfile,"%c",(unsigned char)buffer[j]);
                else fprintf(logfile,".");
            }
            fprintf(logfile,"\n");
        }
    }
}

int main(int argc, char *argv[])
{
    char ip_source[18];
    char * pip_so = ip_source;
    char num_port[7];
    char * p_port = num_port;

    // ctrl c 받으면 종료 처리
    struct sigaction inter;
    inter.sa_handler = exit_capturing;
    sigemptyset(&inter.sa_mask);
    inter.sa_flags = SA_INTERRUPT;

    if(sigaction(SIGINT, &inter, NULL) < 0)
    {
        perror("sigaction error : ");
        return 0;
    }


    printf("+------ 캡처 프로그램 시작-------+\n");

    strcpy(p_port, argv[1]);
    printf("| 캡처하는 프로토콜 :   %s\n", p_port);

    strcpy(pip_so, argv[2]);
    printf("| 캡처하는   ip:   %s\n", pip_so);

    printf("+--------------------------------+\n");

    socklen_t saddr_size;
    int data_size;
    struct sockaddr saddr;
    struct in_addr in;

    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);

    if (!strcmp(p_port, "http")) {
        logfile = fopen("log_http.txt", "w");
        printf("log_http.txt로 기록을 시작합니다..\n");
        if (logfile == NULL) {
            printf("http 로그파일 생성 실패.\n");
            return 1;
        }
    }
    else if (!strcmp(p_port, "dns")) {
        myflag = 1;
        logfile = fopen("log_dns.txt", "w");
        printf("log_dns.txt로 기록을 시작합니다..\n");
        if (logfile == NULL) {
            printf("dns 로그파일 생성 실패.\n");
            return 1;
        }
    }
    else {
        printf("error \n");
        return 1;
    }
    //AF_INET, SOCK_PACKET으로하면 Layer2 까지 조작 밑에껀 Layer3까지 조작
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        printf("소켓  초기화 실패\n");
        return 1;
    }

    while (1) {
        saddr_size = sizeof saddr;

        data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, &saddr_size);
        if (data_size < 0) {
            printf("리턴값0보다 작은 에러");
            return 1;
        }

        ProcessPacket(buffer, data_size, pip_so);
    }

    close(sock_raw);

    return 0;
}

void exit_capturing()
{
    close(sock_raw);
    printf("\n =-=-= close Raw Socket.=-=-=\n");
    exit(1);

}

bool check_http(unsigned char* p)
{
    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
        return true;
    }
    //GET
    else if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
        return true;
    }
    //POST
    else if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
        return true;
    }
    //PUT
    else if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
        return true;
    }
    //DELETE
    else if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
        return true;
    }
    //HEAD
    else if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
        return true;
    }
    return false;
}