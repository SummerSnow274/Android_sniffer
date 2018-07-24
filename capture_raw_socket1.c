//learn from other net friends
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <signal.h>
#define oops(msg){perror(msg);exit(0);}
int set_promisc(char *interface,int sockfd);
int open_raw_socket();
void ethop(char*);
void ipop(char*);
void tcpop(char*);
void udpop(char*);
void icmpop(char*);
void printresult(void);
int tcp_count=0,udp_count=0,ip_count=0,arp_count=0,icmp_count=0,unkonw_count=0;
int main(int ac,char**av)
{
    if(ac!=2)
	oops("usage:interface name");
    int sockfd=open_raw_socket();
    set_promisc(av[1],sockfd);
    char buffer[2048];
    char *data;
    int i=0;
    signal(SIGINT,printresult);
    while(1)
    {
	int n=recvfrom(sockfd,buffer,sizeof(buffer),0,NULL,NULL);
	if(n<42)
	{
	    printf("incomplete packete \n");
	    continue;
	}
	printf("----------------------------------------------------------------------------------------------------------------------------------\n");
	ethop(buffer);
	data=(char*)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr));
	printf("data is %s\n",data);
    }
}
void printresult(void)
{
    printf("IP=%d arp=%d unkonw=%d\n",ip_count,arp_count,unkonw_count);
    printf("tcp=%d,udp=%d,icmp=%d\n",tcp_count,udp_count,icmp_count);
    tcp_count=0,udp_count=0,ip_count=0,arp_count=0,icmp_count=0,unkonw_count=0;
    exit(0);
    
}
int set_promisc(char *interface ,int sockfd)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name,interface,strlen(interface)+1);
    if((ioctl(sockfd,SIOCGIFFLAGS,&ifr))<0)
	oops("ioctl get");
 
    ifr.ifr_flags|=IFF_PROMISC;
 
    if((ioctl(sockfd,SIOCSIFFLAGS,&ifr))<0)
	oops("ioctl save");
    printf("set promisc scueess\n");
}
int open_raw_socket()
{
    int sockfd;
    if((sockfd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP)))<0)
	oops("socket create");
    return sockfd;
}
 
void ethop(char *buffer)
{
        struct ethhdr *eth;
	int i=0;
        eth=(struct ethhdr*)buffer;
    	printf("Sourc Mac:");
	for(i=0;i<6;i++)
	    printf("%x ",eth->h_source[i]);
	printf("\nDest Mac:");
	for(i=0;i<6;i++)
	    printf("%x ",eth->h_dest[i]);
	printf("\neth type:");
	short type=ntohs(eth->h_proto);
	switch(type)
	{
	    case 0x0800:
		printf("type is ip packet\n");
		ip_count++;
		ipop(buffer+sizeof(struct ethhdr));
		break;
	    case 0x0806:
		arp_count++;
		printf("type is arp packet\n");
		break;
	    default:
		unkonw_count++;
		printf("unkonw type\n");
		break;
	}
}	
	
void ipop(char *buffer)
{
        struct iphdr*ip=(struct iphdr*)buffer;
	struct in_addr addr;
	addr.s_addr=ip->saddr;
	printf("---------ip source :%s\n",inet_ntoa(addr));
	addr.s_addr=ip->daddr;
	printf("---------ip dest : %s\n",inet_ntoa(addr));
	int type=ip->protocol;
	switch(type)
	{
	    case 1:
		printf("---------ip type is ICMP packet\n");
		icmp_count++;
		icmpop(buffer+sizeof(struct iphdr));
		break;
	    case 6:
		printf("---------ip type is TCP packet\n");
		tcpop(buffer+sizeof(struct iphdr));
		tcp_count++;
		break;
	    case 17:
		printf("---------ip type is UDP packet\n");
		udpop(buffer+sizeof(struct iphdr));
		udp_count++;
		break;
	    default:
		printf("---------unkown ip type\n");
		break;
	}
}
void tcpop(char*buffer)
{
    	struct tcphdr *tcp=(struct tcphdr*)buffer;
	printf("-------------------------------tcp source port %d\n",ntohs(tcp->source));
	printf("-------------------------------tcp dest port %d\n",ntohs(tcp->dest));
}
void udpop(char*buffer)
{
    	struct udphdr *udp=(struct udphdr*)buffer;
	printf("-------------------------------udp source port%d\n",ntohs(udp->source));
	printf("-------------------------------udp dest port %d\n",ntohs(udp->dest));
}
void icmpop(char*buffer)
{
    struct icmphdr*icmp=(struct icmphdr*)buffer;
    int type=icmp->type;
    switch(type)
    {
	case 0:
	    printf("--------------------------------icmp type is request\n");
	    break;
	case 8:
	    printf("--------------------------------icmp type is reply\n");
	    break;
	case 11:
	    printf("---------------------------------icmp type is time-out\n");
	    break;
	default:
	    printf("---------------------------------unkonw icmp type\n");
	    break;
    }
}
