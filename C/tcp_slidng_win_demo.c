#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUF_SIZE 65536
#define MSS 1000
#define MAX_INFLIGHT 64

uint64_t now_ms(){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return (uint64_t)ts.tv_sec*1000 + ts.tv_nsec/1000000;
}

uint16_t checksum(void *d, int l){
    uint32_t s=0; uint16_t *p=d;
    while(l>1){ s+=*p++; if(s&0x80000000) s=(s&0xffff)+(s>>16); l-=2; }
    if(l) s+=*(uint8_t*)p;
    while(s>>16) s=(s&0xffff)+(s>>16);
    return ~s;
}

uint16_t tcp_checksum(struct iphdr *ip,struct tcphdr *t,uint8_t *pl, int pln){
    struct{uint32_t s,d;uint8_t z,p;uint16_t l;}ph;
    ph.s=ip->saddr; ph.d=ip->daddr; ph.z=0; ph.p=IPPROTO_TCP;
    ph.l=htons(sizeof(*t)+pln);
    int T=sizeof(ph)+sizeof(*t)+pln;
    uint8_t *b=calloc(1,T);
    memcpy(b,&ph,sizeof(ph)); memcpy(b+sizeof(ph),t,sizeof(*t));
    if(pln) memcpy(b+sizeof(ph)+sizeof(*t),pl,pln);
    uint16_t c=checksum(b,T); free(b); return c;
}

void get_mac(const char *i,uint8_t m[6]){
    int f=socket(AF_INET,SOCK_DGRAM,0); struct ifreq r={0};
    strncpy(r.ifr_name,i,IFNAMSIZ-1); ioctl(f,SIOCGIFHWADDR,&r);
    memcpy(m,r.ifr_hwaddr.sa_data,6); close(f);
}

void get_ip(const char *i,char *b){
    int f=socket(AF_INET,SOCK_DGRAM,0); struct ifreq r={0};
    strncpy(r.ifr_name,i,IFNAMSIZ-1); ioctl(f,SIOCGIFADDR,&r);
    struct sockaddr_in *a=(void*)&r.ifr_addr; strcpy(b,inet_ntoa(a->sin_addr));
    close(f);
}

struct arp_pkt{
    uint16_t h,p; uint8_t hl,pl; uint16_t op;
    uint8_t sha[6],spa[4],tha[6],tpa[4];
}__attribute__((packed));

void arp(int s,int ifi,uint8_t mm[6],char *mi,char *ti,uint8_t dm[6]){
    uint8_t b[60]={0};
    struct ethhdr *e=(void*)b; struct arp_pkt *a=(void*)(b+14);
    memset(e->h_dest,0xff,6); memcpy(e->h_source,mm,6); e->h_proto=htons(ETH_P_ARP);
    a->h=htons(1); a->p=htons(ETH_P_IP); a->hl=6; a->pl=4; a->op=htons(1);
    memcpy(a->sha,mm,6); inet_pton(AF_INET,mi,a->spa); inet_pton(AF_INET,ti,a->tpa);
    struct sockaddr_ll sa={.sll_family=AF_PACKET,.sll_ifindex=ifi,.sll_halen=6};
    memset(sa.sll_addr,0xff,6); sendto(s,b,42,0,(void*)&sa,sizeof(sa));
    while(1){
        recv(s,b,sizeof(b),0); struct ethhdr *re=(void*)b;
        if(ntohs(re->h_proto)!=ETH_P_ARP) continue;
        struct arp_pkt *ra=(void*)(b+14);
        if(ntohs(ra->op)==2 && !memcmp(ra->spa,a->tpa,4)){
            memcpy(dm,ra->sha,6); return;
        }
    }
}


