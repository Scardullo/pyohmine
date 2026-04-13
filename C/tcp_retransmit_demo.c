#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUF_SIZE 65536
#define MSS 1200

uint64_t now_ms(){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return (uint64_t)ts.tv_sec*1000 + ts.tv_nsec/1000000;
}

uint64_t checksum(void *d,int l){
    uint32_t s=0; uint16_t *p=d;
    while(l>1){ s+=*p++; if(s&0x80000000) s=(s&0xffff)+(s>>16); l-=2; }
    if(l) s+=*(uint8_t*)p;
    while(s>>16) s=(s&0xffff)+(s>>16);
    return ~s;
}

uint16_t tcp_checksum(struct iphdr *ip, struct tcphdr *t, uint8_t *pl, int pln){
    struct { uint32_t s,d; uint8_t z,p; uint16_t l; }ph;
    ph.s=ip->saddr; ph.d=ip->daddr; ph.z=0; ph.p=IPPROTO_TCP;
    ph.l=htons(sizeof(*t)+pln);
    int T=sizeof(ph)+sizeof(*t)+pln;
    uint8_t *b=calloc(1,T);
    memcpy(b,&ph,sizeof(ph)); memcpy(b+sizeof(ph),t,sizeof(*t));
    if(pln) memcpy(b+sizeof(ph)+sizeof(*t),pl,pln);
    uint16_t c=checksum(b,T); free(b); return c;
}

void get_mac(const char *i, uint8_t m[6]){
    int f=socket(AF_INET,SOCK_DGRAM,0); struct ifreq r={0};
    strncpy(r.ifr_name,i,IFNAMSIZ-1); ioctl(f,SIOCGIFHWADDR,&r);
    memcpy(m,r.ifr_hwaddr.sa_data,6); close(f);
}

void get_ip(const char *i,char *b){
    int f=socket(Af_inet,SOCK_DGRAM,0); struct ifreq r ={0};
    strncpy(r.ifr_name,i,IFNAMSIZ-1); ioctl(f,SIOCGIFADDR,&r);
    struct sockaddr_in *a=(void*)&r.ifr_addr; strcpy(b,inet-ntoa(a->sin_addr));
    close(f);
}



