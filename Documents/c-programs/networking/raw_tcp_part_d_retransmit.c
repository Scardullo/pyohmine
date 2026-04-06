/*
 raw_tcp_part_d_retransmit.c
 Part D: TCP with retransmission + RTT estimation

 Build:
   gcc raw_tcp_part_d_retransmit.c -o raw_tcp_part_d

 Run:
   sudo ./raw_tcp_part_d eth0 <dst_ip> <dst_port>
*/

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
#define MSS 1200


uint64_t now_ms(){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return (uint64_t)ts.tv_sec*1000 + ts.tv_nsec/1000000;
}


uint16_t checksum(void *d,int l){
    uint32_t s=0; uint16_t *p=d;
    while(l>1){ s+=*p++; if(s&0x80000000) s=(s&0xffff)+(s>>16); l-=2; }
    if(l) s+=*(uint8_t*)p;
    while(s>>16) s=(s&0xffff)+(s>>16);
    return ~s;
}


uint16_t tcp_checksum(struct iphdr *ip,struct tcphdr *t,uint8_t *pl,int pln){
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

// arp

struct arp_pkt{
    uint16_t h,p; uint8_t hl,pl; uint16_t op;
    uint8_t sha[6],spa[4],tha[6],tpa[4];
}__attribute__((packed));

void arp(int s,int ifi,uint8_t mm[6],char *mi,char *ti,uint8_t dm[6]){
    uint8_t b[60]={0};
    struct ethhdr *e=(struct ethhdr*)b; struct arp_pkt *a=(struct arp_pkt*)(b+14);
    memset(e->h_dest,0xff,6); memcpy(e->h_source,mm,6); e->h_proto=htons(ETH_P_ARP);
    a->h=htons(1); a->p=htons(ETH_P_IP); a->hl=6; a->pl=4; a->op=htons(1);
    memcpy(a->sha,mm,6); inet_pton(AF_INET,mi,a->spa); inet_pton(AF_INET,ti,a->tpa);
    struct sockaddr_ll sa={.sll_family=AF_PACKET,.sll_ifindex=ifi,.sll_halen=6};
    memset(sa.sll_addr,0xff,6); sendto(s,b,42,0,(struct sockaddr*)&sa,sizeof(sa));
    while(1){
        recv(s,b,sizeof(b),0); struct ethhdr *re=(void*)b;
        if(ntohs(re->h_proto)!=ETH_P_ARP) continue;
        struct arp_pkt *ra=(void*)(b+14);
        if(ntohs(ra->op)==2 && !memcmp(ra->spa,a->tpa,4)){
            memcpy(dm,ra->sha,6); return;
        }
    }
}

// tcp

void send_tcp(int s,struct sockaddr_ll *sa,uint8_t *mm,uint8_t *dm,
              char *mi,char *di,uint16_t sp,uint16_t dp,
              uint32_t seq,uint32_t ack,uint8_t fl,uint8_t *pl,int plen){

    uint8_t b[BUF_SIZE]={0};
    
    struct ethhdr *e=(void*)b; 
    struct iphdr *ip=(void*)(b+14);
    struct tcphdr *t=(void*)(b+14+sizeof(*ip));

    memcpy(e->h_dest,dm,6); memcpy(e->h_source,mm,6); e->h_proto=htons(ETH_P_IP);
    ip->ihl=5; ip->version=4; ip->ttl=64; ip->protocol=IPPROTO_TCP;
    ip->saddr=inet_addr(mi); ip->daddr=inet_addr(di);

    t->source=htons(sp); t->dest=htons(dp);
    t->seq=htonl(seq); t->ack_seq=htonl(ack);
    t->doff=5; t->window=htons(64240);
    t->fin=fl&TH_FIN; t->syn=fl&TH_SYN; t->rst=fl&TH_RST; t->psh=fl&TH_PUSH; t->ack=fl&TH_ACK;

    if(plen) memcpy(b+14+sizeof(*ip)+sizeof(*t),pl,plen);

    ip->tot_len=htons(sizeof(*ip)+sizeof(*t)+plen);
    ip->check=checksum(ip,sizeof(*ip));
    t->check=tcp_checksum(ip,t,b+14+sizeof(*ip)+sizeof(*t),plen);

    sendto(s,b,14+sizeof(*ip)+sizeof(*t)+plen,0,(void*)sa,sizeof(*sa));
}

// main

int main(int c,char **v){
    if(c<4){printf("use: %s <iface> <dst_ip> <dst_port>\n",v[0]);return 1;}

    srand(time(NULL));
    uint32_t snd=rand(), rcv=0;
    double srtt=300, rto=500;   // ms

    char *ifn=v[1], *dip=v[2]; int dport=atoi(v[3]);

    int s=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    struct ifreq r={0}; strncpy(r.ifr_name,ifn,IFNAMSIZ-1); ioctl(s,SIOCGIFINDEX,&r);

    uint8_t mm[6],dm[6]; char mi[32];
    get_mac(ifn,mm); get_ip(ifn,mi);
    arp(s,r.ifr_ifindex,mm,mi,dip,dm);

    struct sockaddr_ll sa={.sll_family=AF_PACKET,.sll_ifindex=r.ifr_ifindex,.sll_halen=6};
    memcpy(sa.sll_addr,dm,6);

    uint16_t sport=rand()%50000+10000;

    // handshake
    send_tcp(s,&sa,mm,dm,mi,dip,sport,dport,snd,0,TH_SYN,NULL,0); snd++;

    uint8_t b[BUF_SIZE];

    while(1){
        recv(s,b,sizeof(b),0); struct iphdr *ip=(void*)(b+14);
        if(ip->protocol!=IPPROTO_TCP) continue;
        struct tcphdr *t=(void*)(b+14+ip->ihl*4);
        if(ntohs(t->dest)!=sport) continue;
        if(t->syn&&t->ack){ rcv=ntohl(t->seq)+1; break; }
    }

    send_tcp(s,&sa,mm,dm,mi,dip,sport,dport,snd,rcv,TH_ACK,NULL,0);

    // data w/ retransmission
    char msg[]="GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n";
    int len=strlen(msg);

    uint64_t sent_time=0;
resend:
    printf("[>] Sending data (rto=%.0f ms)\n",rto);
    send_tcp(s,&sa,mm,dm,mi,dip,sport,dport,snd,rcv,TH_ACK|TH_PUSH,(uint8_t*)msg,len);
    sent_time=now_ms();

    while(1){
        fd_set f; FD_ZERO(&f); FD_SET(s,&f);
        struct timeval tv={.tv_sec=(int)(rto/1000),.tv_usec=(int)((int)rto%1000)*1000};

        int rv=select(s+1,&f,NULL,NULL,&tv);
        if(rv==0){ printf("[!] Timeout, retransmitting\n"); goto resend; }

        int n=recv(s,b,sizeof(b),0);
        struct iphdr *ip=(void*)(b+14);
        if(ip->protocol!=IPPROTO_TCP) continue;
        struct tcphdr *t=(void*)(b+14+ip->ihl*4);
        if(ntohs(t->dest)!=sport) continue;

        if(t->ack && ntohl(t->ack_seq)>=snd+len){
            double rtt=now_ms()-sent_time;
            srtt=0.875*srtt + 0.125*rtt;
            rto=srtt*2;
            printf("[+] ACK received RTT=%.0f ms\n",rtt);
            snd+=len;
            break;
        }
    }

    printf("[+] Reliable send complete\n");
    close(s);
}
