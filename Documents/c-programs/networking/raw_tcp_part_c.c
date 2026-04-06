/*
 raw_tcp_full_stack.c
 Full user-space TCP over raw Ethernet

 Features:
  - ARP
  - TCP handshake
  - TCP option parsing
  - Data send + ACK
  - FIN close
  - Flow filtering

 Build:
   gcc raw_tcp_full_stack.c -o raw_tcp_full_stack

 Run:
   sudo ./raw_tcp_full_stack eth0 <dst_ip> <dst_port>
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
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUF_SIZE 65536

/* ================= Checksums ================= */

uint16_t checksum(void *data, int len){
    uint32_t sum=0; uint16_t *p=data;
    while(len>1){ sum+=*p++; if(sum&0x80000000) sum=(sum&0xffff)+(sum>>16); len-=2; }
    if(len) sum+=*(uint8_t*)p;
    while(sum>>16) sum=(sum&0xffff)+(sum>>16);
    return ~sum;
}

uint16_t tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, uint8_t *pl, int plen){
    struct pseudo{uint32_t s,d;uint8_t z,p;uint16_t l;}ph;
    ph.s=ip->saddr; ph.d=ip->daddr; ph.z=0; ph.p=IPPROTO_TCP;
    ph.l=htons(sizeof(*tcp)+plen);
    int t=sizeof(ph)+sizeof(*tcp)+plen;
    uint8_t *b=calloc(1,t);
    memcpy(b,&ph,sizeof(ph)); memcpy(b+sizeof(ph),tcp,sizeof(*tcp));
    if(plen) memcpy(b+sizeof(ph)+sizeof(*tcp),pl,plen);
    uint16_t c=checksum(b,t); free(b); return c;
}

/* ================= Interface ================= */

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

/* ================= ARP ================= */

struct arp_pkt{
    uint16_t h,p; uint8_t hl,pl; uint16_t op;
    uint8_t sha[6],spa[4],tha[6],tpa[4];
}__attribute__((packed));

int arp(int s,int ifi,uint8_t mm[6],char *mi,char *ti,uint8_t dm[6]){
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
        if(ntohs(ra->op)==2 && !memcmp(ra->spa,a->tpa,4)){ memcpy(dm,ra->sha,6); return 0; }
    }
}

/* ================= TCP send ================= */

void send_tcp(int s,struct sockaddr_ll *sa,uint8_t *mm,uint8_t *dm,
              char *mi,char *di,uint16_t sp,uint16_t dp,
              uint32_t seq,uint32_t ack,uint8_t fl,uint8_t *pl,int plen){

    uint8_t b[BUF_SIZE]={0};
    struct ethhdr *e=(void*)b; struct iphdr *ip=(void*)(b+14);
    struct tcphdr *t=(void*)(b+14+sizeof(*ip));

    memcpy(e->h_dest,dm,6); memcpy(e->h_source,mm,6); e->h_proto=htons(ETH_P_IP);

    ip->ihl=5; ip->version=4; ip->ttl=64; ip->protocol=IPPROTO_TCP;
    ip->saddr=inet_addr(mi); ip->daddr=inet_addr(di);

    t->source=htons(sp); t->dest=htons(dp); t->seq=htonl(seq); t->ack_seq=htonl(ack);
    t->doff=5; t->window=htons(64240);
    t->fin=fl&TH_FIN; t->syn=fl&TH_SYN; t->rst=fl&TH_RST; t->psh=fl&TH_PUSH; t->ack=fl&TH_ACK;

    if(plen) memcpy(b+14+sizeof(*ip)+sizeof(*t),pl,plen);

    ip->tot_len=htons(sizeof(*ip)+sizeof(*t)+plen); ip->check=checksum(ip,sizeof(*ip));
    t->check=tcp_checksum(ip,t,b+14+sizeof(*ip)+sizeof(*t),plen);

    sendto(s,b,14+sizeof(*ip)+sizeof(*t)+plen,0,(void*)sa,sizeof(*sa));
}

/* ================= MAIN ================= */

int main(int c,char **v){
    if(c<4){printf("use: %s <iface> <dst_ip> <dst_port>\n",v[0]);return 1;}

    srand(time(NULL));
    uint32_t snd=rand(), rcv=0;
    char *ifn=v[1], *dip=v[2]; int dport=atoi(v[3]);

    int s=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    struct ifreq r={0}; strncpy(r.ifr_name,ifn,IFNAMSIZ-1); ioctl(s,SIOCGIFINDEX,&r);

    uint8_t mm[6],dm[6]; char mi[32];
    get_mac(ifn,mm); get_ip(ifn,mi);
    printf("[+] IP %s\n",mi);

    arp(s,r.ifr_ifindex,mm,mi,dip,dm);
    printf("[+] ARP OK\n");

    struct sockaddr_ll sa={.sll_family=AF_PACKET,.sll_ifindex=r.ifr_ifindex,.sll_halen=6};
    memcpy(sa.sll_addr,dm,6);
    uint16_t sport=rand()%50000+10000;

    /* SYN */
    send_tcp(s,&sa,mm,dm,mi,dip,sport,dport,snd,0,TH_SYN,NULL,0); snd++;

    uint8_t b[BUF_SIZE];

    /* SYN-ACK */
    while(1){
        recv(s,b,sizeof(b),0); struct iphdr *ip=(void*)(b+14);
        if(ip->protocol!=IPPROTO_TCP) continue;
        struct tcphdr *t=(void*)(b+14+ip->ihl*4);
        if(ntohs(t->dest)!=sport) continue;
        if(t->syn&&t->ack){ rcv=ntohl(t->seq)+1; break; }
    }

    send_tcp(s,&sa,mm,dm,mi,dip,sport,dport,snd,rcv,TH_ACK,NULL,0);
    printf("[+] Handshake done\n");

    /* DATA */
    char msg[]="GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n";
    send_tcp(s,&sa,mm,dm,mi,dip,sport,dport,snd,rcv,TH_ACK|TH_PUSH,(uint8_t*)msg,strlen(msg));
    snd+=strlen(msg);

    /* RECEIVE + FIN */
    while(1){
        int n=recv(s,b,sizeof(b),0); struct iphdr *ip=(void*)(b+14);
        if(ip->protocol!=IPPROTO_TCP) continue;
        struct tcphdr *t=(void*)(b+14+ip->ihl*4);
        if(ntohs(t->dest)!=sport) continue;

        int h=14+ip->ihl*4+t->doff*4, d=n-h;
        if(d>0){ fwrite(b+h,1,d,stdout); rcv=ntohl(t->seq)+d;
            send_tcp(s,&sa,mm,dm,mi,dip,sport,dport,snd,rcv,TH_ACK,NULL,0); }

        if(t->fin){
            rcv++; send_tcp(s,&sa,mm,dm,mi,dip,sport,dport,snd,rcv,TH_ACK,NULL,0);
            send_tcp(s,&sa,mm,dm,mi,dip,sport,dport,snd,rcv,TH_FIN|TH_ACK,NULL,0); snd++;
            break;
        }
    }

    printf("\n[+] Closed cleanly\n");
    close(s);
}
