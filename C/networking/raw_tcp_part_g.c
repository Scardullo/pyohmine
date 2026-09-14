/*
 raw_tcp_part_g_advanced.c

 Part G: Advanced User-Space TCP Stack (builds on Part F)

 Part F already merged retransmission + sliding window + full duplex
 into one connection struct. This part takes it further with the
 mechanisms real TCP stacks add on top of that baseline:

   - Flow control   : honor the PEER's advertised receive window,
                       not just our own congestion window (cwnd).
   - Fast retransmit : on 3 duplicate ACKs, resend immediately
                       instead of waiting out a full RTO timeout,
                       and recover via halved cwnd (Reno-style)
                       instead of collapsing back to slow start.
   - Karn's algorithm: never sample RTT from a retransmitted
                       segment - you can't tell which copy the ACK
                       is actually for, so the sample would lie.
   - RTO backoff     : each consecutive timeout doubles the retransmit
                       timer (capped), instead of retrying at a fixed
                       interval forever.
   - Graceful close  : a real 4-way FIN/ACK teardown with FIN_WAIT_1,
                       FIN_WAIT_2, CLOSING, TIME_WAIT, CLOSE_WAIT and
                       LAST_ACK, instead of one abrupt FIN at exit.
   - True full duplex: select() watches stdin AND the socket at once,
                       so you can type a line and have it queued for
                       send while replies are still streaming in.

 Build:
   gcc raw_tcp_part_g_advanced.c -o raw_tcp_part_g

 Run:
   sudo ./raw_tcp_part_g eth0 <dst_ip> <dst_port>

 Type lines to send them to the peer. Type /quit to close gracefully.
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

#define SEND_BUFFER_SIZE 128
#define RECV_BUFFER_SIZE 128

#define MAX_RTO_MS 30000
#define MSL_MS 2000   // real TCP uses ~2 min; shortened here so the demo actually finishes


enum tcp_state{
    ST_CLOSED,
    ST_SYN_SENT,
    ST_ESTABLISHED,
    ST_CLOSE_WAIT,
    ST_LAST_ACK,
    ST_FIN_WAIT_1,
    ST_FIN_WAIT_2,
    ST_CLOSING,
    ST_TIME_WAIT
};


const char *state_name(enum tcp_state s){
    switch(s){
        case ST_CLOSED:      return "CLOSED";
        case ST_SYN_SENT:    return "SYN_SENT";
        case ST_ESTABLISHED: return "ESTABLISHED";
        case ST_CLOSE_WAIT:  return "CLOSE_WAIT";
        case ST_LAST_ACK:    return "LAST_ACK";
        case ST_FIN_WAIT_1:  return "FIN_WAIT_1";
        case ST_FIN_WAIT_2:  return "FIN_WAIT_2";
        case ST_CLOSING:     return "CLOSING";
        case ST_TIME_WAIT:   return "TIME_WAIT";
    }
    return "?";
}


struct tcp_segment{
    uint32_t seq;
    uint16_t len;
    uint8_t data[MSS];

    uint64_t t;

    int sent;
    int acked;
    int retx;      // retransmit count - if >0, Karn's algorithm skips this segment's RTT sample
};


struct recv_segment{
    uint32_t seq;
    uint16_t len;
    uint8_t data[MSS];
};


struct tcp_connection{
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;

    uint32_t fin_seq;       // seq number our FIN consumed, once sent
    uint64_t time_wait_at;  // when we entered TIME_WAIT

    uint16_t snd_wnd;       // peer's advertised receive window (bytes)

    double cwnd;
    double ssthresh;

    double srtt;
    double rto;             // estimator-derived base RTO
    double rto_backoff;     // current (possibly doubled) RTO in effect
    int timeouts;           // consecutive timeouts with no forward progress

    int dup_ack;

    enum tcp_state state;

    struct tcp_segment sendbuf[SEND_BUFFER_SIZE];
    int send_count;

    struct recv_segment recvbuf[RECV_BUFFER_SIZE];
    int recv_count;
};


void set_state(struct tcp_connection *c,enum tcp_state s){
    printf("[state] %s -> %s\n",state_name(c->state),state_name(s));
    c->state=s;
}


// time

uint64_t now_ms(){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC,&ts);
    return (uint64_t)ts.tv_sec*1000 + ts.tv_nsec/1000000;
}


// checksum

uint16_t checksum(void *d,int l){
    uint32_t s=0;
    uint16_t *p=d;

    while(l>1){
        s+=*p++;
        if(s&0x80000000) s=(s&0xffff)+(s>>16);
        l-=2;
    }
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

    memcpy(b,&ph,sizeof(ph));
    memcpy(b+sizeof(ph),t,sizeof(*t));
    if(pln) memcpy(b+sizeof(ph)+sizeof(*t),pl,pln);

    uint16_t c=checksum(b,T);
    free(b);
    return c;
}


// interface

void get_mac(const char *i,uint8_t m[6]){
    int f=socket(AF_INET,SOCK_DGRAM,0);
    struct ifreq r={0};
    strncpy(r.ifr_name,i,IFNAMSIZ-1);
    ioctl(f,SIOCGIFHWADDR,&r);
    memcpy(m,r.ifr_hwaddr.sa_data,6);
    close(f);
}


void get_ip(const char *i,char *b){
    int f=socket(AF_INET,SOCK_DGRAM,0);
    struct ifreq r={0};
    strncpy(r.ifr_name,i,IFNAMSIZ-1);
    ioctl(f,SIOCGIFADDR,&r);
    struct sockaddr_in *a=(void*)&r.ifr_addr;
    strcpy(b,inet_ntoa(a->sin_addr));
    close(f);
}


// arp

struct arp_pkt{
    uint16_t h,p;
    uint8_t hl,pl;
    uint16_t op;
    uint8_t sha[6],spa[4];
    uint8_t tha[6],tpa[4];
}__attribute__((packed));


void arp(int s,int ifi,uint8_t mm[6],char *mi,char *ti,uint8_t dm[6]){
    uint8_t b[60]={0};

    struct ethhdr *e=(void*)b;
    struct arp_pkt *a=(void*)(b+14);

    memset(e->h_dest,0xff,6);
    memcpy(e->h_source,mm,6);
    e->h_proto=htons(ETH_P_ARP);

    a->h=htons(1); a->p=htons(ETH_P_IP); a->hl=6; a->pl=4; a->op=htons(1);
    memcpy(a->sha,mm,6);
    inet_pton(AF_INET,mi,a->spa);
    inet_pton(AF_INET,ti,a->tpa);

    struct sockaddr_ll sa={.sll_family=AF_PACKET,.sll_ifindex=ifi,.sll_halen=6};
    memset(sa.sll_addr,0xff,6);
    sendto(s,b,42,0,(void*)&sa,sizeof(sa));

    while(1){
        recv(s,b,sizeof(b),0);
        struct ethhdr *re=(void*)b;
        if(ntohs(re->h_proto)!=ETH_P_ARP) continue;

        struct arp_pkt *ra=(void*)(b+14);
        if(ntohs(ra->op)==2 && !memcmp(ra->spa,a->tpa,4)){
            memcpy(dm,ra->sha,6);
            return;
        }
    }
}


// tcp packet builder

void send_tcp(int s,struct sockaddr_ll *sa,uint8_t *mm,uint8_t *dm,
              char *mi,char *di,uint16_t sp,uint16_t dp,
              uint32_t seq,uint32_t ack,uint16_t win,uint8_t fl,
              uint8_t *pl,int plen){

    uint8_t b[BUF_SIZE]={0};

    struct ethhdr *e=(void*)b;
    struct iphdr *ip=(void*)(b+14);
    struct tcphdr *t=(void*)(b+14+sizeof(*ip));

    memcpy(e->h_dest,dm,6);
    memcpy(e->h_source,mm,6);
    e->h_proto=htons(ETH_P_IP);

    ip->ihl=5; ip->version=4; ip->ttl=64; ip->protocol=IPPROTO_TCP;
    ip->saddr=inet_addr(mi); ip->daddr=inet_addr(di);

    t->source=htons(sp); t->dest=htons(dp);
    t->seq=htonl(seq); t->ack_seq=htonl(ack);
    t->doff=5; t->window=htons(win);
    t->fin=fl&TH_FIN; t->syn=fl&TH_SYN; t->rst=fl&TH_RST;
    t->psh=fl&TH_PUSH; t->ack=fl&TH_ACK;

    if(pl) memcpy(b+14+sizeof(*ip)+sizeof(*t),pl,plen);

    ip->tot_len=htons(sizeof(*ip)+sizeof(*t)+plen);
    ip->check=checksum(ip,sizeof(*ip));
    t->check=tcp_checksum(ip,t,b+14+sizeof(*ip)+sizeof(*t),plen);

    sendto(s,b,14+sizeof(*ip)+sizeof(*t)+plen,0,(void*)sa,sizeof(*sa));
}


// send buffer

void queue_segment(struct tcp_connection *c,uint32_t seq,uint8_t *data,int len){
    if(c->send_count>=SEND_BUFFER_SIZE) return;

    struct tcp_segment *p=&c->sendbuf[c->send_count];
    p->seq=seq; p->len=len;
    memcpy(p->data,data,len);
    p->t=0; p->sent=0; p->acked=0; p->retx=0;

    c->send_count++;
}


void remove_acked(struct tcp_connection *c){
    while(c->send_count>0 && c->sendbuf[0].acked){
        memmove(&c->sendbuf[0],&c->sendbuf[1],sizeof(c->sendbuf[0])*(c->send_count-1));
        c->send_count--;
    }
}


// send packets allowed by both congestion window AND peer's advertised window

void send_window(struct tcp_connection *c,
                 int s,struct sockaddr_ll *sa,
                 uint8_t *mm,uint8_t *dm,
                 char *mi,char *di,
                 uint16_t sp,uint16_t dp){

    int inflight=0;
    for(int i=0;i<c->send_count;i++)
        if(c->sendbuf[i].sent && !c->sendbuf[i].acked) inflight++;

    // flow control: don't send more segments than the peer's window can hold
    int wnd_segs = c->snd_wnd>0 ? c->snd_wnd/MSS : 1;
    if(wnd_segs<1) wnd_segs=1;

    int allowed=(int)c->cwnd;
    if(wnd_segs<allowed) allowed=wnd_segs;

    for(int i=0;i<c->send_count;i++){
        struct tcp_segment *p=&c->sendbuf[i];
        if(p->sent) continue;
        if(inflight>=allowed) break;

        send_tcp(s,sa,mm,dm,mi,di,sp,dp,
                 p->seq,c->rcv_nxt,65535,
                 TH_ACK|TH_PUSH,p->data,p->len);

        p->t=now_ms();
        p->sent=1;
        inflight++;
    }
}


// process ACK: new data acked, or duplicate ack (-> fast retransmit)

void fast_retransmit(struct tcp_connection *c,
                     int s,struct sockaddr_ll *sa,
                     uint8_t *mm,uint8_t *dm,
                     char *mi,char *di,
                     uint16_t sp,uint16_t dp){

    if(c->send_count==0) return;

    struct tcp_segment *p=&c->sendbuf[0];
    printf("[!] fast retransmit seq=%u (3 dup acks)\n",p->seq);

    send_tcp(s,sa,mm,dm,mi,di,sp,dp,
             p->seq,c->rcv_nxt,65535,
             TH_ACK|TH_PUSH,p->data,p->len);

    p->t=now_ms();
    p->retx++;   // Karn's algorithm: this copy's RTT can no longer be trusted

    // Reno-style fast recovery: halve, don't collapse to slow start
    c->ssthresh = c->cwnd/2;
    if(c->ssthresh<2) c->ssthresh=2;
    c->cwnd = c->ssthresh;
}


void process_ack(struct tcp_connection *c,uint32_t ack,
                 int s,struct sockaddr_ll *sa,
                 uint8_t *mm,uint8_t *dm,
                 char *mi,char *di,
                 uint16_t sp,uint16_t dp){

    if(ack==c->snd_una){
        if(c->send_count>0){
            c->dup_ack++;
            if(c->dup_ack==3){
                fast_retransmit(c,s,sa,mm,dm,mi,di,sp,dp);
                c->dup_ack=0;
            }
        }
        return;
    }

    int moved=0;

    for(int i=0;i<c->send_count;i++){
        struct tcp_segment *p=&c->sendbuf[i];

        if(!p->acked && ack>=p->seq+p->len){
            if(p->retx==0){   // Karn's algorithm: only sample RTT on first-transmit segments
                uint64_t rtt=now_ms()-p->t;
                c->srtt=0.875*c->srtt+0.125*rtt;
                c->rto=c->srtt*2;
            }
            p->acked=1;
            moved=1;
        }
    }

    if(moved){
        c->dup_ack=0;
        c->timeouts=0;
        c->rto_backoff=c->rto;   // fresh progress clears any RTO backoff

        remove_acked(c);

        if(c->cwnd<c->ssthresh) c->cwnd++;
        else c->cwnd+=1.0/c->cwnd;
    }

    c->snd_una=ack;
}


// retransmission timer, with exponential backoff on repeated timeouts

void check_retransmit(struct tcp_connection *c,
                      int s,struct sockaddr_ll *sa,
                      uint8_t *mm,uint8_t *dm,
                      char *mi,char *di,
                      uint16_t sp,uint16_t dp){

    for(int i=0;i<c->send_count;i++){
        struct tcp_segment *p=&c->sendbuf[i];
        if(!p->sent || p->acked) continue;

        if(now_ms()-p->t > c->rto_backoff){
            printf("[!] timeout retransmit seq=%u (rto=%.0fms)\n",p->seq,c->rto_backoff);

            send_tcp(s,sa,mm,dm,mi,di,sp,dp,
                     p->seq,c->rcv_nxt,65535,
                     TH_ACK|TH_PUSH,p->data,p->len);

            p->t=now_ms();
            p->retx++;

            c->timeouts++;
            double backoff = c->rto * (1<<(c->timeouts>6?6:c->timeouts));
            c->rto_backoff = backoff>MAX_RTO_MS ? MAX_RTO_MS : backoff;

            c->ssthresh=c->cwnd/2;
            if(c->ssthresh<2) c->ssthresh=2;
            c->cwnd=1;
        }
    }
}


// application send

void tcp_send_data(struct tcp_connection *c,uint8_t *data,int len){
    int off=0;
    while(off<len){
        int n=len-off>MSS ? MSS : len-off;
        queue_segment(c,c->snd_nxt,data+off,n);
        c->snd_nxt+=n;
        off+=n;
    }
}


// receive buffer (out-of-order reassembly)

void store_recv(struct tcp_connection *c,uint32_t seq,uint8_t *data,int len){
    if(c->recv_count>=RECV_BUFFER_SIZE) return;

    struct recv_segment *p=&c->recvbuf[c->recv_count];
    p->seq=seq; p->len=len;
    memcpy(p->data,data,len);
    c->recv_count++;
}


void process_recv(struct tcp_connection *c){
    int moved=1;
    while(moved){
        moved=0;
        for(int i=0;i<c->recv_count;i++){
            struct recv_segment *p=&c->recvbuf[i];
            if(p->seq==c->rcv_nxt){
                fwrite(p->data,1,p->len,stdout);
                fflush(stdout);
                c->rcv_nxt+=p->len;

                memmove(&c->recvbuf[i],&c->recvbuf[i+1],sizeof(c->recvbuf[0])*(c->recv_count-i-1));
                c->recv_count--;
                moved=1;
                break;
            }
        }
    }
}


void send_ack(int s,struct sockaddr_ll *sa,
              uint8_t *mm,uint8_t *dm,
              char *mi,char *di,
              uint16_t sp,uint16_t dp,
              struct tcp_connection *c){

    send_tcp(s,sa,mm,dm,mi,di,sp,dp,
             c->snd_nxt,c->rcv_nxt,
             65535,TH_ACK,NULL,0);
}


// initiate close: works from ESTABLISHED (active close) or CLOSE_WAIT (passive close's other half)

void tcp_close_initiate(struct tcp_connection *c,
                        int s,struct sockaddr_ll *sa,
                        uint8_t *mm,uint8_t *dm,
                        char *mi,char *di,
                        uint16_t sp,uint16_t dp){

    c->fin_seq=c->snd_nxt;

    send_tcp(s,sa,mm,dm,mi,di,sp,dp,
             c->snd_nxt,c->rcv_nxt,65535,
             TH_FIN|TH_ACK,NULL,0);

    c->snd_nxt++;

    if(c->state==ST_ESTABLISHED) set_state(c,ST_FIN_WAIT_1);
    else if(c->state==ST_CLOSE_WAIT) set_state(c,ST_LAST_ACK);
}


// process incoming TCP packet

void tcp_input(struct tcp_connection *c,
               int s,struct sockaddr_ll *sa,
               uint8_t *mm,uint8_t *dm,
               char *mi,char *di,
               uint16_t sp,uint16_t dp,
               uint8_t *b){

    struct iphdr *ip=(void*)(b+14);
    if(ip->protocol!=IPPROTO_TCP) return;

    struct tcphdr *t=(void*)(b+14+ip->ihl*4);
    if(ntohs(t->dest)!=sp) return;

    int hdr=ip->ihl*4+t->doff*4;
    int plen=ntohs(ip->tot_len)-hdr;

    uint32_t seq=ntohl(t->seq);
    uint32_t ack=ntohl(t->ack_seq);

    c->snd_wnd=ntohs(t->window);

    if(t->ack){
        process_ack(c,ack,s,sa,mm,dm,mi,di,sp,dp);

        if((c->state==ST_FIN_WAIT_1 || c->state==ST_CLOSING) && ack==c->fin_seq+1){
            if(c->state==ST_FIN_WAIT_1){
                set_state(c,ST_FIN_WAIT_2);
            }else{
                set_state(c,ST_TIME_WAIT);
                c->time_wait_at=now_ms();
            }
        }

        if(c->state==ST_LAST_ACK && ack==c->fin_seq+1)
            set_state(c,ST_CLOSED);
    }

    if(plen>0){
        uint8_t *data=b+14+hdr;

        if(seq==c->rcv_nxt){
            fwrite(data,1,plen,stdout);
            fflush(stdout);
            c->rcv_nxt+=plen;
            process_recv(c);
        }else if(seq>c->rcv_nxt){
            store_recv(c,seq,data,plen);   // out of order - buffer it, peer will retransmit the gap
        }

        send_ack(s,sa,mm,dm,mi,di,sp,dp,c);
    }

    if(t->fin){
        c->rcv_nxt++;
        send_ack(s,sa,mm,dm,mi,di,sp,dp,c);

        if(c->state==ST_ESTABLISHED) set_state(c,ST_CLOSE_WAIT);
        else if(c->state==ST_FIN_WAIT_1) set_state(c,ST_CLOSING);
        else if(c->state==ST_FIN_WAIT_2){ set_state(c,ST_TIME_WAIT); c->time_wait_at=now_ms(); }
    }
}


// tcp connect (active open)

void tcp_connect(int s,struct sockaddr_ll *sa,
                 uint8_t *mm,uint8_t *dm,
                 char *mi,char *di,
                 uint16_t sp,uint16_t dp,
                 struct tcp_connection *c){

    uint8_t b[BUF_SIZE];
    uint32_t isn=rand();

    c->snd_una=isn;
    c->snd_nxt=isn+1;
    set_state(c,ST_SYN_SENT);

    send_tcp(s,sa,mm,dm,mi,di,sp,dp,isn,0,65535,TH_SYN,NULL,0);

    while(1){
        recv(s,b,sizeof(b),0);
        struct iphdr *ip=(void*)(b+14);
        if(ip->protocol!=IPPROTO_TCP) continue;

        struct tcphdr *t=(void*)(b+14+ip->ihl*4);
        if(ntohs(t->dest)!=sp) continue;

        if(t->syn&&t->ack){
            c->rcv_nxt=ntohl(t->seq)+1;
            c->snd_una=ntohl(t->ack_seq);
            c->snd_wnd=ntohs(t->window);
            break;
        }
    }

    send_tcp(s,sa,mm,dm,mi,di,sp,dp,c->snd_nxt,c->rcv_nxt,65535,TH_ACK,NULL,0);
    set_state(c,ST_ESTABLISHED);
}


// main

int main(int argc,char **argv){

    if(argc<4){
        printf("use: %s <iface> <dst_ip> <dst_port>\n",argv[0]);
        return 1;
    }

    srand(time(NULL));

    char *ifn=argv[1];
    char *dip=argv[2];
    int dport=atoi(argv[3]);

    int s=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

    struct ifreq r={0};
    strncpy(r.ifr_name,ifn,IFNAMSIZ-1);
    ioctl(s,SIOCGIFINDEX,&r);

    uint8_t mm[6],dm[6];
    char mi[32];

    get_mac(ifn,mm);
    get_ip(ifn,mi);
    arp(s,r.ifr_ifindex,mm,mi,dip,dm);

    struct sockaddr_ll sa={.sll_family=AF_PACKET,.sll_ifindex=r.ifr_ifindex,.sll_halen=6};
    memcpy(sa.sll_addr,dm,6);

    uint16_t sport=rand()%50000+10000;

    struct tcp_connection c={0};
    c.cwnd=1;
    c.ssthresh=16;
    c.srtt=300;
    c.rto=600;
    c.rto_backoff=600;
    c.snd_wnd=65535;

    tcp_connect(s,&sa,mm,dm,mi,dip,sport,dport,&c);

    char req[]=
        "GET / HTTP/1.1\r\n"
        "Host: test\r\n"
        "\r\n";

    tcp_send_data(&c,(uint8_t*)req,strlen(req));

    printf("[+] Connected. Type a line + enter to send, /quit to close.\n");

    uint8_t b[BUF_SIZE];
    char line[MSS];

    while(c.state!=ST_CLOSED){

        if(c.state==ST_TIME_WAIT){
            if(now_ms()-c.time_wait_at>=2*MSL_MS){
                set_state(&c,ST_CLOSED);
                break;
            }
        }

        if(c.state==ST_ESTABLISHED || c.state==ST_CLOSE_WAIT){
            send_window(&c,s,&sa,mm,dm,mi,dip,sport,dport);
            check_retransmit(&c,s,&sa,mm,dm,mi,dip,sport,dport);
        }

        fd_set f;
        FD_ZERO(&f);
        FD_SET(s,&f);
        if(c.state==ST_ESTABLISHED) FD_SET(STDIN_FILENO,&f);

        int maxfd = s>STDIN_FILENO ? s : STDIN_FILENO;

        struct timeval tv={.tv_sec=0,.tv_usec=100000};
        int rv=select(maxfd+1,&f,NULL,NULL,&tv);

        if(rv>0){
            if(FD_ISSET(s,&f)){
                recv(s,b,sizeof(b),0);
                tcp_input(&c,s,&sa,mm,dm,mi,dip,sport,dport,b);
            }

            if(c.state==ST_ESTABLISHED && FD_ISSET(STDIN_FILENO,&f)){
                if(fgets(line,sizeof(line),stdin)){
                    size_t n=strlen(line);
                    if(n && line[n-1]=='\n') line[--n]=0;

                    if(!strcmp(line,"/quit"))
                        tcp_close_initiate(&c,s,&sa,mm,dm,mi,dip,sport,dport);
                    else if(n>0)
                        tcp_send_data(&c,(uint8_t*)line,n);
                }
            }
        }
    }

    printf("[+] Connection closed\n");
    close(s);
    return 0;
}
