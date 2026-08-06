/*
 raw_tcp_part_h_options.c

 Part H: TCP Options + True Bidirectional Flow Control (builds on Part G)

 Part G honored the PEER's window but always advertised a fake, fixed
 65535 window of our own, never handled the peer's window hitting 0,
 and used Karn's algorithm to blindly refuse to sample RTT off any
 retransmitted segment. This part replaces those approximations with
 the real mechanisms that make them unnecessary:

   - Real recv window   : advertise our ACTUAL free reassembly-buffer
                           space, not a hardcoded constant. Flow control
                           now works in both directions, symmetrically.
   - Zero window +       : when OUR window hits 0, refuse to send more
     persist timer         (part G quietly ignored a zero window and
                           kept sending anyway). When the PEER's window
                           hits 0, stop sending data and instead probe
                           with 1 byte on a doubling timer until they
                           reopen it - the classic TCP persist timer,
                           complete with a receiver that also announces
                           reopened windows immediately instead of
                           waiting on the peer to guess.
   - TCP timestamps      : every segment carries a send timestamp; the
     (RFC 7323)             peer echoes it back on the ACK. RTT is then
                           read straight off THAT exact transmission's
                           echo, so retransmit ambiguity - the problem
                           Karn's algorithm works around by refusing to
                           sample - just doesn't arise. Karn's rule is
                           kept as the fallback for when timestamps
                           aren't available.
   - SACK (RFC 2018)     : the receiver reports the exact out-of-order
                           blocks it's holding, so fast retransmit
                           resends the real hole instead of blindly
                           assuming it's always segment 0.
   - Delayed ACK         : in-order data is acked after a short timer
     (RFC 1122)            or after every 2nd segment, not on every
                           single packet - but out-of-order data and
                           FINs are still acked immediately, since
                           that's exactly the signal fast retransmit
                           depends on.
   - struct link         : the socket/interface/MAC/IP plumbing that
                           part G threaded through every function
                           signature is bundled into one struct, so
                           adding more per-packet fields (as above)
                           doesn't keep exploding every call site.

 Build:
   gcc raw_tcp_part_h_options.c -o raw_tcp_part_h

 Run:
   sudo ./raw_tcp_part_h eth0 <dst_ip> <dst_port>

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
#define MSL_MS 2000          // real TCP uses ~2 min; shortened here so the demo actually finishes
#define DELAYED_ACK_MS 200   // RFC 1122: ack within this long, or after the 2nd in-order segment
#define MAX_SACK_BLOCKS 3    // 3 SACK blocks + timestamps exactly fills the 40-byte options budget


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


// raw-socket/link plumbing, bundled so it stops growing every call site

struct link{
    int s;
    struct sockaddr_ll *sa;
    uint8_t *mm,*dm;
    char *mi,*di;
    uint16_t sp,dp;
};


// parsed/serialized TCP option state

struct sack_block{
    uint32_t left,right;
};

struct tcp_opts{
    int has_ts;
    uint32_t tsval,tsecr;

    int sack_n;
    struct sack_block sack[MAX_SACK_BLOCKS];
};


struct tcp_segment{
    uint32_t seq;
    uint16_t len;
    uint8_t data[MSS];

    uint64_t t;

    int sent;
    int acked;
    int retx;      // retransmit count - Karn's fallback skips RTT sampling on these
    int sacked;    // peer's SACK blocks say they already have this - don't resend it
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
    uint16_t last_adv_wnd;  // OUR window as of the last packet we sent them

    double cwnd;
    double ssthresh;

    double srtt;
    double rto;             // estimator-derived base RTO
    double rto_backoff;     // current (possibly doubled) RTO in effect
    int timeouts;           // consecutive timeouts with no forward progress

    int dup_ack;

    uint32_t ts_recent;     // last TSval the peer sent us, echoed back as TSecr

    uint64_t persist_at;    // zero-window probe timer
    double persist_rto;

    int ack_pending;        // delayed-ack bookkeeping
    int unacked_segs;
    uint64_t ack_due_at;

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


// tlen is the TCP header length INCLUDING options, since part H's headers
// are no longer always a fixed 20 bytes

uint16_t tcp_checksum(struct iphdr *ip,struct tcphdr *t,int tlen,uint8_t *pl,int pln){
    struct{uint32_t s,d;uint8_t z,p;uint16_t l;}ph;
    ph.s=ip->saddr; ph.d=ip->daddr; ph.z=0; ph.p=IPPROTO_TCP;
    ph.l=htons(tlen+pln);

    int T=sizeof(ph)+tlen+pln;
    uint8_t *b=calloc(1,T);

    memcpy(b,&ph,sizeof(ph));
    memcpy(b+sizeof(ph),t,tlen);
    if(pln) memcpy(b+sizeof(ph)+tlen,pl,pln);

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


// TCP options: build/parse NOP-padded TLVs (kind 8 = timestamps, kind 5 = SACK)

int build_options(uint8_t *opt,uint32_t tsval,uint32_t tsecr,int with_ts,
                  struct sack_block *sacks,int sack_n){
    int n=0;

    if(with_ts){
        opt[n++]=1; opt[n++]=1;           // NOP,NOP pad the option onto a 4-byte boundary
        opt[n++]=8; opt[n++]=10;          // kind=8 (timestamps), len=10
        uint32_t v=htonl(tsval); memcpy(opt+n,&v,4); n+=4;
        uint32_t e=htonl(tsecr); memcpy(opt+n,&e,4); n+=4;
    }

    if(sack_n>0){
        opt[n++]=1; opt[n++]=1;
        opt[n++]=5; opt[n++]=2+sack_n*8;  // kind=5 (SACK), len

        for(int i=0;i<sack_n;i++){
            uint32_t l=htonl(sacks[i].left), r=htonl(sacks[i].right);
            memcpy(opt+n,&l,4); n+=4;
            memcpy(opt+n,&r,4); n+=4;
        }
    }

    while(n%4) opt[n++]=1;   // NOP-pad header to a 4-byte boundary (doff is in 32-bit words)
    return n;
}


void parse_tcp_options(struct tcphdr *t,struct tcp_opts *o){
    memset(o,0,sizeof(*o));

    uint8_t *p=(uint8_t*)t+sizeof(*t);
    int len=t->doff*4-sizeof(*t);
    int i=0;

    while(i<len){
        uint8_t kind=p[i];
        if(kind==0) break;        // end of option list
        if(kind==1){ i++; continue; }  // NOP

        if(i+1>=len) break;
        uint8_t optlen=p[i+1];
        if(optlen<2 || i+optlen>len) break;

        if(kind==8 && optlen==10){
            uint32_t v,e;
            memcpy(&v,p+i+2,4); memcpy(&e,p+i+6,4);
            o->has_ts=1; o->tsval=ntohl(v); o->tsecr=ntohl(e);
        }else if(kind==5){
            int n=(optlen-2)/8;
            for(int k=0;k<n && o->sack_n<MAX_SACK_BLOCKS;k++){
                uint32_t l,r;
                memcpy(&l,p+i+2+k*8,4); memcpy(&r,p+i+6+k*8,4);
                o->sack[o->sack_n].left=ntohl(l);
                o->sack[o->sack_n].right=ntohl(r);
                o->sack_n++;
            }
        }

        i+=optlen;
    }
}


// our real advertised window: free space left in the reassembly buffer

uint16_t recv_window(struct tcp_connection *c){
    int free_slots=RECV_BUFFER_SIZE-c->recv_count;
    long win=(long)free_slots*MSS;
    if(win<0) win=0;
    if(win>65535) win=65535;   // no window scaling here, same ceiling real unscaled TCP has
    return (uint16_t)win;
}


// report the out-of-order blocks we're holding, as SACK left/right edges
// (no merging of adjacent ranges - real stacks would coalesce; capped at
// MAX_SACK_BLOCKS, so a badly fragmented buffer only reports the first few)

int gather_sacks(struct tcp_connection *c,struct sack_block *out){
    int n=0;
    for(int i=0;i<c->recv_count && n<MAX_SACK_BLOCKS;i++){
        out[n].left=c->recvbuf[i].seq;
        out[n].right=c->recvbuf[i].seq+c->recvbuf[i].len;
        n++;
    }
    return n;
}


uint32_t ts_now(){
    return (uint32_t)now_ms();
}


// tcp packet builder (low level - caller supplies every field explicitly)

void send_tcp(struct link *lk,
              uint32_t seq,uint32_t ack,uint16_t win,uint8_t fl,
              uint8_t *pl,int plen,
              uint32_t tsval,uint32_t tsecr,int with_ts,
              struct sack_block *sacks,int sack_n){

    uint8_t b[BUF_SIZE]={0};

    struct ethhdr *e=(void*)b;
    struct iphdr *ip=(void*)(b+14);
    struct tcphdr *t=(void*)(b+14+sizeof(*ip));
    uint8_t *opt=(uint8_t*)t+sizeof(*t);

    int optlen=build_options(opt,tsval,tsecr,with_ts,sacks,sack_n);
    int tlen=sizeof(*t)+optlen;

    memcpy(e->h_dest,lk->dm,6);
    memcpy(e->h_source,lk->mm,6);
    e->h_proto=htons(ETH_P_IP);

    ip->ihl=5; ip->version=4; ip->ttl=64; ip->protocol=IPPROTO_TCP;
    ip->saddr=inet_addr(lk->mi); ip->daddr=inet_addr(lk->di);

    t->source=htons(lk->sp); t->dest=htons(lk->dp);
    t->seq=htonl(seq); t->ack_seq=htonl(ack);
    t->doff=tlen/4; t->window=htons(win);
    t->fin=fl&TH_FIN; t->syn=fl&TH_SYN; t->rst=fl&TH_RST;
    t->psh=fl&TH_PUSH; t->ack=fl&TH_ACK;

    uint8_t *payload=b+14+sizeof(*ip)+tlen;
    if(pl) memcpy(payload,pl,plen);

    ip->tot_len=htons(sizeof(*ip)+tlen+plen);
    ip->check=checksum(ip,sizeof(*ip));
    t->check=tcp_checksum(ip,t,tlen,payload,plen);

    sendto(lk->s,b,14+sizeof(*ip)+tlen+plen,0,(void*)lk->sa,sizeof(*lk->sa));
}


// tcp packet builder (high level - fills in window/timestamps/SACK from
// connection state, the way real tcp_output() does)

void tcp_output(struct tcp_connection *c,struct link *lk,
                uint32_t seq,uint8_t fl,uint8_t *pl,int plen){

    struct sack_block sacks[MAX_SACK_BLOCKS];
    int sn=gather_sacks(c,sacks);
    uint16_t w=recv_window(c);

    send_tcp(lk,seq,c->rcv_nxt,w,fl,pl,plen,
             ts_now(),c->ts_recent,1,sacks,sn);

    c->last_adv_wnd=w;
}


// send buffer

void queue_segment(struct tcp_connection *c,uint32_t seq,uint8_t *data,int len){
    if(c->send_count>=SEND_BUFFER_SIZE) return;

    struct tcp_segment *p=&c->sendbuf[c->send_count];
    p->seq=seq; p->len=len;
    memcpy(p->data,data,len);
    p->t=0; p->sent=0; p->acked=0; p->retx=0; p->sacked=0;

    c->send_count++;
}


void remove_acked(struct tcp_connection *c){
    while(c->send_count>0 && c->sendbuf[0].acked){
        memmove(&c->sendbuf[0],&c->sendbuf[1],sizeof(c->sendbuf[0])*(c->send_count-1));
        c->send_count--;
    }
}


// send packets allowed by cwnd AND the peer's advertised window - a zero
// window means genuinely zero, not "at least 1" like part G assumed

void send_window(struct tcp_connection *c,struct link *lk){
    int inflight=0;
    for(int i=0;i<c->send_count;i++)
        if(c->sendbuf[i].sent && !c->sendbuf[i].acked) inflight++;

    int allowed;
    if(c->snd_wnd==0){
        allowed=0;   // peer's window is closed - stop; the persist timer takes over
    }else{
        int wnd_segs=c->snd_wnd/MSS;
        if(wnd_segs<1) wnd_segs=1;
        allowed=(int)c->cwnd;
        if(wnd_segs<allowed) allowed=wnd_segs;
    }

    for(int i=0;i<c->send_count;i++){
        struct tcp_segment *p=&c->sendbuf[i];
        if(p->sent) continue;
        if(inflight>=allowed) break;

        tcp_output(c,lk,p->seq,TH_ACK|TH_PUSH,p->data,p->len);

        p->t=now_ms();
        p->sent=1;
        inflight++;
    }
}


// on 3 duplicate ACKs, resend the actual hole - the first segment that's
// neither acked nor already reported via SACK - instead of blindly
// assuming it's always sendbuf[0]

void fast_retransmit(struct tcp_connection *c,struct link *lk){
    if(c->send_count==0) return;

    struct tcp_segment *p=NULL;
    for(int i=0;i<c->send_count;i++){
        if(!c->sendbuf[i].acked && !c->sendbuf[i].sacked){ p=&c->sendbuf[i]; break; }
    }
    if(!p) return;   // everything outstanding is already SACKed by the peer

    printf("[!] fast retransmit seq=%u (3 dup acks)\n",p->seq);

    tcp_output(c,lk,p->seq,TH_ACK|TH_PUSH,p->data,p->len);

    p->t=now_ms();
    p->retx++;

    // Reno-style fast recovery: halve, don't collapse to slow start
    c->ssthresh=c->cwnd/2;
    if(c->ssthresh<2) c->ssthresh=2;
    c->cwnd=c->ssthresh;
}


void process_ack(struct tcp_connection *c,uint32_t ack,struct tcp_opts *po,struct link *lk){

    // SACK blocks can ride along with duplicate ACKs (that's their whole
    // purpose) as well as regular ones, so check them unconditionally
    for(int k=0;k<po->sack_n;k++){
        for(int i=0;i<c->send_count;i++){
            struct tcp_segment *p=&c->sendbuf[i];
            uint32_t end=p->seq+p->len;
            if(!p->acked && p->seq>=po->sack[k].left && end<=po->sack[k].right)
                p->sacked=1;
        }
    }

    if(ack==c->snd_una){
        if(c->send_count>0){
            c->dup_ack++;
            if(c->dup_ack==3){
                fast_retransmit(c,lk);
                c->dup_ack=0;
            }
        }
        return;
    }

    uint64_t ts_rtt=po->has_ts ? now_ms()-po->tsecr : 0;
    int moved=0;

    for(int i=0;i<c->send_count;i++){
        struct tcp_segment *p=&c->sendbuf[i];
        if(p->acked) continue;

        uint32_t end=p->seq+p->len;

        if(ack>=end){
            if(po->has_ts){
                // the echoed timestamp is pinned to this exact transmission,
                // retransmitted or not - the ambiguity Karn's algorithm
                // sidesteps by refusing to sample just doesn't come up
                c->srtt=0.875*c->srtt+0.125*ts_rtt;
                c->rto=c->srtt*2;
            }else if(p->retx==0){
                uint64_t rtt=now_ms()-p->t;
                c->srtt=0.875*c->srtt+0.125*rtt;
                c->rto=c->srtt*2;
            }
            p->acked=1;
            moved=1;
        }else if(ack>p->seq){
            // partial ack: the peer only consumed a prefix of this segment
            // (this is exactly what happens when they answer a 1-byte
            // zero-window probe). Trim it to match reality instead of
            // treating it as either fully acked or untouched.
            uint32_t adv=ack-p->seq;
            memmove(p->data,p->data+adv,p->len-adv);
            p->seq+=adv;
            p->len-=adv;
            moved=1;
            break;   // sendbuf is seq-ordered - nothing after this can be affected
        }else{
            break;
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


// retransmission timer, with exponential backoff on repeated timeouts.
// a full RTO means we no longer trust the SACK scoreboard, so this
// resends anything overdue regardless of whether it was SACKed

void check_retransmit(struct tcp_connection *c,struct link *lk){
    for(int i=0;i<c->send_count;i++){
        struct tcp_segment *p=&c->sendbuf[i];
        if(!p->sent || p->acked) continue;

        if(now_ms()-p->t > c->rto_backoff){
            printf("[!] timeout retransmit seq=%u (rto=%.0fms)\n",p->seq,c->rto_backoff);

            tcp_output(c,lk,p->seq,TH_ACK|TH_PUSH,p->data,p->len);

            p->t=now_ms();
            p->retx++;

            c->timeouts++;
            double backoff=c->rto*(1<<(c->timeouts>6?6:c->timeouts));
            c->rto_backoff=backoff>MAX_RTO_MS ? MAX_RTO_MS : backoff;

            c->ssthresh=c->cwnd/2;
            if(c->ssthresh<2) c->ssthresh=2;
            c->cwnd=1;
        }
    }
}


// zero-window persist timer: when the PEER's window is 0, send_window
// goes silent, so nothing would ever wake them up again if their one
// window-update ACK got lost. Probe with 1 byte on a doubling timer
// until they report a nonzero window.

void check_persist(struct tcp_connection *c,struct link *lk){
    if(c->snd_wnd>0 || c->send_count==0){
        c->persist_rto=1000;
        return;
    }
    if(now_ms()-c->persist_at<c->persist_rto) return;

    struct tcp_segment *p=&c->sendbuf[0];
    printf("[!] zero window - probing with 1 byte (seq=%u)\n",p->seq);

    // the probe isn't tracked in the retransmit table - its only job is to
    // force a fresh ACK out of the peer. If they accept it, process_ack's
    // partial-ack path trims sendbuf[0] to match what actually got through.
    tcp_output(c,lk,p->seq,TH_ACK,p->data,1);

    c->persist_at=now_ms();
    c->persist_rto = c->persist_rto*2>MAX_RTO_MS ? MAX_RTO_MS : c->persist_rto*2;
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


// delayed ACK (RFC 1122): ack right away, bypassing the timer

void ack_now(struct tcp_connection *c,struct link *lk){
    tcp_output(c,lk,c->snd_nxt,TH_ACK,NULL,0);
    c->ack_pending=0;
    c->unacked_segs=0;
}


// ...or schedule one for later - unless this is the 2nd in-order segment
// since the last ack, which RFC 1122 says must be acked immediately too

void schedule_ack(struct tcp_connection *c,struct link *lk){
    c->unacked_segs++;
    if(!c->ack_pending){
        c->ack_pending=1;
        c->ack_due_at=now_ms()+DELAYED_ACK_MS;
    }
    if(c->unacked_segs>=2) ack_now(c,lk);
}


void flush_ack(struct tcp_connection *c,struct link *lk){
    if(c->ack_pending && now_ms()>=c->ack_due_at) ack_now(c,lk);
}


// initiate close: works from ESTABLISHED (active close) or CLOSE_WAIT (passive close's other half)

void tcp_close_initiate(struct tcp_connection *c,struct link *lk){
    c->fin_seq=c->snd_nxt;

    tcp_output(c,lk,c->snd_nxt,TH_FIN|TH_ACK,NULL,0);
    c->snd_nxt++;

    if(c->state==ST_ESTABLISHED) set_state(c,ST_FIN_WAIT_1);
    else if(c->state==ST_CLOSE_WAIT) set_state(c,ST_LAST_ACK);
}


// process incoming TCP packet

void tcp_input(struct tcp_connection *c,struct link *lk,uint8_t *b){

    struct iphdr *ip=(void*)(b+14);
    if(ip->protocol!=IPPROTO_TCP) return;

    struct tcphdr *t=(void*)(b+14+ip->ihl*4);
    if(ntohs(t->dest)!=lk->sp) return;

    struct tcp_opts po;
    parse_tcp_options(t,&po);

    int hdr=ip->ihl*4+t->doff*4;
    int plen=ntohs(ip->tot_len)-hdr;

    uint32_t seq=ntohl(t->seq);
    uint32_t ack=ntohl(t->ack_seq);

    c->snd_wnd=ntohs(t->window);
    if(po.has_ts) c->ts_recent=po.tsval;

    if(t->ack){
        process_ack(c,ack,&po,lk);

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

            if(c->last_adv_wnd==0 && recv_window(c)>0)
                ack_now(c,lk);       // window just reopened - say so immediately
            else
                schedule_ack(c,lk);
        }else if(seq>c->rcv_nxt){
            store_recv(c,seq,data,plen);   // out of order - buffer it
            ack_now(c,lk);                 // immediate dup ack + SACK - drives fast retransmit
        }
    }

    if(t->fin){
        c->rcv_nxt++;
        ack_now(c,lk);

        if(c->state==ST_ESTABLISHED) set_state(c,ST_CLOSE_WAIT);  // they sent fin first
        else if(c->state==ST_FIN_WAIT_1) set_state(c,ST_CLOSING); // both same time
        else if(c->state==ST_FIN_WAIT_2){ set_state(c,ST_TIME_WAIT); c->time_wait_at=now_ms(); } // my fin already acked
    }
}


// tcp connect (active open)

void tcp_connect(struct link *lk,struct tcp_connection *c){
    uint8_t b[BUF_SIZE];
    uint32_t isn=rand();

    c->snd_una=isn;
    c->snd_nxt=isn+1;
    set_state(c,ST_SYN_SENT);

    tcp_output(c,lk,isn,TH_SYN,NULL,0);

    while(1){
        recv(lk->s,b,sizeof(b),0);
        struct iphdr *ip=(void*)(b+14);
        if(ip->protocol!=IPPROTO_TCP) continue;

        struct tcphdr *t=(void*)(b+14+ip->ihl*4);
        if(ntohs(t->dest)!=lk->sp) continue;

        if(t->syn&&t->ack){
            struct tcp_opts po;
            parse_tcp_options(t,&po);

            c->rcv_nxt=ntohl(t->seq)+1;
            c->snd_una=ntohl(t->ack_seq);
            c->snd_wnd=ntohs(t->window);
            if(po.has_ts) c->ts_recent=po.tsval;
            break;
        }
    }

    tcp_output(c,lk,c->snd_nxt,TH_ACK,NULL,0);
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

    struct link lk={.s=s,.sa=&sa,.mm=mm,.dm=dm,.mi=mi,.di=dip,.sp=sport,.dp=(uint16_t)dport};

    struct tcp_connection c={0};
    c.cwnd=1;
    c.ssthresh=16;
    c.srtt=300;
    c.rto=600;
    c.rto_backoff=600;
    c.snd_wnd=65535;
    c.persist_rto=1000;

    tcp_connect(&lk,&c);

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
            send_window(&c,&lk);
            check_retransmit(&c,&lk);
            check_persist(&c,&lk);
            flush_ack(&c,&lk);
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
                tcp_input(&c,&lk,b);
            }

            if(c.state==ST_ESTABLISHED && FD_ISSET(STDIN_FILENO,&f)){
                if(fgets(line,sizeof(line),stdin)){
                    size_t n=strlen(line);
                    if(n && line[n-1]=='\n') line[--n]=0;

                    if(!strcmp(line,"/quit"))
                        tcp_close_initiate(&c,&lk);
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
