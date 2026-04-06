/*
 raw_tcp_client_all_in_one.c
 Part A + B:
   - ARP resolve
   - TCP 3-way handshake
   - Send data (PSH+ACK)
   - Track ACK
   - Receive server data and ACK it

 Build:
   gcc raw_tcp_client_all_in_one.c -o raw_tcp_client

 Run:
   sudo ./raw_tcp_client eth0 <dst_ip> <dst_port>
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
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
#define ARP_TIMEOUT 2
#define TCP_TIMEOUT 5

// checksums

uint16_t checksum(void *data, int len) {
    uint32_t sum = 0;
    uint16_t *p = data;
    while (len > 1) {
        sum += *p++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }
    if (len) sum += *(uint8_t*)p;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

uint16_t tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, uint8_t *payload, int plen) {
    struct pseudo {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } ph;

    ph.src = ip->saddr;
    ph.dst = ip->daddr;
    ph.zero = 0;
    ph.proto = IPPROTO_TCP;
    ph.len = htons(sizeof(struct tcphdr) + plen);

    int total = sizeof(ph) + sizeof(struct tcphdr) + plen;
    uint8_t *buf = calloc(1, total);

    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), tcp, sizeof(struct tcphdr));
    if (plen) memcpy(buf + sizeof(ph) + sizeof(struct tcphdr), payload, plen);

    uint16_t sum = checksum(buf, total);
    free(buf);
    return sum;
}

// interface helpers

void get_iface_mac(const char *ifname, uint8_t mac[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
}

void get_iface_ip(const char *ifname, char *ipbuf) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    struct sockaddr_in *ip = (struct sockaddr_in*)&ifr.ifr_addr;
    strcpy(ipbuf, inet_ntoa(ip->sin_addr));
    close(fd);
}

// arp

struct arp_packet {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
} __attribute__((packed));

int arp_resolve(int sock, int ifindex, uint8_t my_mac[6], char *my_ip,
                char *target_ip, uint8_t out_mac[6]) {

    uint8_t buf[60];
    struct ethhdr *eth = (struct ethhdr*)buf;
    struct arp_packet *arp = (struct arp_packet*)(buf + 14);
    memset(buf, 0, sizeof(buf));

    memset(eth->h_dest, 0xff, 6);
    memcpy(eth->h_source, my_mac, 6);
    eth->h_proto = htons(ETH_P_ARP);

    arp->htype = htons(1);
    arp->ptype = htons(ETH_P_IP);
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = htons(1);
    memcpy(arp->sha, my_mac, 6);
    inet_pton(AF_INET, my_ip, arp->spa);
    inet_pton(AF_INET, target_ip, arp->tpa);

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    memset(addr.sll_addr, 0xff, 6);

    sendto(sock, buf, 42, 0, (struct sockaddr*)&addr, sizeof(addr));

    fd_set fds;
    struct timeval tv;

    while (1) {
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        tv.tv_sec = ARP_TIMEOUT;
        tv.tv_usec = 0;

        if (select(sock+1, &fds, NULL, NULL, &tv) <= 0)
            return -1;

        uint8_t rbuf[BUF_SIZE];
        recv(sock, rbuf, sizeof(rbuf), 0);

        struct ethhdr *reth = (struct ethhdr*)rbuf;
        if (ntohs(reth->h_proto) != ETH_P_ARP) continue;

        struct arp_packet *rarp = (struct arp_packet*)(rbuf + 14);
        if (ntohs(rarp->oper) == 2 &&
            memcmp(rarp->spa, arp->tpa, 4) == 0) {

            memcpy(out_mac, rarp->sha, 6);
            return 0;
        }
    }
}

// packet send helper

void send_tcp(int sock, struct sockaddr_ll *addr,
              uint8_t *my_mac, uint8_t *dst_mac,
              char *my_ip, char *dst_ip,
              uint16_t sport, uint16_t dport,
              uint32_t seq, uint32_t ack,
              uint8_t flags, uint8_t *payload, int plen) {

    uint8_t buf[BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    struct ethhdr *eth = (struct ethhdr*)buf;
    struct iphdr *ip = (struct iphdr*)(buf + 14);
    struct tcphdr *tcp = (struct tcphdr*)(buf + 14 + sizeof(struct iphdr));

    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, my_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    ip->ihl = 5;
    ip->version = 4;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(my_ip);
    ip->daddr = inet_addr(dst_ip);

    tcp->source = htons(sport);
    tcp->dest = htons(dport);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff = 5;
    tcp->window = htons(5840);

    tcp->fin = flags & TH_FIN;
    tcp->syn = flags & TH_SYN;
    tcp->rst = flags & TH_RST;
    tcp->psh = flags & TH_PUSH;
    tcp->ack = flags & TH_ACK;

    memcpy(buf + 14 + sizeof(struct iphdr) + sizeof(struct tcphdr),
           payload, plen);

    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + plen);
    ip->check = checksum(ip, sizeof(struct iphdr));
    tcp->check = tcp_checksum(ip, tcp,
        buf + 14 + sizeof(struct iphdr) + sizeof(struct tcphdr), plen);

    sendto(sock, buf,
           14 + sizeof(struct iphdr) + sizeof(struct tcphdr) + plen,
           0, (struct sockaddr*)addr, sizeof(*addr));
}

// main 

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("usage: %s <iface> <dst_ip> <dst_port>\n", argv[0]);
        return 1;
    }

    char *ifname = argv[1];
    char *dst_ip = argv[2];
    int dst_port = atoi(argv[3]);

    srand(time(NULL));
    uint32_t snd_seq = rand();
    uint32_t rcv_seq = 0;

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(sock, SIOCGIFINDEX, &ifr);
    int ifindex = ifr.ifr_ifindex;

    uint8_t my_mac[6], dst_mac[6];
    char my_ip[32];

    get_iface_mac(ifname, my_mac);
    get_iface_ip(ifname, my_ip);

    printf("[+] My IP %s\n", my_ip);

    if (arp_resolve(sock, ifindex, my_mac, my_ip, dst_ip, dst_mac) < 0) {
        printf("[-] ARP failed\n");
        return 1;
    }

    printf("[+] ARP resolved\n");

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    memcpy(addr.sll_addr, dst_mac, 6);

    uint16_t src_port = rand()%50000 + 10000;

    // syn
    printf("[+] Sending SYN\n");
    send_tcp(sock,&addr,my_mac,dst_mac,my_ip,dst_ip,
             src_port,dst_port,snd_seq,0,TH_SYN,NULL,0);

    snd_seq++;

    uint8_t buf[BUF_SIZE];

    // wait for syn ack
    while (1) {
        recv(sock, buf, sizeof(buf), 0);
        struct iphdr *ip = (struct iphdr*)(buf + 14);
        if (ip->protocol != IPPROTO_TCP) continue;

        struct tcphdr *tcp = (struct tcphdr*)(buf + 14 + ip->ihl*4);
        if (ntohs(tcp->dest) != src_port) continue;

        if (tcp->syn && tcp->ack) {
            rcv_seq = ntohl(tcp->seq) + 1;
            printf("[+] Got SYN-ACK\n");
            break;
        }
    }

    // final ack
    send_tcp(sock,&addr,my_mac,dst_mac,my_ip,dst_ip,
             src_port,dst_port,snd_seq,rcv_seq,TH_ACK,NULL,0);

    printf("[+] Handshake complete\n");

    // send data

    char payload[] =
        "GET / HTTP/1.1\r\n"
        "Host: test\r\n"
        "Connection: close\r\n\r\n";

    int plen = strlen(payload);

    send_tcp(sock,&addr,my_mac,dst_mac,my_ip,dst_ip,
             src_port,dst_port,snd_seq,rcv_seq,TH_ACK|TH_PUSH,
             (uint8_t*)payload, plen);

    snd_seq += plen;

    printf("[+] Data sent\n");

    // receive data

    while (1) {
        int n = recv(sock, buf, sizeof(buf), 0);
        struct iphdr *ip = (struct iphdr*)(buf + 14);
        if (ip->protocol != IPPROTO_TCP) continue;

        struct tcphdr *tcp = (struct tcphdr*)(buf + 14 + ip->ihl*4);
        if (ntohs(tcp->dest) != src_port) continue;

        int hlen = 14 + ip->ihl*4 + tcp->doff*4;
        int dlen = n - hlen;

        if (dlen > 0) {
            fwrite(buf + hlen, 1, dlen, stdout);
            rcv_seq = ntohl(tcp->seq) + dlen;

            send_tcp(sock,&addr,my_mac,dst_mac,my_ip,dst_ip,
                     src_port,dst_port,snd_seq,rcv_seq,TH_ACK,NULL,0);
        }

        if (tcp->fin) break;
    }

    printf("\n[+] Server closed\n");

    close(sock);
    return 0;
}
