#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/socket.h>

#define ETH_HDR_LEN 14
#define ARP_REQUEST 1
#define ARP_REPLY   2
#define ETH_P_ARP   0x0806

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
};

unsigned short checksum(unsigned short *buf, int bytes) {
    unsigned long sum = 0;
    while (bytes > 1) { sum += *buf++; bytes -= 2; }
    if (bytes == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void print_mac(unsigned char *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int arp_resolve(int sockfd, const char *iface,
                const unsigned char *src_mac, unsigned char dst_mac, const char *target_ip)
{
    unsigned char buffer[42];
    struct ethhdr * eth = (struct ethhdr *)buffer;
    struct {
        uint16_t htype, ptype, oper;
        uint8_t hlen, plen;
        uint8_t sha[6], spa[4], tha[6], tpa[4];
    } __attribute__((packed)) *arp = (void *)(buffer + ETH_HDR_LEN);

    unsigned char my_ip[4], tgt_ip[4];
    inet_pton(AF_INET, "10.0.0.5", my_ip);
    inet_pton(AF_INET, target_ip, tgt_ip);

    memset(buffer, 0, sizeof(buffer));

    memset(eth->h_dest, 0xff, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_ARP);

    arp->htype = htons(1);
    arp->ptype = htons(0x0800);
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = htons(ARP_REQUEST);
    memcpy(arp->sha, src_mac, 6);
    memcpy(arp->spa, my_ip, 4);
    memset(arp->tha, 0, 6);
    memcpy(arp->tpa, tgt_ip, 4);

    struct sockaddr_ll dev = {0};
    dev.sll_ifindex = if_nametoindex(iface);
    dev.sll_halen = ETH_ALEN;
    memcpy(dev.sll_addr, eth->h_dest, 6);

    if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&dev, sizeof(dev)) < 0){
        perror("ARP send");
        return -1;
    }

    while (1) {
        int n = recv(sockfd, buffer, sizeof(buffer), 0);
        if (n < 0) { perror("recv"); return -1; }

        eth = (struct ethhdr *)buffer;
        arp = (void *)(buffer + ETH_HDR_LEN);

        if (ntohs(eth->h_proto) == ETH_P_ARP && ntohs(arp->oper) == ARP_REPLY &&
            memcmp(arp->spa, tgt_ip, 4) == 0) 
        {
            memcpy(dst_mac, arp->sha, 6);
            return 0;
        }
    }
}


int build_tcp_packet(unsigned char *packet, unsigned char *src_mac, unsigned char *dst_mac,
                     const char *src_ip, const char *dst_ip, int src_port, int dst_port,
                     uint32_t seq_num, uint32_t ack_num, int syn , int ack_flag,
                     const char *payload, int add_mss_option)
{
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr  *ip  = (struct iphdr *)(packet + ETH_HDR_LEN);
    unsigned char *tcp_start = packet + ETH_HDR_LEN + sizeof(struct iphdr);
    struct tcphdr *tcp = (struct tcphdr *)tcp_start;
    unsigned char *options = tcp_start + sizeof(struct tcphdr);
    int tcp_opt_len = 0;

    if (add_mss_option) {
        options[0] = 2;
        options[1] = 4;
        uint16_t mss = htons(1460);
        memcpy(options + 2, &mss , 2);
        tcp_opt_len = 4;
    }

    while ((sizeof(struct tcphdr) + tcp_opt_len) % 4 != 0)
        options[tcp_opt_len++] = 1;


}


