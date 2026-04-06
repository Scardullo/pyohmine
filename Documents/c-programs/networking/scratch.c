/*
 * Mini TCP/IP Client with TCP Options Support
 * - Raw Ethernet
 * - ARP resolution
 * - Dynamic IP/TCP header sizing
 * - TCP SYN with MSS option
 *
 * Run as root. Linux only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/socket.h>

// constants

#define ETH_HDR_LEN 14
#define ARP_REQUEST 1
#define ARP_REPLY   2
#define ETH_P_ARP   0x0806

// pseudo header

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
};

// checksum

unsigned short checksum(unsigned short *buf, int bytes)
{
    unsigned long sum = 0;

    while (bytes > 1) {
        sum += *buf++;
        bytes -= 2;
    }

    if (bytes == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}


void print_mac(unsigned char *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}


int arp_resolve(int sockfd, const char *iface,
                const unsigned char *src_mac,
                unsigned char *dst_mac,
                const char *target_ip)
{
    unsigned char buffer[42];
    struct ethhdr *eth = (struct ethhdr *)buffer;

    struct {
        uint16_t htype;
        uint16_t ptype;
        uint8_t  hlen;
        uint8_t  plen;
        uint16_t oper;
        uint8_t  sha[6];
        uint8_t  spa[4];
        uint8_t  tha[6];
        uint8_t  tpa[4];
    } __attribute__((packed)) *arp = (void *)(buffer + ETH_HDR_LEN);

    unsigned char my_ip[4];
    unsigned char target_ip_bytes[4];

    inet_pton(AF_INET, "192.168.1.2", my_ip);
    inet_pton(AF_INET, target_ip, target_ip_bytes);

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
    memcpy(arp->tpa, target_ip_bytes, 4);

    struct sockaddr_ll dev = {0};
    dev.sll_ifindex = if_nametoindex(iface);
    dev.sll_halen = ETH_ALEN;
    memcpy(dev.sll_addr, eth->h_dest, 6);

    if (sendto(sockfd, buffer, sizeof(buffer), 0,
               (struct sockaddr*)&dev, sizeof(dev)) < 0) {
        perror("ARP send");
        return -1;
    }

    while (1) {
        int n = recv(sockfd, buffer, sizeof(buffer), 0);
        if (n < 0) { perror("recv"); return -1; }

        eth = (struct ethhdr *)buffer;
        arp = (void *)(buffer + ETH_HDR_LEN);

        if (ntohs(eth->h_proto) == ETH_P_ARP &&
            ntohs(arp->oper) == ARP_REPLY &&
            memcmp(arp->spa, target_ip_bytes, 4) == 0)
        {
            memcpy(dst_mac, arp->sha, 6);
            return 0;
        }
    }
}


int build_tcp_packet(unsigned char *packet,
                     unsigned char *src_mac, unsigned char *dst_mac,
                     const char *src_ip, const char *dst_ip,
                     int src_port, int dst_port,
                     int syn, int ack_flag,
                     const char *payload,
                     int add_mss_option)
{
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr  *ip  = (struct iphdr *)(packet + ETH_HDR_LEN);

    unsigned char *tcp_start = packet + ETH_HDR_LEN + sizeof(struct iphdr);
    struct tcphdr *tcp = (struct tcphdr *)tcp_start;

    unsigned char *options = tcp_start + sizeof(struct tcphdr);
    int tcp_opt_len = 0;

    /* ---- TCP Options (MSS) ---- */
    if (add_mss_option) {
        options[0] = 2;   // MSS kind
        options[1] = 4;   // length
        uint16_t mss = htons(1460);
        memcpy(options + 2, &mss, 2);
        tcp_opt_len = 4;
    }

    /* pad to 4-byte boundary */
    while ((sizeof(struct tcphdr) + tcp_opt_len) % 4 != 0) {
        options[tcp_opt_len++] = 1; // NOP
    }

    int tcp_hdr_len = sizeof(struct tcphdr) + tcp_opt_len;

    unsigned char *data =
        packet + ETH_HDR_LEN + sizeof(struct iphdr) + tcp_hdr_len;

    int payload_len = payload ? strlen(payload) : 0;
    if (payload) memcpy(data, payload, payload_len);

    // ethernet
    memcpy(eth->h_source, src_mac, 6);
    memcpy(eth->h_dest, dst_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    // ip
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + tcp_hdr_len + payload_len);
    ip->id = htons(rand() % 65535);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    inet_pton(AF_INET, src_ip, &ip->saddr);
    inet_pton(AF_INET, dst_ip, &ip->daddr);
    ip->check = checksum((unsigned short *)ip, ip->ihl * 4);

    // tcp
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(rand() % 100000);
    tcp->ack_seq = ack_flag ? htonl(1) : 0;
    tcp->doff = tcp_hdr_len / 4;
    tcp->syn = syn;
    tcp->ack = ack_flag;
    tcp->window = htons(5840);
    tcp->urg_ptr = 0;
    tcp->check = 0;

    // tcp checksum
    struct pseudo_hdr pseudo;
    pseudo.src = ip->saddr;
    pseudo.dst = ip->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.tcp_len = htons(tcp_hdr_len + payload_len);

    int psize = sizeof(pseudo) + tcp_hdr_len + payload_len;
    unsigned char *pseudogram = malloc(psize);

    memcpy(pseudogram, &pseudo, sizeof(pseudo));
    memcpy(pseudogram + sizeof(pseudo), tcp, tcp_hdr_len);
    if (payload)
        memcpy(pseudogram + sizeof(pseudo) + tcp_hdr_len, payload, payload_len);

    tcp->check = checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    return ETH_HDR_LEN + sizeof(struct iphdr) + tcp_hdr_len + payload_len;
}


void send_packet(int sockfd, unsigned char *packet, int len,
                 const char *iface, unsigned char *dst_mac)
{
    struct sockaddr_ll dev = {0};
    dev.sll_ifindex = if_nametoindex(iface);
    dev.sll_halen = ETH_ALEN;
    memcpy(dev.sll_addr, dst_mac, 6);

    sendto(sockfd, packet, len, 0,
           (struct sockaddr *)&dev, sizeof(dev));
}


int main()
{
    srand(time(NULL));

    const char *iface = "eth0";
    unsigned char src_mac[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
    unsigned char dst_mac[6];

    const char *src_ip = "192.168.1.2";
    const char *dst_ip = "192.168.1.3";

    int src_port = 12345;
    int dst_port = 80;

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) { perror("socket"); return 1; }

    printf("Resolving ARP...\n");
    if (arp_resolve(sockfd, iface, src_mac, dst_mac, dst_ip) < 0)
        return 1;

    printf("Target MAC: "); print_mac(dst_mac);

    unsigned char packet[1500];
    memset(packet, 0, sizeof(packet));

    printf("Sending SYN with MSS option...\n");

    int len = build_tcp_packet(packet,
                               src_mac, dst_mac,
                               src_ip, dst_ip,
                               src_port, dst_port,
                               1, 0, NULL,
                               1);  // add MSS option

    send_packet(sockfd, packet, len, iface, dst_mac);

    close(sockfd);
    return 0;
}
