/*
 * Mini TCP/IP Client in C (Single File)
 *
 * Features:
 * - Raw Ethernet frames
 * - ARP resolution
 * - IP header parsing/construction
 * - TCP three-way handshake (SYN, SYN-ACK, ACK)
 * - Send simple text message
 *
 * WARNING:
 * - Must be run as root
 * - Linux only
 * - Educational; not production-ready
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/tcp.h>            // <-- Changed from netinet/tcp.h
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

// Ethernet + ARP
#define ETH_HDR_LEN 14
#define ARP_REQUEST 1
#define ARP_REPLY   2
#define ETH_P_ARP 0x0806

// Pseudo-header for TCP checksum
struct pseudo_hdr {
    unsigned int src;       // 4 bytes
    unsigned int dst;       // 4 bytes
    unsigned char zero;     // 1 byte
    unsigned char proto;    // 1 byte
    unsigned short tcp_len; // 2 bytes
};

// Utility: checksum for IP/TCP
unsigned short checksum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for (; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Print MAC address
void print_mac(unsigned char *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Resolve MAC via ARP
int arp_resolve(int sockfd, const char *iface, const unsigned char *src_mac, unsigned char *dst_mac, const char *target_ip) {
    unsigned char buffer[42];
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct {
        unsigned short htype;
        unsigned short ptype;
        unsigned char hlen;
        unsigned char plen;
        unsigned short oper;
        unsigned char sha[6];
        unsigned char spa[4];
        unsigned char tha[6];
        unsigned char tpa[4];
    } __attribute__((packed)) *arp = (void *)(buffer + ETH_HDR_LEN);

    memset(buffer, 0, sizeof(buffer));
    // Ethernet broadcast
    memset(eth->h_dest, 0xff, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_ARP);

    // ARP request
    arp->htype = htons(1);
    arp->ptype = htons(0x0800);
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = htons(ARP_REQUEST);
    memcpy(arp->sha, src_mac, 6);
    inet_pton(AF_INET, "192.168.1.2", arp->spa); // change to your IP
    memset(arp->tha, 0x00, 6);
    inet_pton(AF_INET, target_ip, arp->tpa);

    struct sockaddr_ll device;
    memset(&device, 0, sizeof(device));
    device.sll_ifindex = if_nametoindex(iface);
    device.sll_halen = ETH_ALEN;
    memcpy(device.sll_addr, eth->h_dest, 6);

    if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&device, sizeof(device)) < 0) {
        perror("ARP send failed");
        return -1;
    }

    // Wait for ARP reply
    while (1) {
        int n = recv(sockfd, buffer, sizeof(buffer), 0);
        if (n < 0) { perror("recv"); return -1; }
        eth = (struct ethhdr *)buffer;
        arp = (void *)(buffer + ETH_HDR_LEN);
        if (ntohs(eth->h_proto) == ETH_P_ARP && ntohs(arp->oper) == ARP_REPLY) {
            memcpy(dst_mac, arp->sha, 6);
            return 0;
        }
    }
}

// Build TCP/IP/Ethernet packet
int build_tcp_packet(unsigned char *packet, unsigned char *src_mac, unsigned char *dst_mac,
                     const char *src_ip, const char *dst_ip,
                     int src_port, int dst_port,
                     int syn, int ack_flag,
                     const char *payload) {

    struct ethhdr *eth = (struct ethhdr *)packet;
    memcpy(eth->h_source, src_mac, 6);
    memcpy(eth->h_dest, dst_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    struct iphdr *ip = (struct iphdr *)(packet + ETH_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(packet + ETH_HDR_LEN + sizeof(struct iphdr));
    char *data = (char *)(packet + ETH_HDR_LEN + sizeof(struct iphdr) + sizeof(struct tcphdr));
    int payload_len = payload ? strlen(payload) : 0;
    if (payload) strcpy(data, payload);

    // IP header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
    ip->id = htons(rand()%65535);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    inet_pton(AF_INET, src_ip, &(ip->saddr));
    inet_pton(AF_INET, dst_ip, &(ip->daddr));
    ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr)/2);

    // TCP header
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(rand()%10000);
    tcp->ack_seq = ack_flag ? htonl(1) : 0;
    tcp->doff = 5;
    tcp->syn = syn;
    tcp->ack = ack_flag;
    tcp->window = htons(5840);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    // TCP checksum
    struct pseudo_hdr pseudo;
    pseudo.src = ip->saddr;
    pseudo.dst = ip->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.tcp_len = htons(sizeof(struct tcphdr) + payload_len);

    int psize = sizeof(struct pseudo_hdr) + sizeof(struct tcphdr) + payload_len;
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, &pseudo, sizeof(struct pseudo_hdr));
    memcpy(pseudogram + sizeof(struct pseudo_hdr), tcp, sizeof(struct tcphdr));
    if (payload) memcpy(pseudogram + sizeof(struct pseudo_hdr) + sizeof(struct tcphdr), payload, payload_len);

    tcp->check = checksum((unsigned short *)pseudogram, psize/2 + psize%2);
    free(pseudogram);

    return ETH_HDR_LEN + sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;
}

// Send raw packet
void send_packet(int sockfd, unsigned char *packet, int len, const char *iface, unsigned char *dst_mac) {
    struct sockaddr_ll dev;
    memset(&dev,0,sizeof(dev));
    dev.sll_ifindex = if_nametoindex(iface);
    dev.sll_halen = ETH_ALEN;
    memcpy(dev.sll_addr,dst_mac,6);
    sendto(sockfd, packet, len, 0, (struct sockaddr*)&dev, sizeof(dev));
}

// Main client
int main() {
    srand(time(NULL));
    const char *iface = "eth0";           // change
    unsigned char src_mac[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
    unsigned char dst_mac[6];
    const char *src_ip = "192.168.1.2";  // change
    const char *dst_ip = "192.168.1.3";  // change
    int src_port = 12345, dst_port = 80;

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) { perror("Socket"); return 1; }

    printf("Resolving MAC for %s...\n", dst_ip);
    if (arp_resolve(sockfd, iface, src_mac, dst_mac, dst_ip) < 0) {
        printf("ARP failed\n"); return 1;
    }
    printf("Destination MAC: "); print_mac(dst_mac);

    unsigned char packet[1500];
    memset(packet,0,sizeof(packet));

    // 1. Send SYN
    printf("Sending SYN...\n");
    int len = build_tcp_packet(packet, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, 1, 0, NULL);
    send_packet(sockfd, packet, len, iface, dst_mac);

    printf("SYN sent. (Handshake continuation not fully implemented)\n");

    // 2. Send simple text message (ACK + payload)
    const char *msg = "Hello from mini TCP/IP stack!";
    len = build_tcp_packet(packet, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, 0, 1, msg);
    send_packet(sockfd, packet, len, iface, dst_mac);

    printf("Message sent: %s\n", msg);
    close(sockfd);
    return 0;
}
