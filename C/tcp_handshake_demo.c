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
	uint8_t  zero, proto;
	uint16_t len;
    } ph;

    ph.src = ip->saddr;
    ph.dst = ip->daddr;
    ph.zero = 0;
    ph.proto = IPPROTO_TCP;
    ph.len = htons(sizeof(struct tcphdr) + plen);
    uint8_t *buf = calloc(1, total);

    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), tcp, sizeof(struct tcphdr));
    if (plen) memcpy(buf + sizeof(ph) + sizeof(struct tcphdr), payload, plen);

    uint16_t sum = checksum(buf, total);
    free(buf);
    return sum;
}

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

struct arp_apcket {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
}__attribute__((packed));

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
	if (ntohs(rarp->oper) == 2 && memcmp(rarp->spa, arp->tpa, 4) == 0) {
	    memcpy(out_mac, rarp->sha, 6);
	    return 0;
	}
    }
}

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
}
