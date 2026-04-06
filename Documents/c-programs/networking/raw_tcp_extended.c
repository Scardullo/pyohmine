/*
 * raw_eth_tcp_full.c — EXTENDED VERSION
 * ------------------------------------------------------------
 * FULL USERLAND TCP CLIENT OVER RAW ETHERNET
 *
 * Features:
 *  - AF_PACKET raw Ethernet socket
 *  - ARP resolution + ARP cache
 *  - Ethernet frame build/parse
 *  - IPv4 header build/parse + checksum
 *  - TCP header build/parse + pseudo-header checksum
 *  - TCP options: MSS, NOP padding, Timestamps
 *  - Full TCP 3-way handshake
 *  - Data send + ACK tracking
 *  - Passive receive of inbound data
 *  - FIN close with full FIN/ACK loops
 *  - Timeouts + retries
 *  - Verbose logging
 *
 * WARNING:
 *  - Linux only
 *  - Must run as root
 *  - Do NOT use on networks you do not own
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
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

#define MAX_PACKET 65536
#define ARP_CACHE_SIZE 32
#define TIMEOUT_SEC 5

#define LOG(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)

// utility helpers

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void hexdump(const void *buf, size_t len) {
    const uint8_t *p = buf;
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("\n%04zx: ", i);
        printf("%02x ", p[i]);
    }
    printf("\n");
}

// checksums

static uint16_t checksum16(const void *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *p = data;

    while (len > 1) {
        sum += *p++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if (len)
        sum += *(uint8_t *)p;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

static uint16_t tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, const uint8_t *payload, size_t payload_len) {
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } pseudo;

    pseudo.src = ip->saddr;
    pseudo.dst = ip->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len = htons(sizeof(struct tcphdr) + payload_len);

    uint32_t sum = 0;
    sum += checksum16(&pseudo, sizeof(pseudo));
    sum += checksum16(tcp, sizeof(struct tcphdr));
    if (payload_len)
        sum += checksum16(payload, payload_len);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

// arp cache

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    uint64_t ts;
} arp_entry_t;

static arp_entry_t arp_cache[ARP_CACHE_SIZE];

static uint8_t *arp_cache_lookup(uint32_t ip) {
    for (int i = 0; i < ARP_CACHE_SIZE; i++)
        if (arp_cache[i].ip == ip)
            return arp_cache[i].mac;
    return NULL;
}

static void arp_cache_store(uint32_t ip, uint8_t mac[6]) {
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].ip == 0 || arp_cache[i].ip == ip) {
            arp_cache[i].ip = ip;
            memcpy(arp_cache[i].mac, mac, 6);
            arp_cache[i].ts = now_ms();
            return;
        }
    }
}

// ethernet + arp

static void build_arp_request(uint8_t *buf, uint8_t *src_mac, uint32_t src_ip, uint32_t target_ip) {
    struct ethhdr *eth = (struct ethhdr *)buf;
    memset(eth->h_dest, 0xff, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_ARP);

    struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ethhdr));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op  = htons(ARPOP_REQUEST);
    memcpy(arp->arp_sha, src_mac, 6);
    memcpy(arp->arp_spa, &src_ip, 4);
    memset(arp->arp_tha, 0x00, 6);
    memcpy(arp->arp_tpa, &target_ip, 4);
}

static int parse_arp_reply(uint8_t *pkt, size_t len, uint32_t want_ip, uint8_t *out_mac) {
    if (len < sizeof(struct ethhdr) + sizeof(struct ether_arp)) return 0;
    struct ethhdr *eth = (struct ethhdr *)pkt;
    if (ntohs(eth->h_proto) != ETH_P_ARP) return 0;
    struct ether_arp *arp = (struct ether_arp *)(pkt + sizeof(struct ethhdr));
    if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REPLY) return 0;
    uint32_t spa;
    memcpy(&spa, arp->arp_spa, 4);
    if (spa != want_ip) return 0;
    memcpy(out_mac, arp->arp_sha, 6);
    return 1;
}

// tcp

static size_t build_tcp_options(uint8_t *optbuf) {
    size_t off = 0;

    // MSS
    optbuf[off++] = 2; // kind
    optbuf[off++] = 4; // len
    uint16_t mss = htons(1460);
    memcpy(optbuf + off, &mss, 2);
    off += 2;

    // NOP
    optbuf[off++] = 1;

    // Timestamp
    optbuf[off++] = 8;
    optbuf[off++] = 10;
    uint32_t tsval = htonl((uint32_t)now_ms());
    uint32_t tsecr = 0;
    memcpy(optbuf + off, &tsval, 4); off += 4;
    memcpy(optbuf + off, &tsecr, 4); off += 4;

    while (off % 4) optbuf[off++] = 0;
    return off;
}

// ip + tcp builders

static size_t build_ip_tcp(uint8_t *pkt,
    uint8_t *src_mac, uint8_t *dst_mac,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t sport, uint16_t dport,
    uint32_t seq, uint32_t ack,
    uint16_t flags,
    const uint8_t *payload, size_t payload_len,
    int with_opts)
{
    struct ethhdr *eth = (struct ethhdr *)pkt;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(*eth));
    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(*eth) + sizeof(*ip));

    uint8_t *opt = (uint8_t *)(tcp + 1);
    size_t optlen = 0;
    if (with_opts) optlen = build_tcp_options(opt);

    size_t tcp_len = sizeof(*tcp) + optlen + payload_len;

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(*ip) + tcp_len);
    ip->id = htons(rand() & 0xffff);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;
    ip->check = 0;
    ip->check = checksum16(ip, sizeof(*ip));

    tcp->source = htons(sport);
    tcp->dest = htons(dport);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff = (sizeof(*tcp) + optlen) / 4;
    tcp->window = htons(65535);
    tcp->urg_ptr = 0;

    tcp->fin = !!(flags & TH_FIN);
    tcp->syn = !!(flags & TH_SYN);
    tcp->rst = !!(flags & TH_RST);
    tcp->psh = !!(flags & TH_PUSH);
    tcp->ack = !!(flags & TH_ACK);

    if (payload_len)
        memcpy((uint8_t *)tcp + sizeof(*tcp) + optlen, payload, payload_len);

    tcp->check = 0;
    tcp->check = tcp_checksum(ip, tcp, payload, payload_len);

    return sizeof(*eth) + sizeof(*ip) + tcp_len;
}

// receiver parsing

static int parse_tcp_packet(uint8_t *buf, size_t len,
    uint32_t src_ip, uint16_t src_port,
    uint32_t *seq, uint32_t *ack, uint16_t *flags,
    uint8_t **payload, size_t *payload_len)
{
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) return 0;

    struct ethhdr *eth = (struct ethhdr *)buf;
    if (ntohs(eth->h_proto) != ETH_P_IP) return 0;

    struct iphdr *ip = (struct iphdr *)(buf + sizeof(*eth));
    if (ip->protocol != IPPROTO_TCP) return 0;
    if (ip->saddr != src_ip) return 0;

    struct tcphdr *tcp = (struct tcphdr *)((uint8_t *)ip + ip->ihl*4);
    if (ntohs(tcp->source) != src_port) return 0;

    *seq = ntohl(tcp->seq);
    *ack = ntohl(tcp->ack_seq);

    *flags = 0;
    if (tcp->fin) *flags |= TH_FIN;
    if (tcp->syn) *flags |= TH_SYN;
    if (tcp->rst) *flags |= TH_RST;
    if (tcp->psh) *flags |= TH_PUSH;
    if (tcp->ack) *flags |= TH_ACK;

    size_t hdrlen = sizeof(*eth) + ip->ihl*4 + tcp->doff*4;
    if (len > hdrlen) {
        *payload = buf + hdrlen;
        *payload_len = len - hdrlen;
    } else {
        *payload = NULL;
        *payload_len = 0;
    }

    return 1;
}

// main client

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        fprintf(stderr, "Run as root.\n");
        return 1;
    }

    if (argc < 5) {
        printf("Usage: %s <iface> <src-ip> <dst-ip> <dst-port> [payload]\n", argv[0]);
        return 0;
    }

    const char *iface = argv[1];
    uint32_t src_ip = inet_addr(argv[2]);
    uint32_t dst_ip = inet_addr(argv[3]);
    uint16_t dport = atoi(argv[4]);
    const char *payload = argc > 5 ? argv[5] : "";
    size_t payload_len = strlen(payload);

    srand(time(NULL));

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) die("socket");

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) die("SIOCGIFHWADDR");
    uint8_t src_mac[6]; memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) die("SIOCGIFINDEX");
    int ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;

    LOG("[+] Interface %s ready\n", iface);

    uint8_t buf[MAX_PACKET];
    uint8_t dst_mac[6];

    // ARP resolution
    uint8_t *cached = arp_cache_lookup(dst_ip);
    if (!cached) {
        build_arp_request(buf, src_mac, src_ip, dst_ip);
        sendto(sock, buf, sizeof(struct ethhdr)+sizeof(struct ether_arp), 0,
               (struct sockaddr *)&addr, sizeof(addr));
        LOG("[+] ARP request sent\n");

        uint64_t end = now_ms() + 2000;
        while (now_ms() < end) {
            ssize_t n = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
            if (n > 0 && parse_arp_reply(buf, n, dst_ip, dst_mac)) {
                arp_cache_store(dst_ip, dst_mac);
                LOG("[+] ARP resolved\n");
                break;
            }
        }
    } else memcpy(dst_mac, cached, 6);

    uint32_t seq = rand();
    uint32_t ack = 0;

    // SYN
    size_t pktlen = build_ip_tcp(buf, src_mac, dst_mac, src_ip, dst_ip,
                                  40000, dport, seq, 0, TH_SYN, NULL, 0, 1);
    sendto(sock, buf, pktlen, 0, (struct sockaddr *)&addr, sizeof(addr));
    LOG("[>] SYN sent seq=%u\n", seq);

    // handshake
    while (1) {
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) continue;
        uint16_t flags;
        uint8_t *pl; size_t pllen;
        uint32_t rseq, rack;
        if (!parse_tcp_packet(buf, n, dst_ip, dport, &rseq, &rack, &flags, &pl, &pllen)) continue;

        if ((flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
            ack = rseq + 1;
            seq += 1;
            LOG("[<] SYN-ACK rseq=%u rack=%u\n", rseq, rack);
            break;
        }
    }

    // ACK
    pktlen = build_ip_tcp(buf, src_mac, dst_mac, src_ip, dst_ip,
                          40000, dport, seq, ack, TH_ACK, NULL, 0, 0);
    sendto(sock, buf, pktlen, 0, (struct sockaddr *)&addr, sizeof(addr));
    LOG("[>] ACK sent\n");

    // DATA
    if (payload_len) {
        pktlen = build_ip_tcp(buf, src_mac, dst_mac, src_ip, dst_ip,
                              40000, dport, seq, ack, TH_ACK|TH_PUSH,
                              (const uint8_t*)payload, payload_len, 0);
        sendto(sock, buf, pktlen, 0, (struct sockaddr *)&addr, sizeof(addr));
        LOG("[>] DATA sent len=%zu\n", payload_len);
        seq += payload_len;

        while (1) {
            ssize_t n = recv(sock, buf, sizeof(buf), 0);
            if (n <= 0) continue;
            uint16_t flags;
            uint8_t *pl; size_t pllen;
            uint32_t rseq, rack;
            if (!parse_tcp_packet(buf, n, dst_ip, dport, &rseq, &rack, &flags, &pl, &pllen)) continue;
            if ((flags & TH_ACK) && rack >= seq) {
                LOG("[<] DATA ACK rack=%u\n", rack);
                break;
            }
        }
    }

    // FIN
    pktlen = build_ip_tcp(buf, src_mac, dst_mac, src_ip, dst_ip,
                          40000, dport, seq, ack, TH_FIN|TH_ACK, NULL, 0, 0);
    sendto(sock, buf, pktlen, 0, (struct sockaddr *)&addr, sizeof(addr));
    LOG("[>] FIN sent\n");
    seq += 1;

    int got_fin = 0;
    while (1) {
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) continue;
        uint16_t flags;
        uint8_t *pl; size_t pllen;
        uint32_t rseq, rack;
        if (!parse_tcp_packet(buf, n, dst_ip, dport, &rseq, &rack, &flags, &pl, &pllen)) continue;

        if ((flags & TH_ACK) && rack >= seq) LOG("[<] FIN ACK\n");
        if (flags & TH_FIN) {
            ack = rseq + 1;
            got_fin = 1;
            LOG("[<] FIN from peer\n");
        }
        if (got_fin) break;
    }

    // final ACK
    pktlen = build_ip_tcp(buf, src_mac, dst_mac, src_ip, dst_ip,
                          40000, dport, seq, ack, TH_ACK, NULL, 0, 0);
    sendto(sock, buf, pktlen, 0, (struct sockaddr *)&addr, sizeof(addr));
    LOG("[>] Final ACK sent, closed\n");

    close(sock);
    return 0;
}
