#define IFNAMSIZ 16  // max interface name length

struct ifreq {
    char ifr_name[IFNAMSIZ];  // interface name, e.g., "eth0"

    union {
        struct sockaddr ifr_addr;       // for SIOCGIFADDR / SIOCSIFADDR
        struct sockaddr ifr_dstaddr;    // destination address
        struct sockaddr ifr_broadaddr;  // broadcast address
        struct sockaddr ifr_netmask;    // netmask
        struct sockaddr ifr_hwaddr;     // hardware/MAC address
        short           ifr_flags;      // interface flags
        int             ifr_ifindex;    // interface index
        int             ifr_metric;     // metric
        int             ifr_mtu;        // MTU
        char            ifr_slave[IFNAMSIZ];
        char            ifr_newname[IFNAMSIZ];
        char           *ifr_data;
    };
};
