#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define RANDRANGE(min,max) (rand() % (max + 1 - min) + min)

#define APP_NAME        "sniffex"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>



#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "c-ipcrypt/ipcrypt.h"

/* default amount of packets to capture (-1 for infinite) */
#define NUM_PACKETS -1
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN    6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len);

void
print_app_usage(void);

/*
 * print help text
 */
void
print_app_usage(void)
{
    
    printf("Usage: %s [interface]\n", APP_NAME);
    printf("\n");
    printf("Options:\n");
    printf("    interface    Listen on <interface> for packets.\n");
    printf("\n");
    
    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{
    const u_char *ch = payload;
    
    if (len <= 0) {
        return;
    }
    
    int i;
    for(i = 0; i < MIN(len, 4); i++) {
        printf("%02X", *ch);
        ch++;
    }
    for(; i < 4; i++) {
        printf("00"); // Fill the gap
    }
    
    return;
}

/*
 * anonymize the given IP by applying a random XOR on it
 */
struct in_addr anonymize_ip(struct in_addr in_ip) {
    unsigned char bytes[4];
    bytes[0] = (in_ip.s_addr >> 24) & 0xFF;
    bytes[1] = (in_ip.s_addr >> 16) & 0xFF;
    bytes[2] = (in_ip.s_addr >> 8) & 0xFF;
    bytes[3] = in_ip.s_addr & 0xFF;
    
    unsigned char anon_bytes[4];
    unsigned char key[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    
    ipcrypt_encrypt(bytes, anon_bytes, key);
    
    struct in_addr anon_ip;
    anon_ip.s_addr |= anon_bytes[0] << 24;
    anon_ip.s_addr |= anon_bytes[1] << 16;
    anon_ip.s_addr |= anon_bytes[2] << 8;
    anon_ip.s_addr |= anon_bytes[3];
    return anon_ip;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static long first_timestamp = -1;
    if (first_timestamp == -1) {
        first_timestamp = time(NULL);
    }
    
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    
    int size_ip;
    int size_tcp;
    int size_payload;
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    
    /* determine protocol */
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            // printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }
    
    /*
     *  OK, this packet is TCP.
     */
    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    
    printf("%zu,", time(NULL) - first_timestamp); // timestamp
    printf("TCP,"); // protocol(TCP/UDP)
    printf("%d,", ntohs(ip->ip_tos)); // tos
    printf("%d,", ntohs(ip->ip_ttl)); // ttl
    printf("%08X,", anonymize_ip(ip->ip_src).s_addr);  // anonymized source ip
    printf("%s,", inet_ntoa(ip->ip_src)); // real source ip
    printf("%d,", ntohs(tcp->th_sport)); // src_port
    printf("%08X,", anonymize_ip(ip->ip_dst).s_addr); // anonymized destination ip
    printf("%s,", inet_ntoa(ip->ip_dst)); // real destination ip
    printf("%d,", ntohs(tcp->th_dport)); // dst_port
    printf("%d,", ntohs(tcp->th_seq)); // sequence
    printf("%d,", ntohs(tcp->th_win)); // window
    // Do *NOT* include the checksum in the trace, as it can leak the original src/dst IPs.
    
    printf( (tcp->th_flags & TH_URG) ? "1," : "0,"); // is_urg(0 or 1)
    printf( (tcp->th_flags & TH_ACK) ? "1," : "0,"); // is_ack(0 or 1)
    printf( (tcp->th_flags & TH_PUSH) ? "1," : "0,"); // is_push(0 or 1)
    printf( (tcp->th_flags & TH_RST) ? "1," : "0,"); // is_rst(0 or 1)
    printf( (tcp->th_flags & TH_SYN) ? "1," : "0,"); // is_syn(0 or 1)
    printf( (tcp->th_flags & TH_FIN) ? "1," : "0,"); // is_fin(0 or 1)
    
    /* define/compute tcp payload (segment) offset */
    const u_char *payload; /* Packet payload */
    
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    
    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    
    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
        print_payload(payload, size_payload);
    }
    
    printf("\n"); // The end.
    
    return;
}

void showIP()
{
    struct ifaddrs *ifaddr, *ifa;
    int s;
    char host[NI_MAXHOST];
    
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        
        s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        
        if( strcmp(ifa->ifa_name, "en0") == 0 && ifa->ifa_addr->sa_family == AF_INET )
        {
            if (s != 0)
            {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            printf("\tInterface : <%s>\n",ifa->ifa_name );
            printf("\t  Address : <%s>\n", host);
        }
    }
    
    freeifaddrs(ifaddr);
}


int main(int argc, char **argv)
{
    srand(time(NULL));
    char *dev = NULL;            /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
    pcap_t *handle;                /* packet capture handle */
    
    char filter_exp[] = "";        /* filter expression [3] */
    struct bpf_program fp;            /* compiled filter program (expression) */
    bpf_u_int32 mask;            /* subnet mask */
    bpf_u_int32 net;            /* ip */
    
    /* check for capture device name on command-line */
    if (argc == 2) {
        dev = argv[1];
    }
    else if (argc > 2) {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        print_app_usage();
        exit(EXIT_FAILURE);
    }
    else {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                    errbuf);
            exit(EXIT_FAILURE);
        }
    }
    
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }
    
    /* print capture info */
    printf("# Device: %s\n", dev);
    showIP();
    printf("# Filter expression: %s\n", filter_exp);
    
    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }
    
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }
    
    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    /* now we can set our callback function */
    pcap_loop(handle, NUM_PACKETS, got_packet, NULL);
    
    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
    
    printf("\nCapture complete.\n");
    
    return 0;
}
