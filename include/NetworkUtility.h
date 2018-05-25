//
// Created by kurox on 18-4-12.
//

#ifndef NETWORKUTILITY_H
#define NETWORKUTILITY_H

#include <cstdlib>
#include <iostream>
//#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <cstdio>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <string>
#include <sstream>
#include <sys/types.h>

using namespace std;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
// #define ETHER_ADDR_LEN    6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl; /* version << 4 | header length >> 2 */
    u_char ip_tos; /* type of service */
    u_short ip_len; /* total length */
    u_short ip_id; /* identification */
    u_short ip_off; /* fragment offset field */
#define IP_RF 0x8000 /* reserved fragment flag */
#define IP_DF 0x4000 /* dont fragment flag */
#define IP_MF 0x2000 /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    u_char ip_ttl; /* time to live */
    u_char ip_p; /* protocol */
    u_short ip_sum; /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq; /* sequence number */
    tcp_seq th_ack; /* acknowledgement number */
    u_char th_offx2; /* recv_playload offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

class NetworkUtility {
public:
/*
 * print recv_playload in rows of 16 bytes: offset hex ascii
 *
 * 00000 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a GET / HTTP/1.1..
 */
    static void print_hex_ascii_line(stringstream &ss, const u_char *payload, int len, int offset) {

        int i;
        int gap;
        const u_char *ch;
        char buffer[256];
        /* offset */
        sprintf(buffer, "%05d ", offset);
        ss << buffer;
        /* hex */
        ch = payload;
        for (i = 0; i < len; i++) {
            sprintf(buffer, "%02x ", *ch);
            ss << buffer;
            ch++;
            /* print extra space after 8th byte for visual aid */
            if (i == 7)
                ss << " ";
        }
        /* print space to handle line less than 8 bytes */
        if (len < 8)
            ss << " ";

        /* fill hex gap with spaces if not full line */
        if (len < 16) {
            gap = 16 - len;
            for (i = 0; i < gap; i++) {
                ss << "   ";
            }
        }
        ss << "\t";

        /* ascii (if printable) */
        ch = payload;
        for (i = 0; i < len; i++) {
            if (isprint(*ch)) {
                sprintf(buffer, "%c", *ch);
                ss << buffer;
            } else
                ss << ".";
            ch++;
        }

        ss << "\n";
    }

/*
 * print packet payload recv_playload (avoid printing binary recv_playload)
 */
    static void print_payload(stringstream &ss, const u_char *payload, int len) {

        int len_rem = len;
        int line_width = 16;            /* number of bytes per line */
        int line_len;
        int offset = 0;                    /* zero-based offset counter */
        const u_char *ch = payload;

        if (len <= 0)
            return;

        /* recv_playload fits on one line */
        if (len <= line_width) {
            print_hex_ascii_line(ss, ch, len, offset);
            return;
        }

        /* recv_playload spans multiple lines */
        for (;;) {
            /* compute current line length */
            line_len = static_cast<int>(line_width % len_rem);
            /* print line */
            print_hex_ascii_line(ss, ch, line_len, offset);
            /* compute total remaining */
            len_rem = len_rem - line_len;
            /* shift pointer to remaining bytes to print */
            ch = ch + line_len;
            /* add offset */
            offset = offset + line_width;
            /* check if we have line width chars or less */
            if (len_rem <= line_width) {
                /* print last line and get out */
                print_hex_ascii_line(ss, ch, len_rem, offset);
                break;
            }
        }

    }
};


#endif //NETWORKUTILITY_H
