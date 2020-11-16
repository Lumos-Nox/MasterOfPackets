#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define SRCIP "192.168.1.132"
#define DSTIP "192.168.1.177"
#define SRCPORT 31143
#define DSTPORT 4869
#define PACKETSIZE 4096

typedef struct ip {
    unsigned char headerLength:4, version:4;
    unsigned char typeOfService;
    unsigned short totalLength;
    unsigned short id;
    unsigned short fragmentOffset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short headerChecksum;
    unsigned int src;
    unsigned int dst;
} ipHdr;

typedef struct udp {
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned short totalLength;
    unsigned short checksum;
} udpHdr;

typedef struct pseudo {
    unsigned int src;
    unsigned int dst;
    unsigned char zeros;
    unsigned char protocol;
    unsigned short udpLength;
    udpHdr udph;
} pseudoHdr;

unsigned short csum(unsigned short *buf, int size);
int craftUDP(ipHdr *iph, udpHdr *udph, char *data);

int main(int argc, const char * argv[]) {
    struct sockaddr_in dest;
    unsigned int s;
    char packet[PACKETSIZE];
    ipHdr *iph = (ipHdr *) packet;
    udpHdr *udph = (udpHdr *) &packet[sizeof(ipHdr)];
    char *data = &packet[sizeof(ipHdr) + sizeof(udpHdr)];
    WSADATA wsaData;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup() failed: %d\n", WSAGetLastError());
        exit(1);
    }

    // Create socket
    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == SOCKET_ERROR) {
        printf("socket() failed: %d\n", WSAGetLastError());
        exit(1);
    }

    // Set the IP_HDRINCL flag
    int on = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *) &on, sizeof(on)) < 0) {
        printf("setsockopt() failed: %d\n", WSAGetLastError());
        exit(1);
    }

    // Setup address structure
    memset((char *) &dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DSTPORT);
    dest.sin_addr.S_un.S_addr = inet_addr(DSTIP);

    // Craft UDP
    memset(packet, 0, PACKETSIZE);
    int len = craftUDP(iph, udph, data);

    if (sendto(s, packet, len, 0,
               (struct sockaddr *) &dest, sizeof(dest)) < 0) {
        printf("sendto() failed: %d\n", WSAGetLastError());
        exit(1);
    }

    closesocket(s);
    WSACleanup();

    return 0;
}

unsigned short csum(unsigned short *buf, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buf ++;
        size -= sizeof(unsigned short);
    }
    if (size) cksum += *(char *) buf;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short) (~cksum);
}

int craftUDP(ipHdr *iph, udpHdr *udph, char *data) {
    // Data
    char msg[] = "Goodnight, Miss Anmingle^^";
    size_t msgLen = strlen(msg);
    memcpy(data, msg, msgLen);

    // IP header
    iph->version = 4;
    iph->headerLength = 5;
    iph->typeOfService = 0;
    iph->totalLength = htons(sizeof(ipHdr) + sizeof(udpHdr) + msgLen);
    iph->id = htons(31143);
    iph->fragmentOffset = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->headerChecksum = 0;
    iph->src = inet_addr(SRCIP);
    iph->dst = inet_addr(DSTIP);

    iph->headerChecksum = csum((unsigned short *) iph, sizeof(ipHdr));

    // UDP header
    udph->srcPort = htons(SRCPORT);
    udph->dstPort = htons(DSTPORT);
    udph->totalLength = htons(sizeof(udpHdr) + msgLen);
    udph->checksum = 0;

    // Pseudo header
    pseudoHdr ph;
    ph.src = iph->src;
    ph.dst = iph->dst;
    ph.zeros = 0;
    ph.protocol = IPPROTO_UDP;
    ph.udpLength = udph->totalLength;
    ph.udph = *udph;
    char buf[1024];
    memcpy(buf, &ph, sizeof(pseudoHdr));
    memcpy(buf + sizeof(pseudoHdr), data, msgLen);

    udph->checksum = csum((unsigned short *) buf, sizeof(pseudoHdr) + msgLen);

    return sizeof(ipHdr) + sizeof(udpHdr) + msgLen;
}
