#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define SRCIP "192.168.1.132"
#define DSTIP "192.168.1.177"
#define SRCPORT 31143
#define DSTPORT 12345
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

typedef struct tcp {
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned int seq;
    unsigned int ackSeq;
    unsigned short reserved:4, dataOffset:4, fin:1, syn:1, rst:1, psh:1,
            ack:1, urg:1, ece:1, cwr:1;
    unsigned short windowSize;
    unsigned short checksum;
    unsigned short urgentPointer;
} tcpHdr;

typedef struct pseudo {
    unsigned int src;
    unsigned int dst;
    unsigned char zeros;
    unsigned char protocol;
    unsigned short tcpLength;
    tcpHdr tcph;
} pseudoHdr;

unsigned short csum(unsigned short *buf, int size);
int craftTCP(ipHdr *iph, tcpHdr *tcph, char *data);

int main(int argc, const char * argv[]) {
    struct sockaddr_in dest;
    unsigned int s;
    char packet[PACKETSIZE];
    ipHdr *iph = (ipHdr *) packet;
    tcpHdr *tcph = (tcpHdr *) &packet[sizeof(ipHdr)];
    char *data = &packet[sizeof(ipHdr) + sizeof(tcpHdr)];
    WSADATA wsaData;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup() failed: %d\n", WSAGetLastError());
        exit(1);
    }

    // TODO socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    // Create raw socket without any protocol-header inside
    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == SOCKET_ERROR) {
        printf("socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
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
    dest.sin_addr.s_addr = inet_addr(DSTIP);

    // Craft TCP
    memset(packet, 0, PACKETSIZE);
    int len = craftTCP(iph, tcph, data);

    if (sendto(s, packet, len, 0,
               (struct sockaddr *) &dest, sizeof(dest)) == SOCKET_ERROR) {
        printf("sendto() failed: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        exit(1);
    }

    // Shutdown

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

int craftTCP(ipHdr *iph, tcpHdr *tcph, char *data) {
    // Data
    char msg[] = "Goodnight, Miss Anmingle^^";
    size_t msgLen = strlen(msg);
    memcpy(data, msg, msgLen);

    // IP header
    iph->version = 4;
    iph->headerLength = 5;
    iph->typeOfService = 0;
    iph->totalLength = htons(sizeof(ipHdr) + sizeof(tcpHdr) + msgLen);
    iph->id = htons(31143);
    iph->fragmentOffset = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->headerChecksum = 0;
    iph->src = inet_addr(SRCIP);
    iph->dst = inet_addr(DSTIP);

    iph->headerChecksum = csum((unsigned short *) iph, sizeof(ipHdr));

    // TCP header
    tcph->srcPort = htons(SRCPORT);
    tcph->dstPort = htons(DSTPORT);
    tcph->seq = 0;
    tcph->ackSeq = 0;
    tcph->dataOffset = 5;
    tcph->reserved = 0;
    tcph->cwr = 0;
    tcph->ece = 0;
    tcph->urg = 0;
    tcph->ack = 0;
    tcph->psh = 0;
    tcph->rst = 0;
    tcph->syn = 1;
    tcph->fin = 0;
    tcph->windowSize = htons(1024);
    tcph->checksum = 0;
    tcph->urgentPointer = 0;

    // Pseudo header
    pseudoHdr ph;
    ph.src = iph->src;
    ph.dst = iph->dst;
    ph.zeros = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcpLength = htons(sizeof(tcpHdr) + msgLen);
    ph.tcph = *tcph;
    char buf[1024];
    memcpy(buf, &ph, sizeof(pseudoHdr));
    memcpy(buf + sizeof(pseudoHdr), data, msgLen);

    tcph->checksum = csum((unsigned short *) buf, sizeof(pseudoHdr) + msgLen);

    return sizeof(ipHdr) + sizeof(tcpHdr) + msgLen;
}
