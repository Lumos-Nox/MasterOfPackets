#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define SRC "127.0.0.1"
#define DST "127.0.0.1"
#define DATAGRAMSIZE 4096

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

unsigned short csum(unsigned short *buf, int size);
int craftIPv4(ipHdr *iph, char *payload);

int main(int argc, const char * argv[]) {
    struct sockaddr_in sin;
    unsigned int s;
    char datagram[DATAGRAMSIZE];
    ipHdr *iph = (ipHdr *) datagram;
    WSADATA wsaData;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup() failed: %d\n", WSAGetLastError());
        exit(1);
    }

    // Create socket
    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == SOCKET_ERROR) {
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
    memset((char *) &sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.S_un.S_addr = inet_addr(DST);

    // Craft IPv4
    memset(datagram, 0, DATAGRAMSIZE);
    char *payload = &datagram[sizeof(ipHdr)];
    int len = craftIPv4(iph, payload);

    if (sendto(s, datagram, len, 0,
               (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        printf("sendto() failed: %d\n", WSAGetLastError());
        exit(1);
    }

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

int craftIPv4(ipHdr *iph, char *payload) {
    // Payload
    char msg[] = "Hi, world!";
    size_t msgLen = strlen(msg);
    strcpy(payload, msg);

    // IP header
    iph->version = 4;
    iph->headerLength = 5;
    iph->typeOfService = 0;
    iph->totalLength = htons(sizeof(ipHdr) + msgLen);
    iph->id = htons(35329);
    iph->fragmentOffset = 0;
    iph->ttl = 255;
    iph->protocol = 0;
    iph->headerChecksum = 0;
    iph->src = inet_addr(SRC);
    iph->dst = inet_addr(DST);

    iph->headerChecksum = csum((unsigned short *) iph, sizeof(ipHdr));

    return sizeof(ipHdr) + msgLen;
}
