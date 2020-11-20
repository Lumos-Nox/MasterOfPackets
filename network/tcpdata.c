#include <stdio.h>
#include <winsock2.h>
#include <pcap.h>

#define SRCIP "192.168.1.132"
#define DSTIP "192.168.1.177"
#define SRCPORT 31143
#define DSTPORT 4869
#define PACKETSIZE 4096

typedef struct ether {
    unsigned char dst[6];
    unsigned char src[6];
    unsigned short type;
} etherHdr;

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
int craftTCP(etherHdr *eh, ipHdr *iph, tcpHdr *tcph, int flag, int recvSeqNo,
             int recvAckNo);
pcap_t * openNetworkDevice();
unsigned char *data;

int main(int argc, char *argv[]) {
    unsigned char packet[PACKETSIZE] = {0};
    etherHdr *eh = (etherHdr *) packet;
    ipHdr *iph = (ipHdr *) &packet[sizeof(etherHdr)], *iphx;
    tcpHdr *tcph = (tcpHdr *) &packet[sizeof(etherHdr) + sizeof(ipHdr)], *tcphx;
    data = &packet[sizeof(etherHdr) + sizeof(ipHdr) + sizeof(tcpHdr)];
    int len, result;
    struct pcap_pkthdr *pktHdr;
    const unsigned char *pktData;

    pcap_t *adhandle = openNetworkDevice();

    memset(packet, 0, PACKETSIZE);

    // Send SYN (SYN_SENT)
    len = craftTCP(eh, iph, tcph, 0, 0, 0);
    pcap_sendpacket(adhandle, packet, len);

    while ((result = pcap_next_ex(adhandle, &pktHdr, &pktData)) >= 0) {
        if (result == 0) continue;
        // Capture SYN-ACK
        iphx = (ipHdr *) (pktData + 14);
        tcphx = (tcpHdr *) (pktData + 34);
        if (iphx->src == inet_addr(DSTIP) && ntohs(tcphx->dstPort) == SRCPORT
            && tcphx->syn == 1 && tcphx->ack == 1) break;
    }

    // Send ACK after receiving SYN-ACK (ESTABLISHED)
    len = craftTCP(eh, iph, tcph, 1, ntohl(tcphx->seq), ntohl(tcphx->ackSeq));
    pcap_sendpacket(adhandle, packet, len);
    printf("Connection [ESTABLISHED]\n");

    Sleep(1000);

    // Send data
    len = craftTCP(eh, iph, tcph, 3, ntohl(tcphx->seq), ntohl(tcphx->ackSeq));
    pcap_sendpacket(adhandle, packet, len);

    while ((result = pcap_next_ex(adhandle, &pktHdr, &pktData)) >= 0) {
        if (result == 0) continue;
        // Capture ACK
        iphx = (ipHdr *) (pktData + 14);
        tcphx = (tcpHdr *) (pktData + 34);
        if (iphx->src == inet_addr(DSTIP) && ntohs(tcphx->dstPort) == SRCPORT
            && tcphx->ack == 1) break;
    }

    // Send FIN-ACK
    len = craftTCP(eh, iph, tcph, 2, ntohl(tcphx->seq) - 1, ntohl(tcphx->ackSeq));
    pcap_sendpacket(adhandle, packet, len);

    while ((result = pcap_next_ex(adhandle, &pktHdr, &pktData)) >= 0) {
        if (result == 0) continue;
        // Capture FIN-ACK (LAST_ACK)
        iphx = (ipHdr *) (pktData + 14);
        tcphx = (tcpHdr *) (pktData + 34);
        if (iphx->src == inet_addr(DSTIP) && ntohs(tcphx->dstPort) == SRCPORT
            && tcphx->ack == 1 && tcphx->fin == 1) break;
    }

    // Send ACK after receiving FIN-ACK (CLOSED)
    len = craftTCP(eh, iph, tcph, 1, ntohl(tcphx->seq), ntohl(tcphx->ackSeq));
    pcap_sendpacket(adhandle, packet, len);
    printf("Connection [CLOSED]\n");

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

int craftTCP(etherHdr *eh, ipHdr *iph, tcpHdr *tcph, int flag, int recvSeqNo,
             int recvAckNo) {
    // Data
    char msg[] = "Goodnight, Miss Anmingle^^";
    size_t msgLen = strlen(msg);
    memcpy(data, msg, msgLen);

    // Ethernet header
    eh->dst[0] = 0x8c; eh->dst[1] = 0xdc; eh->dst[2] = 0xd4;
    eh->dst[3] = 0x32; eh->dst[4] = 0x82; eh->dst[5] = 0x34;
    eh->src[0] = 0xd8; eh->src[1] = 0xcb; eh->src[2] = 0x8a;
    eh->src[3] = 0xd8; eh->src[4] = 0xfb; eh->src[5] = 0x7d;
    eh->type = htons(0x0800);

    // IP header
    iph->version = 4;
    iph->headerLength = 5;
    iph->typeOfService = 0;
    iph->totalLength = htons(sizeof(ipHdr) + sizeof(tcpHdr));
    if (flag == 3) iph->totalLength = htons(sizeof(ipHdr) + sizeof(tcpHdr) + msgLen);
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
    if (flag == 0) { // SYN
        tcph->seq = htonl(0xffffffff);
        tcph->ackSeq = htonl(0);
        tcph->ack = 0;
        tcph->syn = 1;
    } else if (flag == 1 || flag == 2 || flag == 3) { // ACK or FIN-ACK or PSH-ACK
        tcph->seq = htonl(recvAckNo);
        tcph->ackSeq = htonl(recvSeqNo + 1);
        tcph->ack = 1;
        tcph->syn = 0;
    } else exit(1);
    tcph->dataOffset = 5;
    tcph->reserved = 0;
    tcph->cwr = 0;
    tcph->ece = 0;
    tcph->urg = 0;
    tcph->psh = flag == 3 ? 1 : 0;
    tcph->rst = 0;
    tcph->fin = flag == 2 ? 1 : 0;
    tcph->windowSize = htons(65535);
    tcph->checksum = 0;
    tcph->urgentPointer = 0;

    // Pseudo header
    pseudoHdr ph;
    ph.src = iph->src;
    ph.dst = iph->dst;
    ph.zeros = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcpLength = flag != 3 ? htons(sizeof(tcpHdr)) : htons(sizeof(tcpHdr) + msgLen);
    ph.tcph = *tcph;
    char buf[1024];
    memcpy(buf, &ph, sizeof(pseudoHdr));
    if (flag == 3) memcpy(buf + sizeof(pseudoHdr), data, msgLen);

    tcph->checksum = csum((unsigned short *) buf, sizeof(pseudoHdr));
    if (flag == 3) {
        tcph->checksum = csum((unsigned short *) buf, sizeof(pseudoHdr) + msgLen);
        return sizeof(etherHdr) + sizeof(ipHdr) + sizeof(tcpHdr) + msgLen;
    }

    return sizeof(etherHdr) + sizeof(ipHdr) + sizeof(tcpHdr);
}

pcap_t * openNetworkDevice() {
    pcap_if_t *alldevs, *d;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve all network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs() failed: %s\n", errbuf);
        exit(1);
    }

    // Print all network devices
    int i = 0;
    for (d = alldevs; d; d = d->next)
        printf("%d. %s\n", ++ i, d->description);
    if (i == 0) {
        printf("No interface found.");
        exit(1);
    }

    // Choose a network device
    int inum;
    printf("Choose a network device (1-%d): ", i);
    scanf("%d", &inum);
    if (inum < 1 || inum > i) {
        printf("Invalid device number.\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i ++);

    // Open the network device
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "Failed to open the adapter: %s.\n", d->name);
        pcap_freealldevs(alldevs);
        exit(1);
    }

    pcap_freealldevs(alldevs);

    return adhandle;
}
