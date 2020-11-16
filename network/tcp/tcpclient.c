#include <stdio.h>
#include <winsock2.h>

#define DSTIP "192.168.1.168"
#define DSTPORT 31143
#define BUFLEN 256 /* Send at most 255 characters, 242 is recommended for
                      receiving normally [I RECEIVED ""] */

int main(int argc, const char * argv[]) {
    unsigned int s;
    struct sockaddr_in dest;
    char sendMsg[BUFLEN], recvMsg[BUFLEN];
    WSADATA wsaData;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup() failed: %d\n", WSAGetLastError());
        exit(1);
    }

    // Create socket
    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        exit(1);
    }

    // Setup address structure
    memset((char *) &dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(DSTIP);
    dest.sin_port = htons(DSTPORT);

    // Connect
    if (connect(s, (struct sockaddr *) &dest, sizeof(dest)) == SOCKET_ERROR) {
        printf("connect() failed: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        exit(1);
    }

    while (1) {
        printf("MESSAGE: ");
        gets(sendMsg);
        if (strlen(sendMsg) > BUFLEN - 14) {
            printf("MESSAGE TOO LONG");
            break;
        }
        if (send(s, sendMsg, strlen(sendMsg), 0) == SOCKET_ERROR) {
            printf("send() failed: %d\n", WSAGetLastError());
            closesocket(s);
            WSACleanup();
            exit(1);
        }

        if (strcmp(sendMsg, "bye") == 0) break;

        memset(recvMsg, '\0', BUFLEN);
        if (recv(s, recvMsg, BUFLEN, 0) == SOCKET_ERROR) {
            printf("recv() failed: %d\n", WSAGetLastError());
            closesocket(s);
            WSACleanup();
            exit(1);
        }
        printf("REPLY [%s]\n\n", recvMsg);
    }

    closesocket(s);
    WSACleanup();

    return 0;
}
