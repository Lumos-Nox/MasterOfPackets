#include <stdio.h>
#include <winsock2.h>

#define DSTIP "13.225.141.222"
#define URL "www.neverssl.com"
//#define DSTIP "93.184.216.34"
//#define URL "www.example.com"
#define DSTPORT 80
#define BUFLEN 4096

int main(int argc, const char * argv[]) {
    unsigned int s;
    struct sockaddr_in dest;
    char *reqMsg, recvMsg[BUFLEN], data[BUFLEN];
    FILE *f;
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

    // Send HTTP request message
    reqMsg = "GET / HTTP/1.1\r\n"
             "Host: "URL"\r\n"
             "Connection: close\r\n"
             "\r\n";
    if (send(s, reqMsg, strlen(reqMsg), 0) == SOCKET_ERROR) {
        printf("send() failed: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        exit(1);
    }

    // Receive server response (header & body)
    memset(recvMsg, '\0', BUFLEN);
    int i = 0, len;
    while ((len = recv(s, recvMsg, BUFLEN, 0)) > 0) {
        memcpy(data + i, recvMsg, len);
        i += len;
    }
    data[i] = '\0';

    closesocket(s);
    WSACleanup();

    f = fopen("x.html", "w+");
    if (f == NULL) {
        printf("Failed to open file\n");
        exit(1);
    }
    fputs(strstr(data, "\r\n\r\n") + 4, f);
    fclose(f);

    return 0;
}
