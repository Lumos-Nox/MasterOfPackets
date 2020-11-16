#include <stdio.h>
#include <winsock2.h>

#define PORT 31143
#define BUFLEN 256

int main(int argc, const char * argv[]) {
    unsigned int s, clientSocket;
    struct sockaddr_in sin;
    char recvMsg[BUFLEN], sendMsg[BUFLEN];
    WSADATA wsaData;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup() failed: %d\n", WSAGetLastError());
        exit(1);
    }

    // Create a socket for listening for incoming connection requests
    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        exit(1);
    }

    // Setup address structure
    memset((char *) &sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(PORT);

    // Bind
    if (bind(s, (struct sockaddr *) &sin, sizeof(sin)) == SOCKET_ERROR) {
        printf("bind() failed: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        exit(1);
    }

    // Listen
    if (listen(s, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen() failed: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        exit(1);
    }

    printf("Listening on socket [%s:%d]....\n", "0.0.0.0", PORT);

    // Accept a client socket
    if ((clientSocket = accept(s, NULL, NULL)) == INVALID_SOCKET) {
        printf("accept() failed: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        exit(1);
    }

    // No longer need server socket
    closesocket(s);

    while (1) {
        memset(recvMsg, '\0', BUFLEN);
        if (recv(clientSocket, recvMsg, BUFLEN, 0) == SOCKET_ERROR) {
            printf("recv() failed: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            WSACleanup();
            exit(1);
        }
        printf("MESSAGE [%s] FROM [%s:%d]\n", recvMsg,
               inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

        if (strcmp(recvMsg, "bye") == 0) break;

        memset(sendMsg, '\0', BUFLEN);
        strcpy(sendMsg, "I RECEIVED \"");
        strcpy(sendMsg + strlen(sendMsg), recvMsg);
        strcpy(sendMsg + strlen(sendMsg), "\"");
        if (send(clientSocket, sendMsg, strlen(sendMsg), 0) == SOCKET_ERROR) {
            printf("send() failed: %d\n", WSAGetLastError());
            closesocket(clientSocket);
            WSACleanup();
            exit(1);
        }
    }

    closesocket(clientSocket);
    WSACleanup();

    return 0;
}
