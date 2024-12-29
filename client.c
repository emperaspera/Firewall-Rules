#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define BUFFERLENGTH 256

void error(const char *msg) {
    perror(msg);
    exit(1);
}

void send_request(int sockfd, const char *message) {
    ssize_t n = write(sockfd, message, strlen(message));
    if (n < 0) {
        error("ERROR writing message to socket");
    }
}

char *receive_response(int sockfd) {
    char *buffer = malloc(BUFFERLENGTH);
    if (buffer == NULL) {
        error("Memory allocation failed");
    }

    ssize_t n = read(sockfd, buffer, BUFFERLENGTH - 1);
    if (n < 0) {
        free(buffer);  // Free buffer on error
        error("ERROR reading message from socket");
    }
    buffer[n] = '\0';
    return buffer;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <serverHost> <serverPort> <command> [parameters]\n", argv[0]);
        exit(1);
    }

    const char *host = argv[1];
    const char *port = argv[2];
    char message[BUFFERLENGTH] = {0};

    // Concatenate command and parameters to form the message without needing quotes
    for (int i = 3; i < argc; i++) {
        strncat(message, argv[i], BUFFERLENGTH - strlen(message) - 1);
        if (i < argc - 1) {
            strncat(message, " ", BUFFERLENGTH - strlen(message) - 1);
        }
    }

    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        error("ERROR resolving address");
    }

    int sockfd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) continue;
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1) break;
        close(sockfd);
    }
    freeaddrinfo(res);

    if (rp == NULL) {
        error("ERROR connecting to server");
    }

    send_request(sockfd, message);
    char *response = receive_response(sockfd);
    printf("%s\n", response);

    free(response);
    close(sockfd);
    return 0;
}
