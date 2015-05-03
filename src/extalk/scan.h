#include <netdb.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define DEBUG   1
#define TIMEOUT 2 /*seconds*/
#define TARGET_PORT "54321"
#define PAYLOAD_SIZE 900
#define MAX_RESPONSE_SIZE 4096

int scan(char* host, const char* payload);
