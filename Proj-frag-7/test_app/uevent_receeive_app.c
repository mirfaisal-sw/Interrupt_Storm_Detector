
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define NL_MAX_PAYLOAD 8192

int main () {
    int nl_socket;
    struct sockaddr_nl src_addr;
    char msg[NL_MAX_PAYLOAD];
    int ret;

    // Prepare source address
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = -1;

    nl_socket = socket(AF_NETLINK, (SOCK_DGRAM | SOCK_CLOEXEC),      NETLINK_KOBJECT_UEVENT);
    if (nl_socket < 0) {
        printf("Failed to create socket for DeviceFinder");
        exit(1);
    }

    ret = bind(nl_socket, (struct sockaddr*) &src_addr, sizeof(src_addr));
    if (ret) {
        printf("Failed to bind netlink socket..");
        close(nl_socket);
        return 1;
    }

    printf("Waiting for events now...\n");
    while (1) {
        int r = recv(nl_socket, msg, sizeof(msg), MSG_DONTWAIT);
        if (r == -1)
            continue;
        if (r < 0) {
            perror("");
            continue;
        }
        printf("length:%i\n msg:%s", r, msg);

    }
}


