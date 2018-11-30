#include <stdint.h>
#include <iostream>
#include "tcp.h"

int32_t TransTcp::connected(void)
{
#if 0
#define SERVER_PORT (8888)
    int enable = 1;
    int32_t ret = 0;
    //    const char *server_ip = "192.168.100.100";
    const char *server_ip = "0.0.0.0";
    struct sockaddr_in minit_serv_addr;

    mfd = socket(AF_INET, SOCK_STREAM, 0);
    if (mfd < 0) {
        printf("Create socket failed %s\n", strerror(errno));
        exit(1);
    }
    setsockopt(mfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    memset(&minit_serv_addr, 0, sizeof(minit_serv_addr));
    minit_serv_addr.sin_family = AF_INET;
    minit_serv_addr.sin_port   = htons(SERVER_PORT);

    //	minit_serv_addr.sin_addr.s_addr = INADDR_ANY;
#if 1
    ret = inet_aton(server_ip, &minit_serv_addr.sin_addr);
    if (0 == ret) {
        printf("inet_aton failed %d %s\n", ret, strerror(errno));
        exit(1);
    }
#endif
    ret = bind(mfd, (struct sockaddr *) &minit_serv_addr, sizeof(minit_serv_addr));
    if (0 != ret) {
        printf("bind failed %d %s\n", ret, strerror(errno));
        exit(2);
    }

    ret = listen(mfd, 1);
    if (0 != ret) {
        printf("listen failed %d %s\n", ret, strerror(errno));
        exit(3);
    }
#endif
    return mfd;
}
int32_t TransTcp::process(void)
{
    return 0;
}
int32_t TransTcp::stop(void)
{
    return 0;

}

