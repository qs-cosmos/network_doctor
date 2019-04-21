#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


#include "system_sniffer.h"

// 封装 send() => 处理 errno 错误
int __wp_send(int fd, void *msg, size_t len, int flags) {
    int ret;
    do {
        ret = send(fd, msg, len, flags);
    } while ((ret == -1) && (errno == EINTR));
    return ret > 0 ? ret : 0;
}

// 封装 recv() => 处理 errno 错误
int __wp_recv(int fd, void *msg, size_t len, int flags) {
    int ret;
    do {
        ret = recv(fd, msg, len, flags);
    } while ((ret == -1) && (errno == EINTR));
    return ret;
}

char *__inet_addr (uint32_t ip) {
    struct in_addr addr = {
        .s_addr = htonl(ip)
    };
    return inet_ntoa(addr);
}

char *__inet_addr (uint32_t ip, char *__addr) {
    struct in_addr addr = {
        .s_addr = htonl(ip)
    };
    inet_ntop(AF_INET, &addr, __addr, INET_ADDRSTRLEN);
    return __addr;
}

/*
 * 报文截获 + 解构
 */

WpInet::WpInet(const u_char *datagram) {
    this->ip_h = NULL;
    if (datagram) {
        this->ip_h = IP_HEAD(datagram);
        // 调整字节存储方式 (网络 => 主机, 大端 or 小端)
        this->ip_h->tot_len = ntohs(this->ip_h->tot_len);
        this->ip_h->id = ntohs(this->ip_h->id);
        this->ip_h->frag_off = ntohs(this->ip_h->frag_off);
        this->ip_h->check = ntohs(this->ip_h->check);
        this->ip_h->saddr = ntohl(this->ip_h->saddr);
        this->ip_h->daddr = ntohl(this->ip_h->daddr);
    }
    // 运行时间
    this->runtime = 0;
}

WpInet::~WpInet() {
    if(this->ip_h) this->ip_h = NULL;
}

void WpInet::print() {
    if (!this->ip_h) return;
    printf("\n===========IP Protocol=========\n");
    printf("      Version: %d\n", this->ip_h->version);
    printf("Header Length: %d\n", this->ip_h->ihl * 4);
    printf("          TOS: %d\n", this->ip_h->tos);
    printf(" Total Length: %d\n", this->ip_h->tot_len);
    printf("           Id: %d\n", this->ip_h->id);
    printf("       Offset: %d\n", this->ip_h->frag_off);
    printf("          TTL: %d\n", this->ip_h->ttl);
    printf("     Checksum: %d\n",this->ip_h->check);
    printf("     Protocol: %d\n", this->ip_h->protocol);
    printf("     Src Addr: %s\n", __inet_addr(this->ip_h->saddr));
    printf("     Dst Addr: %s\n", __inet_addr(this->ip_h->daddr));
    printf("===========IP Protocol=========\n");
}

WpIcmp::WpIcmp(const u_char *datagram): WpInet(datagram) {
    this->icmp = datagram ? IP_ICMP(datagram) : NULL;
}

WpIcmp::~WpIcmp() {
    if(this->icmp) this->icmp = NULL;
}

void WpIcmp::print() {
    WpInet::print();
}

WpTcp::WpTcp(const u_char *datagram): WpInet(datagram) {
    this->tcp_h = NULL;
    if (datagram) {
        this->tcp_h = TCP_HEAD(datagram);
        this->tcp_h->source = ntohs(this->tcp_h->source);
        this->tcp_h->dest = ntohs(this->tcp_h->dest);
        this->tcp_h->seq = ntohl(this->tcp_h->seq);
        this->tcp_h->ack = ntohl(this->tcp_h->ack);
        this->tcp_h->window = ntohs(this->tcp_h->window);
        this->tcp_h->check = ntohs(this->tcp_h->check);
        this->tcp_h->urg_ptr = ntohs(this->tcp_h->urg_ptr);
    }
}

WpTcp::~WpTcp() {
    if(this->tcp_h) this->tcp_h = NULL;
}

void WpTcp::print() {
    WpInet::print();
    if(!this->tcp_h) return;

    printf("===========TCP Protocol=========\n");
    printf("  Source Port: %d\n", this->tcp_h->source);
    printf("    Dest Port: %d\n", this->tcp_h->dest);
    printf("   Seq Number: %u\n", this->tcp_h->seq);
    printf("   ACK Number: %u\n", this->tcp_h->ack_seq);
    printf("Header Length: %d\n", this->tcp_h->doff * 4);
    printf("     CheckSum: %d\n", this->tcp_h->check);
    printf("  Window Size: %d\n", this->tcp_h->window);
    printf("   Urgent Ptr: %d\n", this->tcp_h->urg_ptr);
    printf("===========TCP Protocol=========\n");
}

WpUdp::WpUdp(const u_char *datagram): WpInet(datagram) {
    this->udp_h = NULL;
    if (datagram) {
        this->udp_h = UDP_HEAD(datagram);
        this->udp_h->source = ntohs(this->udp_h->source);
        this->udp_h->dest = ntohs(this->udp_h->dest);
        this->udp_h->len = ntohs(this->udp_h->len);
        this->udp_h->check = ntohs(this->udp_h->check);
    }
}

WpUdp::~WpUdp() {
    if(this->udp_h) this->udp_h = NULL;
}

void WpUdp::print() {
    WpInet::print();
}

WpDns::WpDns(const u_char *datagram): WpUdp(datagram) {
    this->dns_h = datagram ? DNS_HEAD(datagram) : NULL;
}

WpDns::~WpDns() {
    if(this->dns_h) this->dns_h = NULL;
}

void WpDns::print() {
    WpInet::print();
}

WpDev::WpDev() {
    memset(this->name, 0, IF_NAMESIZE);
    memset(this->mac, 0, ETH_ALEN);
    this->ip = 0;
    this->netmask = 0;
    this->gateway = 0;
}

void WpDev::print() {

    printf("name:%-16s  mac:", this->name);
    for(int i = 0; i < 6; i++)
        printf("%02X%s",this->mac[i], i < 5 ? ":":"");
    printf("     ip:%-16s", __inet_addr(this->ip));
    printf("netmask:%-16s", __inet_addr(this->netmask));
    printf("gateway:%-16s\n", __inet_addr(this->gateway));
}

pcap_t *wp_pcap_handler(char *dev, uint32_t net, char *filter, char *errbuf) {
    struct bpf_program fp;

    if (!dev) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return NULL;
    }

    pcap_t *handler = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);

    if (!handler) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return NULL;
    }

    if (pcap_compile(handler, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter, pcap_geterr(handler)
        );
        return NULL;
    }

    if (pcap_setfilter(handler, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter, pcap_geterr(handler)
        );
        return NULL;
    }
    return handler;
}


/*
 * 硬件配置 - 网络接口
 */


int wp_run_devs(WpDevMap *dev_map) {
    if(!dev_map) return -1;

    // 默认网关
    struct sockaddr_nl src, dst;
    struct { struct nlmsghdr hdr; struct rtmsg msg; } request;
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    int seq = 0, pid = pthread_self() << 16 || getpid();

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    memset(&request, 0, sizeof(request));

    src.nl_family = AF_NETLINK;
    src.nl_pid = pid;
    bind(fd, (struct sockaddr *)&src, sizeof(src));

    dst.nl_family = AF_NETLINK;
    connect(fd, (struct sockaddr *)&dst, sizeof(dst));

    request.hdr.nlmsg_len = sizeof(request);
    request.hdr.nlmsg_type = RTM_GETROUTE;
    request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.hdr.nlmsg_seq = ++seq;
    request.hdr.nlmsg_pid = pid;

    int done = __wp_send(fd, (void *)&request, sizeof(request), 0);

    u_char response[BUFSIZ];
    struct nlmsghdr *nl_msg_hdr;
    while (done) {
        int len = __wp_recv(fd, response, BUFSIZ, 0);
        nl_msg_hdr = (struct nlmsghdr *)(response);
        if(!NLMSG_OK(nl_msg_hdr, len)) return 1;

        do {
            switch(nl_msg_hdr->nlmsg_type) {
            case NLMSG_ERROR:
                return 2;
            case NLMSG_DONE:
                done = 0;
                break;
            default:
                struct rtmsg *rt_msg_hdr = (struct rtmsg *)NLMSG_DATA(nl_msg_hdr);
                if(rt_msg_hdr->rtm_type != RTN_UNICAST) {
                    nl_msg_hdr = NLMSG_NEXT(nl_msg_hdr, len);
                    continue;
                }
                struct rtattr *attr = (struct rtattr *)RTM_RTA(rt_msg_hdr);
                int rta_len = RTM_PAYLOAD(nl_msg_hdr);
                char *name = NULL;
                struct in_addr *ip = NULL;
                char __name[IF_NAMESIZE];
                while(RTA_OK(attr, rta_len)) {
                    switch (attr->rta_type) {
                        case RTA_GATEWAY:
                            if(rt_msg_hdr->rtm_family == AF_INET)
                                ip = (struct in_addr *)RTA_DATA(attr);
                            break;
                        case RTA_OIF:
                            name = __name;
                            if_indextoname(*(int *)RTA_DATA(attr), name);
                            break;
                    }
                    attr = RTA_NEXT(attr, rta_len);
                }
                if (name && ip) {
                    WpDev *run_dev;
                    if(dev_map->count(name))
                        run_dev = dev_map->at(name);
                    else {
                        run_dev = new WpDev();
                        strcpy(run_dev->name, name);
                        // char *name 本质是一个地址变量
                        // WpDevMap 实际的key值是 name 的地址变量值
                        // 而在当前作用域内, name 存储的地址变量值不变
                        // 因此, 不能使用 (*dev_map)[name] = run_dev;
                        // 此外, name 本身是一个临时变量
                        (*dev_map)[run_dev->name] = run_dev;
                    }
                    run_dev->gateway = ntohl(ip->s_addr);
                }
                break;
            }
            nl_msg_hdr = NLMSG_NEXT(nl_msg_hdr, len);
        } while (NLMSG_OK(nl_msg_hdr, len));
    }
    close(fd);

    // MAC + IP + 子网掩码
    struct ifaddrs *devList, *dev;
    if (getifaddrs(&devList) == -1) return 3;

    for(dev = devList; dev; dev = dev->ifa_next) {
        if (!(dev->ifa_flags & IFF_UP)) continue;
        const char *name = dev->ifa_name;
        WpDev *run_dev;

        if(dev_map->count(name))
            run_dev = dev_map->at(name);
        else
            continue;                       // 不关心无默认网关的接口

        // {
        //     run_dev = new WpDev();
        //     strcpy(run_dev->name, dev->ifa_name);
        //     (*dev_map)[run_dev->name] = run_dev;
        // }

        switch(dev->ifa_addr->sa_family) {
            case AF_INET:
                run_dev->ip = ntohl(((struct sockaddr_in *)dev->ifa_addr)->sin_addr.s_addr);
                run_dev->netmask = ntohl(((struct sockaddr_in *)dev->ifa_netmask)->sin_addr.s_addr);
                break;
            case AF_PACKET:
                memcpy(run_dev->mac, ((struct sockaddr_ll *)dev->ifa_addr)->sll_addr, ETH_ALEN);
                break;
        }
    }
    freeifaddrs(devList);

    return 0;
}

/*
 * 系统资源 —— 套接字 <=> 进程
 */

WpInetSock::WpInetSock() {
    this->inode = 0;

    this->sip = 0;
    this->dip = 0;
    this->sport = 0;
    this->dport = 0;

    this->pid = 0;
    this->fd = 0;
    this->cpu = 0.0;
    this->mem = 0;
}

void WpInetSock::print() {
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    printf("%-10u %15s:%-5u %15s:%-5u pid=%-10u pname=%-20s cpu=%-6.2f mem=%-8lu",
        this->inode, __inet_addr(this->sip, src), this->sport,
        __inet_addr(this->dip, dst), this->dport, this->pid, this->pname,
        this->cpu, this->mem
    );
}

WpTcpSock::WpTcpSock(): WpInetSock() {
    this->state = 0;
    memset(&(this->info), 0, PR_GET_NAME);
}

void WpTcpSock::print() {
    WpInetSock::print();
    printf(" %s\n", SOCK_STATE.at(this->state));
}

int wp_tcp_socks(WpTcpSockMap *sock_map) {
    if(!sock_map) return -1;

    // socket 列表
    struct sockaddr_nl src, dst;
    struct { struct nlmsghdr hdr; struct inet_diag_req_v2 msg; } request;
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG);
    int seq = 0, pid = pthread_self() << 16 || getpid();

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    memset(&request, 0, sizeof(request));

    src.nl_family = AF_NETLINK;
    src.nl_pid = pid;
    bind(fd, (struct sockaddr *)&src, sizeof(src));

    dst.nl_family = AF_NETLINK;
    connect(fd, (struct sockaddr *)&dst, sizeof(dst));

    request.hdr.nlmsg_len = sizeof(request);
    request.hdr.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.hdr.nlmsg_seq = ++seq;
    request.hdr.nlmsg_pid = pid;

    request.msg.sdiag_family = AF_INET;
    request.msg.sdiag_protocol = IPPROTO_TCP;
    request.msg.idiag_states = -1;
    request.msg.idiag_ext = INET_DIAG_INFO;


    int done = __wp_send(fd, (void *)&request, sizeof(request), 0);

    u_char response[BUFSIZ];
    struct nlmsghdr *nl_msg_hdr;
    struct inet_diag_msg *inet_msg;
    while (done) {
        int len = recv(fd, response, BUFSIZ, 0);
        nl_msg_hdr = (struct nlmsghdr *)response;
        if(!NLMSG_OK(nl_msg_hdr, len)) return 1;

        do {
            switch(nl_msg_hdr->nlmsg_type) {
            case NLMSG_ERROR:
                return 2;
            case NLMSG_DONE:
                done = 0;
                break;
            case SOCK_DIAG_BY_FAMILY:
                inet_msg = (struct inet_diag_msg *) NLMSG_DATA(nl_msg_hdr);
                uint32_t inode = inet_msg->idiag_inode;
                if (!inode || (*inet_msg->id.idiag_src & IN_LOOPBACKNET) ==
                    IN_LOOPBACKNET || (*inet_msg->id.idiag_dst & IN_LOOPBACKNET)
                    == IN_LOOPBACKNET) break;

                WpTcpSock *tcp_sock;
                if(sock_map->count(inode)) tcp_sock = sock_map->at(inode);
                else {
                    tcp_sock = new WpTcpSock();
                    (*sock_map)[inode] = tcp_sock;
                }
                tcp_sock->inode = inet_msg->idiag_inode;
                tcp_sock->sip = ntohl(*(inet_msg->id.idiag_src));
                tcp_sock->dip = ntohl(*(inet_msg->id.idiag_dst));
                tcp_sock->sport = ntohs(inet_msg->id.idiag_sport);
                tcp_sock->dport = ntohs(inet_msg->id.idiag_dport);
                tcp_sock->state = inet_msg->idiag_state;

                int rta_len = NLMSG_PAYLOAD(nl_msg_hdr, sizeof(*inet_msg));
                struct rtattr *attr = (struct rtattr *)(inet_msg + 1);

                while(RTA_OK(attr, rta_len)) {
                    switch(attr->rta_type) {
                    case INET_DIAG_INFO:
                        tcp_sock->info = *(struct tcp_info *)RTA_DATA(attr);
                        break;
                    }
                    attr = RTA_NEXT(attr, rta_len);
                }
                break;
            }
            nl_msg_hdr = NLMSG_NEXT(nl_msg_hdr, len);
        } while (NLMSG_OK(nl_msg_hdr, len));
    }

    // 进程 <= inode => 套接字
    // 借鉴: github.com/shemminger/iproute2/blob/master/misc/ss.c
    const char *root = getenv("PROC_ROOT") ? : "/proc/";
    struct dirent *d;
    char name[1024];
    int nameoff;
    DIR *dir;

    strncpy(name, root, sizeof(name));

    if (strlen(name) == 0 || name[strlen(name) - 1] != '/')
        strcat(name, "/");

    nameoff = strlen(name);
    dir = opendir(name);
    if (!dir) return 3;

    while ((d = readdir(dir)) != NULL) {

        struct dirent *tmp_d;
        char process[PR_GET_NAME];
        char *p;
        int pid, pos;
        DIR *tmp_dir;
        char crap;

        // 获取进程 ID
        if (sscanf(d->d_name, "%d%c", &pid, &crap) != 1) continue;

        snprintf(name + nameoff, sizeof(name) - nameoff, "%d/fd/", pid);
        pos = strlen(name);

        if ((tmp_dir = opendir(name)) == NULL) continue;

        process[0] = '\0';
        p = process;

        while((tmp_d = readdir(tmp_dir)) != NULL) {
            const char *pattern = "socket:[";
            unsigned int ino;
            char lnk[64];
            int fd;
            ssize_t link_len;
            char tmp[1024];

            // 获取 文件描述符fd
            if (sscanf(tmp_d->d_name, "%d%c", &fd, &crap) != 1) continue;

            snprintf(name + pos, sizeof(name) - pos, "%d", fd);

            // 获取 连接
            link_len = readlink(name, lnk, sizeof(lnk) - 1);
            if (link_len == -1) continue;
            lnk[link_len] = '\0';

            // 过滤非 套接字(socket) fd
            if(strncmp(lnk, pattern, strlen(pattern))) continue;

            // 获取 socket => inode
            sscanf(lnk, "socket:[%u]", &ino);
            if(!sock_map->count(ino)) continue;

            // 获取 进程名称
            if (*p == '\0') {
                FILE *fp;
                snprintf(tmp, sizeof(tmp), "%s/%d/stat", root, pid);
                if ((fp = fopen(tmp, "r")) != NULL) {
                    if (fscanf(fp, "%*d (%[^)])", p) < 1);
                    fclose(fp);
                }
            }
            WpTcpSock *tcp_sock = sock_map->at(ino);
            tcp_sock->pid = pid;
            tcp_sock->fd = fd;
            strcpy(tcp_sock->pname, p);
        }
        closedir(tmp_dir);
    }
    closedir(dir);

    return 0;
}
