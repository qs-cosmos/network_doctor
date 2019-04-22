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

#include <string>

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

// 获取 proc 根目录
const char *__proc_root() {
    static std::string root = getenv("PROC_ROOT") ? : "/proc/";
    uint32_t len = root.length();
    if (len == 0 || root[len-1] != '/') root.append("/");
    return root.data();
}

// 获取 系统内存 大小
uint64_t __sys_mem() {
    const char *root = __proc_root();
    uint32_t len = strlen(root) + 8;
    uint64_t sys_mem = 1;   // 避免除0操作
    char *path = new char[len];

    snprintf(path, len, "%smeminfo", root);

    FILE *fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%*s%lu", &sys_mem);
        fclose(fp);
    }
    delete [] path;
    return sys_mem;
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

WpDev::WpDev() {
    memset(this->name, 0, IF_NAMESIZE);
    memset(this->mac, 0, ETH_ALEN);
    this->ip = 0;
    this->netmask = 0;
    this->gateway = 0;
}

uint32_t WpDev::net() {
    return this->ip & this->netmask;
}

void WpDev::print() {
    printf("name:%-16s  mac:", this->name);
    for(int i = 0; i < 6; i++)
        printf("%02X%s",this->mac[i], i < 5 ? ":":"");
    printf("     ip:%-16s", __inet_addr(this->ip));
    printf("netmask:%-16s", __inet_addr(this->netmask));
    printf("    net:%-16s", __inet_addr(this->net()));
    printf("gateway:%-16s\n", __inet_addr(this->gateway));
}

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
                    WpDevPtr run_dev;
                    if(dev_map->count(name))
                        run_dev = dev_map->at(name);
                    else {
                        run_dev = WpDevPtr(new WpDev());
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
        WpDevPtr run_dev;

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

const char *WpProc::PROC_ROOT = __proc_root();
uint64_t WpProc::SYS_MEM = __sys_mem();
long WpProc::CLK_TCK = sysconf(_SC_CLK_TCK);
long WpProc::PAGE_SIZE = sysconf(_SC_PAGE_SIZE);

WpProc::WpProc(uint32_t pid) {
    this->__pid = pid;
    this->name[0] = '\0';
    this->exec_path = NULL;
    this->cpu_time = 0.0;
    this->up_time = 0.0;
    this->start_time = 0.0;
    this->use_mem = 0;
    this->old_up_time = 0.0;
    this->update();
}

WpProc::~WpProc() {
    if(this->exec_path) delete [] this->exec_path;
    this->exec_path = NULL;
}

void WpProc::update() {
    uint32_t len = strlen(this->PROC_ROOT) + 16;
    char *path = new char[len];
    char lnk[1024];
    uint64_t utime = 0, stime = 0, rss = 0;
    unsigned long long start_time = 0;
    FILE *fp;
    float old_up_time = 0.0;
    int lnk_len = 0;

    // 读取 /proc/uptime
    snprintf(path, len , "%s/uptime", this->PROC_ROOT);
    if ((fp = fopen(path, "r")) != NULL) {
        old_up_time = this->up_time;
        fscanf(fp, "%f", &this->up_time);
        // 避免两次更新时间间隔太短
        if (this->up_time - old_up_time < 0.5) {
            this->up_time = old_up_time;
            return;
        }
        fclose(fp);
    }

    // 读取 /proc/[pid]/exe
    if (this->exec_path == NULL) {
        snprintf(path, len , "%s%d/exe", this->PROC_ROOT, this->__pid);
        lnk_len = readlink(path, lnk, sizeof(lnk) - 1);
        if (lnk_len != -1) {
            lnk[lnk_len] = '\0';
            this->exec_path = new char[lnk_len + 1];
            strcpy(this->exec_path, lnk);
            this->exec_path[lnk_len] = '\0';
        }
    }

    // 读取 /proc/[pid]/stat
    snprintf(path, len, "%s%u/stat", this->PROC_ROOT, this->__pid);
    if ((fp = fopen(path, "r")) != NULL) {
        fscanf(fp, "%*u (%[^)]) %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u "
           "%*u %lu %lu %*d %*d %*d %*d %*d %*d %llu %*u %lu", this->name,
           &utime, &stime, &start_time, &rss
        );
        fclose(fp);
    }

    this->old_cpu_time = this->cpu_time;
    this->cpu_time = (float)(utime + stime) / this->CLK_TCK;

    this->start_time = (float)start_time / this->CLK_TCK;
    if(this->old_up_time < 0.1)
        this->old_up_time = this->start_time;
    else
        this->old_up_time = old_up_time;

    this->use_mem = rss * this->PAGE_SIZE / 1024;

    delete [] path;
}

uint32_t WpProc::pid() {
    return this->__pid;
}

float WpProc::cpu() {
    float cpu_time = this->cpu_time - this->old_cpu_time;
    float run_time = this->up_time - this->old_up_time;
    if (run_time < 0.0 || cpu_time < 0.00001) return 0.0;
    return cpu_time / run_time;
}

float WpProc::mem() {
    return (float)this->use_mem / this->SYS_MEM;
}

void WpProc::print() {
    // printf("%-12.6f  %-12.6f %-12.6f  %-12.6f\n",
    //     this->cpu_time, this->old_cpu_time, this->up_time, this->old_up_time
    // );
    printf("pid=%-8u    name=%-16s cpu=%8.6f    mem=%8.6f    path=%s\n",
        this->pid(), this->name, this->cpu(), this->mem(),
        this->exec_path ? : ""
    );
}

WpInetSock::WpInetSock() {
    this->inode = 0;
    this->pid = 0;
    this->uid = 0;
    this->fd = 0;
    this->sip = 0;
    this->dip = 0;
    this->sport = 0;
    this->dport = 0;
}

void WpInetSock::print() {
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    printf("%-10u %-10u %15s:%-5u %15s:%-5u",
        this->inode, this->pid, __inet_addr(this->sip, src), this->sport,
        __inet_addr(this->dip, dst), this->dport
    );
}

WpTcpSock::WpTcpSock(): WpInetSock() {
    this->state = 0;
    memset(&(this->info), 0, sizeof(this->info));
}

void WpTcpSock::print() {
    WpInetSock::print();
    printf(" %s\n", SOCK_STATE.at(this->state));
}

int wp_tcp_socks(WpTcpSockMap *sock_map, WpProcMap * proc_map) {
    if(!sock_map || !proc_map) return -1;

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
                    == IN_LOOPBACKNET ) break;

                WpTcpSockPtr tcp_sock;
                if(sock_map->count(inode)) tcp_sock = sock_map->at(inode);
                else {
                    tcp_sock = WpTcpSockPtr(new WpTcpSock);
                    (*sock_map)[inode] = tcp_sock;
                }

                tcp_sock->inode = inet_msg->idiag_inode;
                tcp_sock->sip = ntohl(*(inet_msg->id.idiag_src));
                tcp_sock->dip = ntohl(*(inet_msg->id.idiag_dst));
                tcp_sock->sport = ntohs(inet_msg->id.idiag_sport);
                tcp_sock->dport = ntohs(inet_msg->id.idiag_dport);
                tcp_sock->state = inet_msg->idiag_state;
                tcp_sock->timer = inet_msg->idiag_timer;
                tcp_sock->uid = inet_msg->idiag_uid;

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
        char proc = 1;
        int pid, pos;
        DIR *tmp_dir;
        char crap;

        // 获取进程 ID
        if (sscanf(d->d_name, "%d%c", &pid, &crap) != 1) continue;
        // 设置 fd 路径
        snprintf(name + nameoff, sizeof(name) - nameoff, "%d/fd/", pid);
        pos = strlen(name);

        if ((tmp_dir = opendir(name)) == NULL) continue;

        while((tmp_d = readdir(tmp_dir)) != NULL) {
            const char *pattern = "socket:[";
            unsigned int ino;
            char lnk[64];
            int fd;
            ssize_t link_len;

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

            if(proc) {
                if(proc_map->count(pid) == 0) {
                    WpProcPtr proc_ptr(new WpProc(pid));
                    (*proc_map)[pid] = proc_ptr;
                } else
                    proc_map->at(pid)->update();
                proc = 0;
            }

            WpTcpSockPtr tcp_sock = sock_map->at(ino);
            tcp_sock->pid = pid;
            tcp_sock->fd = fd;
        }
        closedir(tmp_dir);
    }
    closedir(dir);

    return 0;
}
