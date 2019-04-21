#ifndef PECKER_SYSTEM_SNIFFER_H
#define PECKER_SYSTEM_SNIFFER_H


/* 数据嗅探器
 * - 报文截获 + 解构
 * - 硬件配置
 * - 系统资源 —— 套接字 <=> 进程
 */

#include <cstring>
#include <map>

#include <arpa/nameser.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/prctl.h>


#include <pcap.h>


/* 报文截获 + 解构 */

typedef struct { uint16_t proto; } __Eth_P;
typedef struct { uint8_t proto; } __Ip_P;
typedef struct { uint16_t port; } __Port;

typedef HEADER dnshdr;

#define ETH_PROTO(frame)    (ntohs(((__Eth_P *)((u_char *)\
                                (frame + (ETH_ALEN << 1))))->proto))
#define ETH_DATA(frame)     (((u_char *)(frame + ETH_HLEN)))

#define IP_PROTO(datagram)  (((__Ip_P *)((u_char *)datagram + 9))->proto)
#define IP_HEAD(datagram)   ((struct iphdr *)datagram)
#define IP_DATA(datagram)   (((u_char *)datagram + \
                                (((struct iphdr *)datagram)->ihl << 2)))
#define TR_SPORT(datagram)  (ntohs(((__Port *)(IP_DATA(datagram)))->port))
#define TR_DPORT(datagram)  (ntohs(((__Port *)(IP_DATA(datagram) + 2))->port))

#define IP_ICMP(datagram)   ((struct icmp *)IP_DATA(datagram))

#define TCP_HEAD(datagram)  ((struct tcphdr *)IP_DATA(datagram))
#define TCP_PAYLOAD(tcp)    (tcp->ip_h->tot_len - \
                                ((tcp->ip_h->ihl + tcp->tcp_h->doff) << 2))

#define UDP_HEAD(datagram)  ((struct udphdr *)IP_DATA(datagram))
#define UDP_DATA(datagram)  (IP_DATA(datagram) + 8)
#define UDP_PAYLOAD(p_udp)  (p_udp->udp_h->len - sizeof(struct udphdr))

#define NAME_MAX_LEN        67
#define ADDR_MAX_NUM        16

#define DNS_HEAD(datagram)  ((dnshdr *)UDP_DATA(datagram))
#define DNS_DATA(datagram)  (UDP_DATA(datagram) + 12)

class WpInet {
    public:
        struct iphdr *ip_h;         // IPv4 Header
        unsigned int runtime;       // 运行时间戳

        WpInet(const u_char *);
        ~WpInet();

        virtual void print();       // 测试打印
};

class WpIcmp: public WpInet {
    public:
        struct icmp *icmp;

        WpIcmp(const u_char *);
        ~WpIcmp();

        void print();
};

class WpTcp: public WpInet {
    public:
        struct tcphdr *tcp_h;

        WpTcp(const u_char *);
        ~WpTcp();

        void print();
};

class WpUdp: public WpInet {
    public:
        struct udphdr *udp_h;

        WpUdp(const u_char *);
        ~WpUdp();

        void print();
};

class WpDns: public WpUdp {
    public:
        dnshdr *dns_h;

        WpDns(const u_char *);
        ~WpDns();

        void print();
};

pcap_t *wp_pcap_handler(char *, uint32_t, char *, char *);

/* 硬件配置 - Running */

#define WP_NLMSG_ERR(nlmsg, len)     (!NLMSG_OK(nlmsg, len) || \
                                        nlmsg->nlmsg_type == NLMSG_ERROR)

class WpDev {
    public:
        char name[IF_NAMESIZE];
        u_char mac[ETH_ALEN];
        uint32_t ip;
        uint32_t netmask;
        uint32_t gateway;

        WpDev();

        void print();
        void net();
};

// 添加一个cmp比较函数
// 避免使用char *的指针进行比较
// 实际使用时, 必须注意 WpDevMap 的key值依然是 char *变量值
struct __cmp_str
{
    bool operator()(const char *a, const char *b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

typedef std::map<const char *, WpDev *, __cmp_str> WpDevMap;
typedef std::map<const char *, WpDev *, __cmp_str>::iterator WpDevMapIter;

int wp_run_devs(WpDevMap *);


/* 系统资源 —— 套接字 <=> 进程 */
class WpInetSock {
    public:
        // socket <= inode(标识符) => process
        uint32_t inode;

        // socket
        uint32_t sip;
        uint32_t dip;
        uint16_t sport;
        uint16_t dport;

        // process
        uint32_t pid;
        uint32_t fd;
        char pname[PR_GET_NAME];
        double cpu;
        uint64_t mem;

        WpInetSock();

        virtual void print();
};

class WpTcpSock: public WpInetSock {
    public:
        uint8_t state;
        struct tcp_info info;

        WpTcpSock();

        void print();
};

static const std::map<uint8_t, const char *const>  SOCK_STATE = {
    {TCP_ESTABLISHED, "ESTABLISHED"},
    {TCP_SYN_SENT, "SYN-SENT"},
    {TCP_SYN_RECV, "SYN-RECV"},
    {TCP_FIN_WAIT1, "FIN-WAIT-1"},
    {TCP_FIN_WAIT2, "FIN-WAIT-2"},
    {TCP_TIME_WAIT, "TIME-WAIT"},
    {TCP_CLOSE, "CLOSE"},
    {TCP_CLOSE_WAIT, "CLOSE-WAIT"},
    {TCP_LAST_ACK, "LAST-ACK"},
    {TCP_LISTEN, "LISTEN"},
    {TCP_CLOSING, "CLOSING"}
};

typedef std::map<uint32_t, WpTcpSock *> WpTcpSockMap;
typedef std::map<uint32_t, WpTcpSock *>::iterator WpTcpSockMapIter;
int wp_tcp_socks(WpTcpSockMap *);

#endif
