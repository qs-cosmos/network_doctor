#include <stdio.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <unistd.h>

#include "system_sniffer.h"

void print_datagram(const u_char *datagram) {
    WpInet *wp_inet;
    switch(IP_PROTO(datagram)) {
        case IPPROTO_ICMP:
            wp_inet = new WpIcmp(datagram);
            break;
        case IPPROTO_TCP:
            wp_inet = new WpTcp(datagram);
            break;
        case IPPROTO_UDP:
            wp_inet = new WpUdp(datagram);
            break;
    }
    wp_inet->print();

}

void get_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *frame) {
    switch(ETH_PROTO(frame)) {
        case ETH_P_IP:
            print_datagram(ETH_DATA(frame));
            break;
        case ETH_P_IPV6:
            printf("\nThis is a IPV6 protocol.\n");
            break;
        case ETH_P_ARP:
            printf("\nThis is a ARP protocol.\n");
            break;
        case ETH_P_RARP:
            printf("\nThis is a RARP protocol.\n");
            break;
        default:
            break;
    }
}

void test_pcap() {
    pcap_t *handler;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    char filter[] = "";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    dev = pcap_lookupdev(errbuf);
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    handler = wp_pcap_handler(dev, net, filter, errbuf);

    if (handler) {
        pcap_loop(handler, 10, get_packet, NULL);
        pcap_close(handler);
    }
}

void test_run_dev() {
    WpDevMap dev_map;
    wp_run_devs(&dev_map);
    WpDevMapIter dev_map_iter = dev_map.begin();

    while(dev_map_iter != dev_map.end()) {
        dev_map_iter->second->print();
        ++dev_map_iter;
    }

}

void test_tcp_sock() {
    WpTcpSockMap sock_map;
    WpProcMap proc_map;
    char done = 3;
    do {
        --done;
        wp_tcp_socks(&sock_map, &proc_map);
        WpProcMapIter proc_map_iter = proc_map.begin();
        while(proc_map_iter != proc_map.end()) {
            proc_map_iter->second->print();
            ++proc_map_iter;
        }
        WpTcpSockMapIter sock_map_iter = sock_map.begin();
        while(sock_map_iter != sock_map.end()) {
            sock_map_iter->second->print();
            ++sock_map_iter;
        }
        sleep(1);
    } while (done);

}

int main() {
    // WpProc wp_proc(10675);
    // do{
        // sleep(3);
    // test_tcp_sock();
    //     wp_proc.update();
    //     wp_proc.print();
    // } while(1);
    test_run_dev();
    // test_tcp_sock();
    return 0;
}


