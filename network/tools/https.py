# coding: utf-8

""" 检查 HTTPS/HTTP请求 的全过程 —— Without Proxy/VPN

基本思路:
    TCS 平台是一个Web应用, 主要通过 HTTPS/HTTP 访问服务器, 请求资源。当TCS平台出
现资源(如: 网页, 视频, 图片等)加载缓慢或失败的问题时, 检查 HTTPS/HTTP 访问的过程
就显得尤为重要。
    使用Proxy或VPN, HTTPS/HTTP 请求的真正发起者大多为 代理服务器。在这种情况下,
则先假设 从代理服务器发起的 HTTPS/HTTP 请求过程不存在任何问题, 检查代理服务器和
主机之间的网络连接。

"""
import os
import select
import socket
import timeit
from config.configure import DNS_SERVERS, Port
from config.function import check_ip
from config.structure import DNSResolverStruct
from config.dns import DNStatus
from packet import IPV, Proto, DNS


class DNSResolver(object):
    """ DNS 解析器

    基本思路:
    - One dns server, one record.
    - All dns server, one ip set.
    """
    def __init__(self, domain):
        # 预声明 self.domain, self.record
        self.domain = None
        self.record = None
        self.config(domain)

    def config(self, domain=None, timeout=0.5, count=2):
        """ 配置 DNS 解析器

        @param domain: 域名
        @type  domain: string

        @param timeout: 超时时间(单位 : s)
        @type  timeout: double

        @param count: 超时重传次数
        @type  count: int
        """
        if domain is not None:
            self.domain = domain
        self.timeout = timeout
        self.count = count
        self.id = os.getpid() & 0xffff
        self.records = []

    def __create_socket(self, dst):
        """创建一个 socket

        @param dst: DNS 服务器
        @type  dst: IPV4/IPV6

        @return : 网络套接字
        @type : socket

        @raise socket.error:  内部不处理 socket.error, 统一交由外部处理
        """
        ipv = check_ip(dst)
        udp = socket.getprotobyname(Proto.UDP)
        if ipv == IPV.ERROR:
            return None
        elif ipv == IPV.IPV4:
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        elif ipv == IPV.IPV6:
            return socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, udp)
        else:
            return None

    def __send(self, sock, dns_server):
        """ 发送DNS请求报文

        @param sock: 网络套接字
        @type  sock: socket

        @param dns_server: dns 服务器
        @type  dns_server: IPV4/IPV6

        @return: DNS查询报文, 发送时间
        @rtype : (packet.DNS(), double)

        @raise socket.error: 内部不处理, 交由外部处理
        """
        # 构建 dns 查询报文
        query = DNS()
        packet = query.construct(domain=self.domain, ID=self.id)
        sock.sendto(packet, (dns_server, Port.DNS))
        return (query, timeit.default_timer())

    def __recv(self, sock, query, sent_time):
        """ 接收 DNS回答报文

        @param sock: 网络套接字
        @type  sock: socket

        @param query: DNS查询报文
        @type  query: packet.DNS

        @param sent_time: 发送时间
        @type  sent_time: double

        @return: 接收时间, DNS回答报文
        @rtype : (double, packet.DNS)

        @raise socket.error: 内部不处理, 交由外部处理
        """
        remained_time = 0
        while True:
            remained_time = self.timeout - timeit.default_timer() + sent_time
            readable = select.select([sock], [], [], remained_time)[0]
            if len(readable) == 0:
                return (-1, None)

            packet, addr = sock.recvfrom(4096)
            recv_time = timeit.default_timer()
            response = DNS()
            ok = response.analysis(packet)
            if ok and response.id == self.id \
                  and query.question.domain == response.question.domain:
                return (recv_time, response)
            if recv_time - sent_time >= self.timeout:
                return (-1, None)

    def resolve(self):
        if self.domain in {None, ''}:
            return
        # 选择 DNS 服务器
        for dns_server in DNS_SERVERS:
            retry = 0
            record = DNSResolverStruct()
            sent_time = 0.0
            recv_time = 0.0
            response = None
            sock = self.__create_socket(dns_server)
            while retry < self.count:
                # 发送 DNS 查询报文
                query, sent_time = self.__send(sock, dns_server)
                # 接收 DNS 回答报文
                recv_time, response = self.__recv(sock, query, sent_time)
                # 超时重传
                if recv_time - sent_time > 0 and response is not None:
                    break
                retry = retry + 1
                self.id = (self.id + 1) & 0xffff
            sock.close()
            # 记录
            record.dns_server = dns_server
            record.domain = self.domain
            record.send_timestamp = sent_time
            record.recv_timestamp = recv_time
            latency = recv_time - sent_time
            record.latency = -1 if latency < 0 else latency

            # 由于 socket.recvfrom 接收的数据有误, 暂停解析DNS回答报文的内容
            record.status = DNStatus(1)
            record.cname = []
            record.ip = []

            self.records.append(record)
