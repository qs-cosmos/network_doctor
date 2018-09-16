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
from config.dns import QueryType, DNStatus
from config.function import check_ip
from config.structure import DNSResolverStruct
from logger import Logger
from packet import IPV, Proto, DNS


class DNSResolver(object):
    """ DNS 解析器

    基本思路:
    - One dns server, one record.
    - All dns server, one ip set.
    """
    def __init__(self):
        self.logger = Logger.get()
        self.domain = None
        self.timeout = 0.5
        self.count = 2
        self.id = 0
        self.records = []
        self.send_timestamp = 0.0
        self.recv_timestamp = 0.0
        self.latency = 0

    def config(self, domain=None, timeout=0.5, retry=2):
        """ 配置 DNS 解析器

        @param domain: 域名
        @type  domain: string

        @param timeout: 超时时间(单位 : s)
        @type  timeout: double

        @param retry: 超时重传次数
        @type  retry: int
        """
        if domain is not None:
            self.domain = domain
        self.timeout = timeout
        self.retry = retry
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
        try:
            self.logger.info('Start to create a socket.')
            ipv = check_ip(dst)
            udp = socket.getprotobyname(Proto.UDP)
            if ipv == IPV.ERROR:
                self.logger.error('Failed to create a socket ' +
                                  'due to the wrong IP: %s' % (dst))
                return None
            elif ipv == IPV.IPV4:
                self.logger.info('Successfully create a IPV4 socket.')
                return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
            elif ipv == IPV.IPV6:
                self.logger.info('Successfully create a IPV6 socket.')
                return socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, udp)
            else:
                self.logger.error('Failed to create a socket ' +
                                  'due to a unknown error')
                return None
        except socket.error as e:
            self.logger.error('Failed to create a socket ' +
                              'due to the socket.error: %s' % (e))
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
        try:
            # 构建 dns 查询报文
            query = DNS()
            packet = query.construct(domain=self.domain, ID=self.id)
            self.logger.info('Send a dns query packet.')
            sock.sendto(packet, (dns_server, Port.DNS))
            return (query, timeit.default_timer())
        except Exception as e:
            self.logger.error('Failed to send a dns query packet ' +
                              'due to the Exception: %s' % (e))
            return (None, -1)

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
        self.logger.info('Expect a dns response packet.')
        remained_time = 0
        while True:
            remained_time = self.timeout - timeit.default_timer() + sent_time
            if remained_time < 0:
                self.logger.warning('Waiting for the packet timeout')
                return (-1, None, None)
            readable = select.select([sock], [], [], remained_time)[0]
            if len(readable) == 0:
                self.logger.warning('Waiting for the packet timeout.')
                return (-1, None)

            # 参考: https://stackoverflow.com/questions/52288283
            byte_stream = bytearray(4096)
            nbytes = 0
            recv_time = 0
            try:
                nbytes, addr = sock.recvfrom_into(byte_stream)
                recv_time = timeit.default_timer()
                self.logger.info('Receive a packet.')
            except Exception as e:
                self.logger.error('Failed to receive a packet ' +
                                  'due to the Exception: %s.' % (e))
                return (-1, None)
            packet = ''
            for i in range(nbytes):
                packet = packet + chr(byte_stream[i])

            response = DNS()
            ok = response.analysis(packet)
            if ok and response.id == self.id \
                  and query.question.domain == response.question.domain:
                self.logger.info('Successfully get a dns response packet.')
                return (recv_time, response)
            if recv_time - sent_time >= self.timeout:
                self.logger.warning('Waiting for the packet timeout.')
                return (-1, None)

    def resolve(self):
        """ 进行 DNS 解析"""
        if self.domain in {None, ''}:
            self.logger.error("The client does't exist DNS servers.")
            return
        # 选择 DNS 服务器
        for dns_server in DNS_SERVERS:
            self.logger.info('Start to dns resolve the domain: ' +
                             '%s by dns server: %s' %
                             (self.domain, dns_server))
            retry = 0
            record = DNSResolverStruct()
            sent_time = 0.0
            recv_time = 0.0
            response = None
            sock = self.__create_socket(dns_server)
            while retry < self.retry:
                self.logger.info('...retry the %dth time...' % (retry))
                if sock is None:
                    break
                # 发送 DNS 查询报文
                query, sent_time = self.__send(sock, dns_server)
                # 接收 DNS 回答报文
                recv_time, response = self.__recv(sock, query, sent_time)
                # 超时重传
                if recv_time - sent_time > 0 and response is not None:
                    break
                retry = retry + 1
                # id + 1
                self.id = (self.id + 1) & 0xffff
            # 记录 查询过程 参数
            record.dns_server = dns_server
            record.domain = self.domain
            record.send_timestamp = sent_time * 1000
            record.recv_timestamp = recv_time * 1000
            latency = (recv_time - sent_time) * 1000
            record.latency = -1 if latency < 0 else latency
            # 记录 查询结果
            if response is None:
                if sock is None:
                    record.status = DNStatus.SOCK_ERROR
                else:
                    record.status = DNStatus.TIME_OUT
                record.cnames = []
                record.ips = []
            else:
                record.status = response.rcode()
                record.cnames = response.answer(QueryType.CNAME)
                record.ips = response.answer(QueryType.A)
                if len(record.ips) == 0:
                    record.status = DNStatus.NO_ANSWER
            self.records.append(record)
            sock.close()
            self.logger.info('End dns resolving the domain: ' +
                             '%s by dns server: %s.' %
                             (self.domain, dns_server))

    def ips(self):
        """ 获取 所有DNS解析得到的 IP """
        ips = set(reduce(lambda x, y: x.ips + y.ips, self.records))
        return [ip for ip in ips]

    def json(self):
        return map(lambda x: x.json(), self.records)
