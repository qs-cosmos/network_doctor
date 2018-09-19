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
import timeit

from config.runtime import CLIENT
from config.logger import Logger
from core.packet.dns import QueryType, DNStatus, DNS
from config.constant import PORT, PROTO, SOCKET
from core.spider.structure import DNSResolverStruct


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

    def __send(self, sock, dns):
        """ 发送DNS请求报文

        @param sock: 网络套接字
        @type  sock: socket

        @param dns_server: dns 服务器
        @type  dns_server: IPV4/IPV6

        @return: DNS查询报文, 发送时间
        @rtype : (packet.DNS(), double)

        @raise socket.error: 内部不处理, 交由外部处理
        """
        self.logger.info('Start to send a dns query packet.')
        try:
            # 构建 dns 查询报文
            query = DNS()
            packet = query.construct(domain=self.domain, ID=self.id)
            sock.sendto(packet, (dns, PORT.DNS))
            self.logger.info('Successfully send a dns query packet.')
            return (timeit.default_timer(), query)
        except Exception:
            self.logger.exception('Failed to send a dns query packet.')
            return (-1, None)

    def __recv(self, sock, sent_time):
        """ 接收 DNS回答报文

        @param sock: 网络套接字
        @type  sock: socket

        @param sent_time: 发送时间
        @type  sent_time: double

        @return: 接收时间, DNS回答报文
        @rtype : (double, packet.DNS)

        @raise socket.error: 内部不处理, 交由外部处理
        """
        self.logger.info('Expecting a dns response packet.')
        remain_time = 0
        while True:
            remain_time = self.timeout - timeit.default_timer() + sent_time
            recv_time, packet = SOCKET.recvfrom(sock, remain_time)
            if recv_time < 0:
                return (recv_time, None)

            response = DNS()
            ok = response.analysis(packet)
            same = (self.domain == response.question.domain)

            if ok and same and response.id == self.id:
                self.logger.info('Successfully get a dns response packet.')
                return (recv_time, response)
            else:
                self.logger.warning('Get a unexpected packet.')

    def resolve(self):
        """ 进行 DNS 解析"""
        if self.domain in {None, ''}:
            self.logger.error("The client does't exist DNS servers.")
            return False
        for dns in CLIENT.DNS:
            # 选择 DNS 服务器
            info = 'Start to dns resolve the domain: %s by dns server: %s'
            self.logger.info(info % (self.domain, dns))

            retry = 0
            record = DNSResolverStruct()
            sent_time = 0.0
            recv_time = 0.0
            response = None
            sock = SOCKET.create(dns, PROTO.UDP)
            while retry < self.retry:
                self.logger.info('...retry the %dth time...' % (retry))
                if sock is None:
                    break
                # 发送 DNS 查询报文
                sent_time, query = self.__send(sock, dns)
                # 接收 DNS 回答报文
                recv_time, response = self.__recv(sock, sent_time)
                # 超时重传
                if recv_time - sent_time > 0 and response is not None:
                    break
                retry = retry + 1
                # id + 1
                self.id = (self.id + 1) & 0xffff

            # 记录 查询过程 参数
            record.dns = dns
            record.domain = self.domain
            record.send_timestamp = sent_time * 1000
            record.recv_timestamp = recv_time * 1000
            latency = (recv_time - sent_time) * 1000
            record.latency = -1 if latency < 0 else latency
            # 记录 查询结果
            if response is None:
                if sock is None:
                    record.status = DNStatus.SOCK_ERROR
                elif recv_time == -1:
                    record.status = DNStatus.TIME_OUT
                else:
                    record.status = DNStatus.RUN_ERROR
                record.cnames = []
                record.ips = []
            else:
                record.status = response.rcode()
                record.cnames = response.answer(QueryType.CNAME)
                record.ips = response.answer(QueryType.A)
                if len(record.ips) == 0:
                    record.status = DNStatus.NO_ANSWER
            self.records.append(record)
            sock = SOCKET.close(sock)

            info = 'End dns resolving the domain: %s by dns server: %s'
            self.logger.info(info % (self.domain, dns))
        return True

    def ips(self):
        """ 获取 所有DNS解析得到的 IP """
        ips = []
        try:
            ips = set(reduce(lambda x, y: x.ips + y.ips, self.records))
            ips = [ip for ip in ips]
        except Exception:
            self.logger.info('The type of records is: %s' % type(self.records))
            self.logger.exception('Failed to get ips.')
        finally:
            return ips

    def json(self):
        records = {}
        try:
            records = map(lambda x: x.json(), self.records)
        except Exception:
            self.logger.info('The type of records is: %s' % type(self.records))
            self.logger.exception('Failed to transfer into json.')
        finally:
            return records
