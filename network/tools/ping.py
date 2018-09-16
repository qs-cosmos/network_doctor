# coding: utf-8

""" 基于 IPv4 检测网络延迟和丢包率

基本思路:
    ICMP, TCP, UDP, HTTP 均可用于检测网络延迟和丢包率, 但是每种协议的检测过程和
检测结果,都有比较多的差异, 因此根据检测过程中采用的协议划分为多个类。同时这些类
之间又存在很多相似性,因此构建一个基类包含所有的相同操作,其他类共同继承于该基类。
    与大多数平台实现的 ping 不同的是, DNS 解析过程将单独作为一个重要的检测内容。
因此这里的输入是IP 地址而不是Domain name。IPv4/IPv6 将在初始化时检测，从而创建合
适的网络通信套接字, 进行后续的检测。

"""

import re
import select
import socket
import threading
import time
import timeit

from config.function import check_ip
from config.structure import ICMPingStruct
from logger import Logger
from packet import IPV, IPV4, Proto, ICMP


class ICMPing(object):
    """ 采用ICMP协议检测网络延迟和丢包率

    基本思路:
    - 仅提供 Once ping one time. 的方法, ping 多次交由上层实现;
    - 记录最近 n 次 ping 的结果 和 单独记录最新一次 ping 的结果;
    - 用 config 方法重置 dst 时, 则会清空上述记录, 即使前后 dst 一致;
    - ping 方法内部不处理异常 socket.error, 打印日志后直接抛出-交由上层处理。

    """
    def __init__(self):
        """ 初始化 ICMPing

        @param dst: 目的主机IP
        @type  dst: ipv4/ipv6
        """
        self.logger = Logger.get()
        self.dst_ip = None
        self.sock = None
        self.timeout = 1
        self.interval = 0.0
        self.id = 0
        self.records = []

    def config(self, dst=None, interval=0.0, timeout=1, rst=False):
        """ 配置 ICMPing

        @param dst: 目的主机IP
        @type  dst: ipv4/ipv6

        @param interval: 发送 ICMP报文 的间隔时间(单位: s)
        @type  interval: double

        @param timeout: 超时时间(单位: s)
        @type  timeout: double

        @param count: 发送 ICMP报文 的总数
        @type  count: int

        @param rst: 清空 record/records
        @type  rst: Bool
        """
        new = False
        if dst is not None:
            self.dst_ip = re.sub(r'\s+', '', dst)
            new = True

        if new or rst:
            # 重置 目的 ip 时, 重置record/records
            # 记录最近 n 次ping的结果
            self.records = []
            # 记录最新一次 ping 的结果
            self.record = None
            # 创建一个新的套接字 self.sock
            self.close()
            self.sock = self.__create_socket()

        self.interval = interval
        self.timeout = timeout
        self.id = threading.currentThread().ident & 0xffff

    def __create_socket(self):
        """ 创建一个 IPV4 socket

        @return: 网络套接字
        @rtype : socket
        """
        try:
            self.logger.info('Start to create a socket.')
            ipv = check_ip(self.dst_ip)
            icmp = socket.getprotobyname(Proto.ICMP)
            if ipv in {IPV.ERROR, IPV.IPV6}:
                self.logger.ERROR('Failed to create a socket ' +
                                  'due to the wrong IP: %s.' % (self.dst_ip))
                return None
            elif ipv == IPV.IPV4:
                self.logger.info('Successfully create a socket.')
                return socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            else:
                self.logger.ERROR('Failed to create a socket ' +
                                  'due to a unknown cause.')
                return None
        except socket.error as e:
            self.logger.error('Failed to create a socket ' +
                              'due to the socket.error: %s' % (e))
            return None

    def __send(self, seq):
        """ 发送 ICMP 回送请求报文

        @return: (发送时间, ICMP 回送请求报文)
        @rtype : (double, ICMP())
        """
        try:
            # 构建 ICMP 报文
            sent_icmp = ICMP()
            sent_icmp.construct(ID=self.id, Seq=seq)
            # 发送 ICMP 报文
            self.logger.info('Send a echo request icmp packet.')
            self.sock.sendto(sent_icmp.icmp, (self.dst_ip, 1))
            return (timeit.default_timer(), sent_icmp)
        except Exception as e:
            self.logger.error('Failed to send a echo request icmp packet ' +
                              'due to the Exception: %s' % (e))
            return (-1, None)

    def __recv(self, sent_time):
        """ 接收 ICMP 回送响应报文

        基本思路:
        采用 select.select 监控 socket - Waiting for I/O completion
        目的 : 用来监控 Ping 是否超时
        - socket.recvfrom 会一直等待 I/O, 而没有 timeout 机制
        - 当 select.select 完成时
          - 未超时: 则通过socket.recvfrom获取数据, 检测是否为回送响应 ICMP 报文
          - 超时: 则终止循环, 抛出 Timeout Error
        设置 select.select() 剩余超时时间
        - 当 socket 中有数据到来时, 不一定是 回送响应 ICMP 报文
        - 因此, 需要进行多次 select.select()
        - 对于 send - recv 这一过程的总超时时间为 self.timeout 是确定的
        - 每进行一次循环, select.select() 的超时时间也就要相应的减少
        - 以保证 总的超时时间为 : self.timeout
        已知. 发送开始时间 则 select.select 剩余超时时间为 :
          self.time_out - timeit.default_timer() + self.sent_time

        @return: (recv_time, ICMP 回送响应报文, IP数据报)
        @rtype : (double, ICMP(), IP())
        """
        self.logger.info('Expect a echo response icmp packet.')
        remained_time = 0
        while True:
            remained_time = self.timeout - timeit.default_timer() + sent_time
            if remained_time < 0:
                self.logger.warning('Waiting for the packet timeout')
                return (-1, None, None)
            readable = select.select([self.sock], [], [], remained_time)[0]
            if len(readable) == 0:
                self.logger.warning('Waiting for the packet timeout')
                return (-1, None, None)

            # 参考: https://stackoverflow.com/questions/52288283
            byte_stream = bytearray(4096)
            nbytes = 0
            recv_time = 0
            try:
                nbytes, addr = self.sock.recvfrom_into(byte_stream)
                recv_time = timeit.default_timer()
                self.logger.info('Receive a packet')
            except Exception as e:
                self.logger.error('Failed to receive a packet ' +
                                  'due to the Exception: %s' % (e))
                return (-1, None, None)
            packet = ''
            for i in range(nbytes):
                packet = packet + chr(byte_stream[i])

            recv_ipv4 = IPV4()
            recv_ipv4.analysis(packet)
            recv_icmp = ICMP()
            ok = recv_icmp.analysis(packet[recv_ipv4.header_length:])
            if ok and recv_icmp.id == self.id and recv_ipv4.src == self.dst_ip:
                self.logger.info('Successfully get a echo response icmp ' +
                                 'packet.')
                return (recv_time, recv_icmp, recv_ipv4)
            if recv_time - sent_time >= self.timeout:
                self.logger.warning('Waiting for the packet timeout')
                return (-1, None, None)

    def ping(self, seq=0):
        """ Only ping one time. """
        self.logger.info('Start to icmping the ip %s' % (self.dst_ip))
        sent_time = -1
        sent_icmp = None
        recv_time = -1
        recv_icmp = None
        recv_ipv4 = None
        if self.sock is not None:
            sent_time, sent_icmp = self.__send(seq)
            recv_time, recv_icmp, recv_ipv4 = self.__recv(sent_time)
        # 整理记录
        record = ICMPingStruct()
        record.seq = seq
        record.ttl = 0 if recv_ipv4 is None else recv_ipv4.ttl
        # 记录 ICMP 回送请求报文
        record.sent_size = 0 if sent_icmp is None else len(sent_icmp.icmp)
        record.sent_timestamp = sent_time * 1000
        # 记录 ICMP 回送响应报文
        record.recv_size = 0 if recv_icmp is None else len(recv_icmp.icmp)
        record.recv_timestamp = recv_time * 1000
        # 计算延迟
        latency = (recv_time - sent_time) * 1000
        record.latency = -1 if latency <= 0 else latency
        # 存入历史记录
        self.records.append(record)
        # 间隔 interval 时间, 再发起下一次请求
        self.logger.info('End icmping the ip %s' % (self.dst_ip))
        time.sleep(self.interval)

    def close(self):
        """ 关闭 socket 连接 """
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def json(self):
        return map(lambda x: x.json(), self.records)
