# coding: utf-8

""" 检测网络延迟和丢包率

基本思路:
    ICMP, TCP, UDP, HTTP 均可用于检测网络延迟和丢包率, 但是每种协议的检测过程和
检测结果,都有比较多的差异, 因此根据检测过程中采用的协议划分为多个类。同时这些类
之间又存在很多相似性,因此构建一个基类包含所有的相同操作,其他类共同继承于该基类。
    与大多数平台实现的 ping 不同的是, DNS 解析过程将单独作为一个重要的检测内容。
因此这里的输入是IP 地址而不是Domain name。IPv4/IPv6 将在初始化时检测，从而创建合
适的网络通信套接字, 进行后续的检测。
"""

import socket
import strcut
import os

"""
模块分离 :
- 创建套接字
- 构建和解析报文
"""


class ICMPing(object):
    """ 采用ICMP协议检测网络延迟和丢包率

    结果数据结构:
    {
       'pings' : [
            {
                'seq' : 1,
                'ttl' : 48
                'sent_size' : 64 (单位 : bytes)
                'recv_size' : 45 (单位 : bytes)
                'sent_timestamp' : 1000
                'recv_timestamp' : 1001
                'latency'  : 1 (单位 : ms, -1 表示 timeout)
            },
       ],
       'dst_ip' : xxx,
       'src_ip' : xxx,
    }
    """

    def __init__(self, dst):
        """ 初始化 ICMPing

        @param dst: 目的主机IP
        @type  dst: ipv4/ipv6
        """
        self.config(dst)
        self.records = {}

    def config(self, dst, interval=1, timeout=1, count=100):
        """ 配置 ICMPing

        @param interval: 发送 ICMP报文 的间隔时间(单位: s)
        @type  interval: double

        @param timeout: 超时时间(单位: s)
        @type  timeout: double

        @param count: 发送 ICMP报文 的总数
        @type  count: int
        """
        self.dst_ip = dst
        self.interval = interval
        self.timeout = timeout
        self.count = count

    def __create_socket(self):
        """ 创建一个 socket

        @return:  网络套接字
        @rtype :  socket
        """
        # 检测 ip 类型
        try:

            pass
        except Exception as e:
            print "Error: %s" % e

    def __ping_once(self, sock):
        """ Ping one time. """
        # 构建 ICMP 报文
        # 发送 ICMP 报文
        # 接收 ICMP 报文
        # 解析 ICMP 报文
        # 整理记录

    def ping(self):
        # 创建 socket
        pass

    def output(self):
        pass
