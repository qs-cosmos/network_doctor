# coding: utf-8

""" 定义常用的数据结构类

- ICMPingStruct: The result of ICMPing.ping()
"""


class ICMPingStruct(object):
    """ 存储进行ICMPing的结果

    Structure:
    {
        'seq' : 1,
        'ttl' : 48
        'sent_size' : 64 (单位 : bytes)
        'recv_size' : 45 (单位 : bytes)
        'sent_timestamp' : 1000
        'recv_timestamp' : 1001
        'latency'  : 1 (单位 : ms, -1 表示 timeout)
    }
    """
    def __init__(self):
        self.seq = 0                # 序列号
        self.ttl = 0                # Time to Live   (单位 : 路由跳数)
        self.sent_size = 0          # 发送数据的大小 (单位 : bytes)
        self.recv_size = 0          # 接收数据的大小 (单位 : bytes)
        self.sent_timestamp = 0.0   # 发送时间戳     (单位 : s)
        self.recv_timestamp = 0.0   # 接收时间戳     (单位 : s)
        self.latency = 0            # 发送接收延迟   (单位 : ms)

    def json(self):
        return {
            'seq': self.seq,
            'ttl': self.ttl,
            'sent_size': self.sent_size,
            'recv_size': self.recv_size,
            'sent_timestamp': self.sent_timestamp,
            'recv_timestamp': self.recv_timestamp,
            'latency': self.latency,
        }


class DNSResolverStruct(object):
    """ 存储 DNS 解析的结果 """
    def __init__(self):
        from config.dns import DNStatus
        self.dns_server = ''        # 响应的dns服务器
        self.domain = ''            # 查询的域名
        self.cname = []             # 域名的规范主机名 - 递归存储
        self.ip = []                # 域名的DNS解析结果
        self.send_timestamp = 0.0   # 发送时间戳        (单位 : s)
        self.recv_timestamp = 0.0   # 接收时间戳        (单位 : s)
        self.latency = 0            # 请求解析延迟      (单位 : ms)
        self.status = 0   # DNS报文的状态码

    def json(self):
        return {
            'dns_server': self.dns_server,
            'name': self.domain,
            'cname': self.cname,
            'ip': self.ip,
            'status': self.status,
            'send_timestamp': self.send_timestamp,
            'recv_timestamp': self.recv_timestamp,
            'latency': self.latency
        }
