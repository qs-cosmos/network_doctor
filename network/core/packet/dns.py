# coding: utf-8

"""
由于 socket.recvfrom() 方法接收的数据存在问题, 暂停解析 DNS 报文的工作
"""

import struct
from config.logger import Logger


def get_domain(packet, offset):
    """ 获取 DNS报文 中问题/资源段的域名

    @param packet: 以问题区域为开始的报文段
    @type  packet: string

    @param offset: 偏移量
    @type  offset: int

    @return: (报文中域名占用字节数, 域名)
    @rtype : (int, string)
    """
    logger = Logger.get()
    length = 0          # 总长度
    node = 0            # 每一段的长度
    domain = None       # 域名
    point = False       # 是否为指针
    first_skip = True   # 是否为第一次跳转

    def is_point(byte):
        """ 识别 偏移指针 """
        return (ord(byte) | 0x3f) == 0xff

    def skip(location):
        """ 指针跳转

        @param location: 表示偏移指针的两个字节
        @type  location: [byte, byte]
        """
        return (ord(location[0]) & 0x3f << 8) + (ord(location[1]) & 0xff)
    while True:
        if node == 0:
            if len(packet) <= offset:
                m_a = 'The offset %d bytes' % (offset)
                m_b = 'beyonds the packet length %d bytes.' % (len(packet))
                logger.debug(m_a + m_b)
                return (-1, None)
            if is_point(packet[offset]):
                point = True
                offset = skip(packet[offset: offset + 2])
                logger.debug('The pointer jumps to %dth byte.' % (offset))
            node = struct.unpack('!B', packet[offset])[0]
            # 当识别为指针时, 则该段实际所占长度为 2 bytes
            # 可能会存在递归指针跳转, 实际所占长度为第一次跳转时的长度
            if point and first_skip:
                length = length + 2
                first_skip = False
                logger.debug('The 1th pointer jump occurred.')
            # 如果不是指针, 则加上每一段的长度
            if not point:
                length = length + node + 1
            offset = offset + 1
            if node == 0:
                debug = 'Return —— length: %d, domain: %s' % (length, domain)
                logger.debug(debug)
                return (length, domain)
            domain = '' if domain is None else domain + '.'
        else:
            if len(packet) <= offset:
                m_a = 'The offset %d bytes' % (offset)
                m_b = 'beyonds the packet length %d bytes.' % (len(packet))
                logger.debug(m_a + m_b)
                return (-1, None)
            domain = domain + struct.unpack('!s', packet[offset])[0]
            offset = offset + 1
            node = node - 1


class DNStatus(object):
    """ DNS 报文的状态码

    取值说明: [0, 9] => DNS RCODES, [10, ) => 自定义
    """
    NO_ERROR = 0                    # DNS 请求完成
    FORMERR = 1                     # DNS 请求格式错误
    SERVER_FAIL = 2                 # DNS 服务器错误
    NO_DOMAIN = 3                   # 域名不存在
    NO_TIMP = 4                     # 功能未实现
    REFUSED = 5                     # 服务器拒绝回答请求
    YX_DOMAIN = 6                   # 不应该存在的名称, 但确实存在
    XRREST = 7                      # 不应该存在的回答, 但确实存在
    NO_TAUTH = 8                    # DNS 服务器对该区域不具有权威性
    NO_TZONE = 9                    # 名称不在区域中
    NO_ANSWER = 10                  # 无回答
    TIME_OUT = 11                   # 超时
    SOCK_ERROR = 12                 # 创建 socket 时出错
    RUN_ERROR = 13                  # 客户端内部运行错误


class QueryType(object):
    """ DNS 报文常用查询类型 """
    A = 1                           # 由域名获得IPv4地址
    NS = 2                          # 查询域名服务器
    CNAME = 5                       # 查询规范名称
    SOA = 6                         # 开始授权
    WKS = 11                        # 熟知服务
    PTR = 12                        # 把IP地址转换成域名
    HINFO = 13                      # 主机信息
    MX = 15                         # 邮件交换
    AAAA = 28                       # 由域名获得 IPV6 地址
    AXFR = 252                      # 传送整个区的请求
    ANY = 255                       # 对所有记录的请求


class Question(object):
    """ DNS 报文问题区域 —— Only One Question"""
    def __init__(self):
        self.logger = Logger.get()
        self.domain = None          # 域名(长度不定)
        self.Type = QueryType.A     # 查询类型 (16 bit)
        self.Class = 1              # 查询类 (16 bit)
        self.length = 0             # 问题区域的长度
        self.packet = None          # DNS 查询数据报

    def construct(self, domain=None, Type=QueryType.A, Class=1):
        """ 构建 DNS 报文问题区域

        @param domain: 域名
        @type  domain: string

        @param Type: 查询类型
        @type  Type: QueryType

        @param Class: 查询类
        @type  Class: int

        @return: 问题区域二进制数据
        @rtype : string
        """
        self.domain = domain        # 域名(长度不定)
        self.Type = Type            # 查询类型 (16 bit)
        self.Class = Class          # 查询类 (16 bit)
        if self.domain is None:
            return

        def pack(x):
            if len(x) == 0:
                return ''
            f = '!b' + str(len(x)) + 's'
            return struct.pack(f, len(x), x)

        nodes = map(pack, self.domain.split('.'))
        p_nodes = reduce(lambda x, y: x + y, nodes)
        self.packet = p_nodes + struct.pack('!bHH', 0, self.Type, self.Class)
        self.length = len(self.packet)

    def analysis(self, packet, offset):
        """ 解析 DNS 报文问题区域

        @param packet: 以问题区域为开始的报文段
        @type  packet: string

        @param Offset: 偏移量
        @type  Offset: int

        @return: 下一个区域的起始偏移量
        @rtype : int
        """
        length, self.domain = get_domain(packet, offset)
        if self.domain is None:
            self.logger.info('Failed to get the domain in the question area.')
            return -1
        offset = offset + length
        self.Type, self.Class = struct.unpack('!HH', packet[offset:offset + 4])
        self.length = length + 4
        return offset + 4

    def json(self):
        return {
            'domain': self.domain,
            'Type': self.Type,
            'Class': self.Class,
            'size': self.length
        }


class Resource(object):
    """ DNS 回答报文资源记录区域 """

    def __init__(self):
        self.logger = Logger.get()
        self.domain = None
        self.Type = QueryType.A
        self.Class = 1
        self.ttl = 0
        self.data_length = 0
        self.data = None

    def analysis(self, packet, offset):
        """ 解析 DNS 回答报文资源记录区域

        @param packet: 以问题区域为开始的报文段
        @type  packet: string

        @param Offset: 偏移量
        @type  Offset: int

        @return: 下一个区域的起始偏移量
        @rtype : int
        """
        #  解析域名

        length, self.domain = get_domain(packet, offset)
        if self.domain is None:
            self.logger.warning('Failed to get the domain ' +
                                'in the resource area.')
            return -1
        offset = offset + length
        self.Type, self.Class, self.ttl, self.data_length = struct.unpack(
            '!HHIH', packet[offset:offset + 10]
        )
        offset = offset + 10
        if self.Type == QueryType.A:
            def pack(x, y):
                return str(x) + '.' + str(y)
            self.data = reduce(pack, struct.unpack(
                '!BBBB', packet[offset:offset + 4]
            ))
        elif self.Type == QueryType.CNAME:
            length, self.data = get_domain(packet, offset)

        return offset + self.data_length

    def json(self):
        return {
            'domain': self.domain,
            'Type': self.Type,
            'Class': self.Class,
            'ttl': self.ttl,
            'data_size': self.data_length,
            'data': self.data
        }


class DNS(object):
    """ DNS 报文 """

    def __init__(self):
        self.header_format = '!HHHHHH'
        self.id = 0             # 会话标识  (16 bit)
        self.flag = 256         # 标识位    (16 bit)
        self.qa = 1             # 问题总数  (16 bit)
        self.an = 0             # 回答总数  (16 bit)
        self.au = 0             # 权威总数  (16 bit)
        self.ad = 0             # 附加总数  (16 bit)
        self.question = None
        self.answers = []
        self.logger = Logger.get()

    def construct(self, domain=None, ID=0, Flag=256, An=0, Au=0, Ad=0):
        """ 构建一个DNS查询报文(一次只查询一个域名)

        @param domain: 域名
        @type  domain: string

        @return: 二进制DNS查询报文
        @rtype : string
        """
        self.logger.info('Start to construct a dns query packet.')
        self.id = ID
        self.flag = Flag
        self.an = An
        self.au = Au
        self.ad = Ad
        # 构建 dns 头部
        header = struct.pack(self.header_format, self.id, self.flag,
                             self.qa, self.an, self.au, self.ad)
        # 构建问题区域
        self.question = Question()
        self.question.construct(domain)

        self.logger.info('Successfully construct a dns query packet.')
        return header + self.question.packet

    def analysis(self, packet):
        """ DNS 回答报文解析

        @param packet: 二进制DNS回答报文
        @type  packet: string
        """
        self.logger.info('Start to analysis the dns response packet.')
        if packet is None or len(packet) < 12:
            self.logger.warning('The length of packet is less than 12 bytes.')
            return False
        # 解析 dns 头部
        offset = 12
        self.id, self.flag, self.qa, self.an, self.au, self.ad = struct.unpack(
            self.header_format, packet[0:offset]
        )
        # 解析 问题区域
        self.question = Question()
        offset = self.question.analysis(packet, offset)
        if offset == -1:
            self.logger.warning('Failed to analysis the question area.')
            return False
        # 解析 回答区域
        self.answers = []
        for i in range(self.an):
            answer = Resource()
            offset = answer.analysis(packet, offset)
            if offset == -1:
                warning = 'Failed to analysis the %dth answer area' % (i)
                self.logger.warning(warning)
                return False
            self.answers.append(answer)
        # 解析 权威区域
        # 解析 附加信息
        self.logger.info('Successfully analysis the dns response packet.')
        return True

    def rcode(self):
        return (self.flag & 0xf)

    def answer(self, Type):
        """ 获取 回答区域 的数据
        @param Type: 请求类型
        @type  Type: core.packet.dns.QueryType
        """
        result = []
        try:
            result = filter(lambda x: x.Type == Type, self.answers)
            result = map(lambda x: x.data, result)
        except Exception:
            self.logger.info('The type of answers is: %s' % type(self.answers))
            self.logger.exception('Failed to get answer about %d.' % Type)
        finally:
            return result
