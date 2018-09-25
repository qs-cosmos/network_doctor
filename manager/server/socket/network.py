# coding: utf-8

""" C/S 网络通信框架: 服务器"""

import ConfigParser
import json
import threading
import random
import SocketServer
import struct
import time
import timeit
import zlib
from config.constant import FILE, SOCKET
from config.logger import Logger


class SESSION:
    """ 网络会话 基本配置 """
    PARSER = ConfigParser.ConfigParser()
    SERVER_HOST = '10.8.120.46'     # 服务器IP
    SERVER_PORT = 32256             # 服务器端口
    BUFF_SIZE = 2048                # 接收缓冲区
    TIMEOUT = 1                     # 超时时间
    CODECS = 'utf-8'                # 通信编码
    # 超时重传次数
    CERT = 1.5                      # 重新认证间隔
    RETRY = 2                       # 最大重传次数
    # 客户端
    IDS = []
    MAX_ID = 9999999999
    MIN_ID = 1000000000

    @staticmethod
    def load(filename='network.conf'):
        logger = Logger.get()
        filepath = FILE.conf(filename)
        lock = threading.Lock()
        lock.acquire()
        try:
            logger.info('Start to load the session configure.')
            SESSION.PARSER.read(filepath)
            SESSION.SERVER_HOST = SESSION.PARSER.get('server', 'host')
            SESSION.SERVER_PORT = SESSION.PARSER.getint('server', 'port')
            SESSION.BUFF_SIZE = SESSION.PARSER.getint('server', 'buff_size')
            SESSION.TIMEOUT = SESSION.PARSER.getint('server', 'timeout')
            SESSION.CODECS = SESSION.PARSER.get('server', 'codecs')
            SESSION.CERT = SESSION.PARSER.getfloat('server', 'cert')
            SESSION.RETRY = SESSION.PARSER.getint('server', 'retry')
            SESSION.MAX_ID = SESSION.PARSER.getint('server', 'max_id')
            SESSION.MIN_ID = SESSION.PARSER.getint('server', 'min_id')
        except Exception:
            logger.warn('Please check your session configure.')
            logger.exception('Failed to load the session configure.')
        finally:
            lock.release()

    @staticmethod
    def cert(ID):
        """ 身份验证 """
        logger = Logger.get()
        lock = threading.Lock()
        lock.acquire()
        try:
            if ID not in SESSION.IDS:
                logger.info('...try to allocate a new client id...')
                ID = random.randint(SESSION.MIN_ID, SESSION.MAX_ID)
                while ID in SESSION.IDS:
                    ID = random.randint(SESSION.MIN_ID, SESSION.MAX_ID)
                SESSION.IDS.append(ID)
            Logger.sign_up(str(ID))
            logger.info('The id %d passed the certification.' % ID)
        except Exception:
            logger.exception('...failed to allocate a new client id...')
            ID = -1
        finally:
            lock.release()
        return ID


class STAMP:
    """ 消息类型 """
    # 通信逻辑 (0~127)
    ID = 0                          # 会话 ID
    END = 1                         # 结束会话
    # 消息内容标识 (128~255)
    CLIENT = 128                    # 客户端基本配置
    DNS_RESOLVE = 129               # DNS 解析
    ICMPING = 130                   # ICMPing 结果


class TYPE:
    """ 数据类型 """
    NONE = 0                        # NoneType
    DICT = 1                        # dict (json数据)
    FLOAT = 2                       # float
    INT = 3                         # int
    STRING = 4                      # str
    UNICODE = 5                     # unicode
    UNKNOWN = 255                   # 未知类型

    @staticmethod
    def type(data):
        if data is None:
            return TYPE.NONE
        type_ = type(data)
        if type_ == dict:
            return TYPE.DICT
        if type_ == float:
            return TYPE.FLOAT
        if type_ == int:
            return TYPE.INT
        if type_ == str:
            return TYPE.STRING
        if type_ == unicode:
            return TYPE.UNICODE
        return TYPE.UNKNOWN


class JPRESS:
    """ JSON 数据段压缩模式 """
    JZLIB = 0                       # json + zlib
    JSON = 1                        # json

    @staticmethod
    def compress(data):
        """ 压缩 JSON数据

        @return: 压缩模式 和 压缩后的数据
        @rtype : (mode, string)
        """
        if not isinstance(data, dict):
            return (-1, data)
        logger = Logger.get()
        str_ = json.dumps(data, separators=(',', ':'))
        mode = JPRESS.JSON
        try:
            str_ = zlib.compress(str_)
            mode = JPRESS.JZLIB
        except Exception:
            logger.exception('Failed to compress data by zlib.')
        finally:
            return (JPRESS.JSON, mode)

    @staticmethod
    def decompress(data, mode):
        """ 解压 JSON数据 """
        if mode == JPRESS.JZLIB:
            data = zlib.decompress(data)
        return json.loads(data)


class FRAME(object):
    """ 应用层通信框架 """
    HEAD = '!BBBBL'
    PACKET = ''

    @staticmethod
    def construct(stamp, data):
        """ 构建应用层通信数据 """
        flags = 0
        type_ = TYPE.type(data)
        if type_ == TYPE.DICT:
            mode, data = JPRESS.compress(data)
            flags = flags + mode
        else:
            data = str(data)
        stamp = stamp & 0xff
        type_ = type_ & 0xff
        flags = flags & 0xff
        header = struct.pack(FRAME.HEAD, stamp, type_, flags, 0, len(data))
        return header + data

    @staticmethod
    def analysis(envelope, head=True, mode=JPRESS.JZLIB):
        """ 解析应用层通信数据 """
        if head:
            # 解析 头部
            # (stamp, type_, flags, 0, length)
            return struct.unpack(FRAME.HEAD, envelope[0:8])
        else:
            # 解析数据
            # json 数据
            return JPRESS.decompress(envelope, mode)

    @staticmethod
    def send(sock, stamp, data=''):
        """ 发送数据: ack 是否需要确认 """
        logger = Logger.get()
        envelope = FRAME.construct(stamp, data)
        try:
            sock.sendall(envelope)
            logger.info('Successfully send all the data.')
            return True
        except Exception:
            logger.exception('Failed to send all the data.')
            return False

    @staticmethod
    def recv(sock):
        """ 接收数据: ack 是否需要发送一个确认

        @return: stamp, data
        @rtype : STAMP, TYPE.*

        说明: stamp < 0 表示 recv 异常退出
            - 目前只有 stamp == -1 存在意义, 即 socket 异常关闭
        """
        logger = Logger.get()
        remain = 0
        logger.info('Start to recveive a application data.')
        start = timeit.default_timer()

        # 接收数据头部
        logger.info('Waiting for a application data header.')
        while len(FRAME.PACKET) < 8:
            remain = SESSION.TIMEOUT - timeit.default_timer() + start
            recv_, data = SOCKET.recvfrom(sock, remain, size=SESSION.BUFF_SIZE)
            if recv_ < 0:
                logger.warn('Failed to get the application data header.')
                return (recv_, None)
            FRAME.PACKET = FRAME.PACKET + data
        logger.info('Succeed to get the application data header.')

        # 解析数据头部
        stamp, type_, flags, _, length = FRAME.analysis(FRAME.PACKET)
        FRAME.PACKET = FRAME.PACKET[8:]

        # 接收数据段
        logger.info('Waiting for the application data fragment.')
        while length > len(FRAME.PACKET):
            remain = SESSION.TIMEOUT - timeit.default_timer() + start
            recv_, data = SOCKET.recvfrom(sock, remain, size=SESSION.BUFF_SIZE)
            if recv_ < 0:
                logger.warn('Failed to get the application data fragment.')
                return (recv_, None)
            FRAME.PACKET = FRAME.PACKET + data
        logger.info('Succeed to get the application data fragment.')

        # 解析数据段
        envelope = FRAME.PACKET[0:length]
        FRAME.PACKET = FRAME.PACKET[length:]
        message = None
        try:
            if type_ == TYPE.DICT:
                message = FRAME.analysis(envelope, False, flags & 0x01)
            elif type_ == TYPE.FLOAT:
                message = float(envelope)
            elif type_ == TYPE.INT:
                message = int(envelope)
            elif type_ == TYPE.STRING:
                message = envelope
            elif type_ == TYPE.UNICODE:
                message = envelope
            elif type_ == TYPE.UNKNOWN:
                logger.warn('Get a unknown data type message and thrown away.')
                return (-6, None)
        except Exception:
            logger.exception('Failed to analysis the application data.')
            return (-5, None)
        return (stamp, message)


class Handler(SocketServer.BaseRequestHandler):
    """ 服务器: 封装服务器通信逻辑 """
    def handle(self):
        self.id = -1
        while True:
            stamp, message = FRAME.recv(self.request)

            # socket 异常关闭
            # 接收字节为 0 bytes
            if stamp == -1:
                break

            # 身份认证
            if stamp == STAMP.ID:
                self.id = SESSION.cert(message)
                FRAME.send(self.request, STAMP.ID, self.id)
                self.logger = Logger.get()

            # socket 结束报文
            if stamp == STAMP.END:
                self.logger.info('...client id: %d exit...' % self.id)
                break

            if stamp == STAMP.DNS_RESOLVE:
                self.__temp('dns', message)

            if stamp == STAMP.ICMPING:
                self.__temp('icmping', message)

    def __temp(self, name, data):
        filepath = FILE.new(str(self.id), 'data', name, 'json')
        with open(filepath, 'w') as f:
            json.dump(data, f)


def start():
    """ 启动 socket server """
    Logger.sign_up('SocketServer', False)
    logger = Logger.get()
    SESSION.load()
    random.seed(time.time())
    addr = (SESSION.SERVER_HOST, SESSION.SERVER_PORT)
    logger.info('...start the socket server (%s, %d)...' % addr)
    server = SocketServer.ThreadingTCPServer(addr, Handler)
    server.serve_forever()
