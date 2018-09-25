# coding: utf-8

""" C/S 网络通信框架

自定义通信协议:
- 数据结构:
    - 头部(header) : 8bytes
        - 消息类型 : 1 byte
        - 数据类型 : 1 byte
        - 符号字段 : 1 byte
            - 压缩模式 : 1 bit
        - 预留字段 : 1 bytes
        - 数据长度 : 4 bytes
    - 数据(data)
- 通信过程:
    - 发送: 对待发送的数据添加一个 header, 发送结束后, 等待接收方发送一个
        确认信息, 只有等到确认信息或超时时, 再进行下一次的发送。
        - 超时时间
    - 接收: 等待接收 >= 8bytes 的数据, 解析待接收的数据长度, 直到接收的数据长度
      等于完整的数据长度, 再数据类型解析数据, 最后发送一个确认信息。
        - 超时时间
- 目的:
    - 解决应用层接收数据时过多或过少的问题
    - 隐藏数据接收发送的具体逻辑, 上层提供和接收 消息类型 和 待发送的数据
"""

import ConfigParser
import json
import struct
import threading
import time
import timeit
import zlib
from config.constant import FILE, PROTO, SOCKET
from config.logger import Logger
from config.runtime import RUNTIME


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
        except Exception:
            logger.warn('Please check your session configure.')
            logger.exception('Failed to load the session configure.')
        finally:
            lock.release()


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
    UNKNOWN = 6                     # 未知类型

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
            return (mode, str_)

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
        """ 发送数据 """
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
        """ 接收数据

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

        envelope = FRAME.PACKET[:length]
        FRAME.PACKET = FRAME.PACKET[length:]
        # 解析数据段
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
                message == envelope
            elif type_ == TYPE.UNKNOWN:
                logger.warn('Get a unknown data type message and thrown away.')
                return (-6, None)
        except Exception:
            logger.exception('Failed to analysis the application data.')
            return (-5, None)
        return (stamp, message)


class Reporter(object):
    """ 客户端: 封装客户端通信逻辑 """
    def __init__(self):
        self.logger = Logger.get()
        self.logger.info('Create a tcp communication socket.')
        self.dispatchers = []
        self.sock = SOCKET.create(SESSION.SERVER_HOST, PROTO.TCP)
        self.addr = (SESSION.SERVER_HOST, SESSION.SERVER_PORT)
        self.id = -1

    def __connect(self):
        """ 建立TCP连接 """
        connected = False
        while RUNTIME.RUNNING and not connected:
            try:
                info = '...try to connect the server (%s, %d)...'
                self.logger.info(info % self.addr)
                if self.sock is not None:
                    self.sock.connect(self.addr)
                connected = True
            except Exception:
                info = 'Failed to connect the server (%s, %d).'
                self.logger.exception(info % self.addr)
                info = '...build connection: sleeping for %f s...'
                self.logger.info(info % (SESSION.CERT * 2))
                time.sleep(SESSION.CERT * 2)
        return connected and RUNTIME.RUNNING

    def __cert(self):
        """ 客户端身份认证 """
        cert = False
        stamp = -255

        self.logger.info('Start to identify authenticate %d.' % RUNTIME.ID)
        while RUNTIME.RUNNING and not cert:
            self.logger.info('...try to identify authenticate...')
            FRAME.send(self.sock, STAMP.ID, RUNTIME.ID)
            stamp, self.id = FRAME.recv(self.sock)
            cert = True if stamp >= 0 else False
            if stamp < 0:
                # 休眠一秒后再进行通信
                self.logger.warn('...failed to identify authenticate...')
                self.logger.warn('...sleep for two seconds...')
                time.sleep(SESSION.CERT)

        if RUNTIME.RUNNING:
            RUNTIME.id(self.id)
            self.logger.info('Succeed to identify authenticate %d.')
        return RUNTIME.RUNNING and cert

    def __upload(self, stamp, data):
        """ 上传 客户端监测数据 """
        self.logger.info('Start the upload queue data transimission.')
        FRAME.send(self.sock, stamp, data)

    def __upload_dispatch(self):
        """ 上传队列批处理 """
        from client.analyzer import EVENT
        # 数据上传
        while True:
            event = EVENT.UPLOAD.get()
            if event is False:
                break
            self.__upload(event[0], event[1])

    def __dispatcher(self):
        """ 创建 批处理 线程 """
        # 尝试建立 TCP 连接
        if self.__connect() and self.__cert() and RUNTIME.RUNNING:
            # 上传数据
            uploader = threading.Thread(target=self.__upload_dispatch)
            self.dispatchers.append(uploader)
            uploader.start()

        # 等待数据上传结束
        self.__join()
        # 向服务器发送 结束报文
        self.logger.info('Send the end packet to server.')
        FRAME.send(self.sock, STAMP.END)
        # 关闭 socket
        SOCKET.close(self.sock)
        self.logger.info('...close the reporter socket...')

    def run(self):
        """ 启动 网络通信线程 """
        SESSION.load()
        threading.Thread(target=self.__dispatcher).start()

    def __join(self):
        for dispatcher in self.dispatchers:
            dispatcher.join()
