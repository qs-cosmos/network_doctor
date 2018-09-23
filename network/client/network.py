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
        - 超时请求重传
        - 请求重传次数
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
        lock = lock.acquire()
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
    OK = 0                          # 接收完成确认
    RETRY = 1                       # 请求重传
    # 消息内容标识 (128~255)
    ID = 128                        # 会话 ID
    CLIENT = 129                    # 客户端基本配置
    DNS_RESOLVE = 130               # DNS 解析
    ICMPING = 131                   # ICMPing 结果


class TYPE:
    """ 数据类型 """
    NONE = 0                        # NoneType
    DICT = 1                        # dict (json数据)
    FLOAT = 2                       # float
    INT = 3                         # int
    STRING = 4                      # str

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
    def send(sock, stamp, data='', ack=True):
        """ 发送数据: ack 是否需要确认 """
        logger = Logger.get()
        envelope = FRAME.construct(stamp, data)
        status = 0
        try:
            sock.sendall(envelope)
            logger.info('Successfully send all the data.')
            if ack:
                logger.info('...waiting for a acknowledge...')
                status, data = FRAME.recv(sock, ack=False)
                if status < 0:
                    logger.warn('Failed to recevie a acknowledge.')
        except Exception:
            logger.exception('Failed to send all the data.')
            status = -5
        return status

    @staticmethod
    def recv(sock, ack=True):
        """ 接收数据: ack 是否需要发送一个确认

        @return: stamp, data
        @rtype : STAMP, TYPE.*
        """
        logger = Logger.get()
        remain = 0
        envelope = ''
        logger.info('Start to recveive a application data.')
        start = timeit.default_timer()

        # 接收数据头部
        logger.info('Waiting for a application data header.')
        while len(envelope) < 8:
            remain = SESSION.TIMEOUT - timeit.default_timer() + start
            recv_, data = SOCKET.recvfrom(sock, remain, size=SESSION.BUFF_SIZE)
            if recv_ < 0:
                logger.warn('Failed to get the application data header.')
                return (-1, None)
            envelope = envelope + data
        logger.info('Succeed to get the application data header.')

        # 解析数据头部
        stamp, type_, flags, _, length = FRAME.analysis(envelope)
        envelope = envelope[8:]
        if length < len(envelope):
            warn = 'The length of data fragment is bigger than expected.'
            logger.warn(warn)
            logger.warn('Failed to get the application data.')
            return (-2, None)

        # 接收数据段
        logger.info('Waiting for the application data fragment.')
        while length != len(envelope):
            remain = SESSION.TIMEOUT - timeit.default_timer() + start
            recv_, data = SOCKET.recvfrom(sock, remain, size=SESSION.BUFF_SIZE)
            if recv_ < 0:
                logger.warn('Failed to get the application data fragment.')
                return (-3, None)
            envelope = envelope + data
            if length < len(envelope):
                warn = 'The length of data fragment is bigger than expected.'
                logger.warn(warn)
                logger.warn('Failed to get the application data.')
                return (-2, None)
        logger.info('Succeed to get the application data fragment.')

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
        except Exception:
            logger.exception('Failed to analysis the application data.')
            return (-4, None)
        if ack:
            logger.info('...send a acknowledge...')
            FRAME.send(sock, STAMP.OK, ack=False)
        return (stamp, message)


class Reporter(object):
    """ 客户端: 封装客户端通信逻辑 """
    def __init__(self):
        self.logger = Logger.get()
        self.logger.info('Create a tcp communication socket.')
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
        while RUNTIME.RUNNING and self.id == -1:
            self.logger.info('Start to identify authenticate.')
            status = FRAME.send(self.sock, STAMP.ID, RUNTIME.ID)
            if status:
                stamp, self.id = FRAME.recv(self.sock)
            if (not status) or stamp < 0:
                self.logger.warn('Failed to identify authenticate.')
                self.id = -1
                # 休眠一秒后再进行通信
                self.logger.warn('...sleep for two seconds...')
                time.sleep(SESSION.CERT)
        if self.id == -1:
            return False
        RUNTIME.id(self.id)
        self.logger.info('Succeed to identify authenticate.')
        return True

    def __upload(self, stamp, data):
        """ 上传 客户端监测数据 """
        status = STAMP.RETRY
        retry = 0
        while status == STAMP.RETRY and retry < SESSION.RETRY:
            self.logger.info('...retry the %dth transimission...')
            retry = retry + 1
            status = FRAME.send(self.sock, stamp, data)
        return status

    def __upload_dispatch(self):
        """ 批处理 """
        from client.analyser import EVENT
        # 通信逻辑
        # 数据上传
        while True:
            event = EVENT.UPLOAD.get()
            if event is False:
                break
            self.__upload(event[0], event[1])

    def __dispatcher(self):
        """ 创建 批处理 线程 """
        # 尝试建立 TCP 连接
        if self.__connect() and self.__cert():
            # 上传数据
            uploader = threading.Thread(target=self.__upload_dispatch)
            uploader.start()

    def run(self):
        """ 启动 网络通信线程 """
        threading.Thread(target=self.__dispatcher).start()
