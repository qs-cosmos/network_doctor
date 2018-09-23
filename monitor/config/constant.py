# coding: utf-8

""" 定义通用不变量: 值 和 函数 """

import os
import select
import socket
import sys
import time
import timeit


class FILE(object):

    @staticmethod
    def module(__file__=__file__):
        """ 获取模块所在绝对路径: 默认返回constant模块所在绝对路径 """
        return os.path.dirname(os.path.realpath(__file__)) + os.sep

    @staticmethod
    def main():
        """ 获取主执行文件绝对路径 """
        return os.path.dirname(os.path.realpath(sys.argv[0])) + os.sep

    @staticmethod
    def new(archive='', dirname='log', filename='monitor', filetype='log'):
        """ 根据当前时间, 创建一个新文件

        @param archive: 文件归档名
        @type  archive: string

        @param dirname: 基本路径
        @type  dirname: string

        @param name: 文件前缀名
        @type  name: string

        @param filetype: 文件后缀名
        @type  filetype: string

        @return: 文件路径
        @rtype : string
        """
        # 获取当前时间单位: s
        date = time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime())
        # 构成文件名
        filename = filename + '_' + date + \
                   ('' if filetype in {None, ''} else '.' + filetype)
        # 获取执行路径, 并以执行路径作为起点
        basic_dir = FILE.main() + dirname + os.sep + archive
        if not os.path.exists(basic_dir):
            os.makedirs(basic_dir)
        filepath = basic_dir + os.sep + filename
        return filepath

    @staticmethod
    def conf(filename):
        """ 获取配置文件路径 """
        return FILE.main() + 'config' + os.sep + filename


class JSON(object):
    """ json 输出格式 """
    SORT = True
    INDENT = 4
    SEP = (',', ':')


class PROTO(object):
    """ socket 协议类型 """
    ICMP = socket.getprotobyname('icmp')
    UDP = socket.getprotobyname('udp')
    TCP = socket.getprotobyname('tcp')


class SOCKET(object):

    @staticmethod
    def create(ip, proto):
        """ 创建一个socket """
        try:
            from core.packet.ip import IPV
            from config.logger import Logger
            logger = Logger.get()
            sock = None
            ipv = IPV.check(ip)
            if ipv == IPV.ERROR:
                error = 'Failed to create a socket due to the wrong ip: %s.'
                logger.error(error % (ip))
                return sock
            addrs = socket.AF_INET if ipv == IPV.IPV4 else socket.AF_INET6
            if proto == PROTO.ICMP:
                if ipv == IPV.IPV6:
                    error = 'Failed to create a socket due to the wrong ip: %s'
                    logger.error(error % (ip))
                    return None
                sock = socket.socket(addrs, socket.SOCK_RAW, proto)
            if proto == PROTO.UDP:
                sock = socket.socket(addrs, socket.SOCK_DGRAM, proto)
            if proto == PROTO.TCP:
                sock = socket.socket(addrs, socket.SOCK_STREAM, proto)
            logger.info('Successfully create a socket.')
            return sock
        except Exception:
            logger.exception('Failed to create a socket.')
            return None

    @staticmethod
    def recvfrom(sock, timeout, size=4096):
        """ 接收一个报文(0~4096 bytes) """
        from config.logger import Logger
        logger = Logger.get()
        if timeout < 0:
            logger.warning('Waiting for the packet timeout.')
            return (-1, None)
        try:
            readable = select.select([sock], [], [], timeout)[0]
        except Exception:
            logger.exception('Failed to receive a packet.')
            return (-2, None)
        if len(readable) == 0:
            logger.warning('Waiting for the packet timeout.')
            return (-1, None)

        # 参考: https://stackoverflow.com/questions/52288283
        byte_stream = bytearray(size)
        nbytes = 0
        recv_time = 0
        try:
            nbytes, addr = sock.recvfrom_into(byte_stream)
            recv_time = timeit.default_timer()
            logger.info('Successfully receive a packet.')
        except Exception:
            logger.exception('Failed to receive a packet.')
            return (-3, None)
        packet = ''
        for i in range(nbytes):
            packet = packet + chr(byte_stream[i])
        return (recv_time, packet)

    @staticmethod
    def close(sock):
        """ 关闭一个 socket """
        if sock is not None:
            sock.close()
        return None


class PORT(object):
    """ 常用端口号 """
    DNS = 53
    HTTP = 80
    HTTPS = 443
