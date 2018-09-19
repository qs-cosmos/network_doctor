# coding: utf-8

""" 客户端运行参数 """

import json
import os
import platform
import re
import socket
import threading
from config.constant import FILE, JSON
from core.packet.ip import IPV


class RUNTIME(object):
    """ 运行数据 """
    FILEPATH = FILE.module(__file__) + 'runtime.json'
    CHECK_LIST = []
    ID = -1
    RUNNING = True                                      # 运行状态
    THREADS = 0                                         # 活跃任务线程数

    @staticmethod
    def load():
        """ 加载运行时数据存储文件 """
        lock = threading.Lock()
        lock.acquire()
        try:
            with open(RUNTIME.FILEPATH, 'r') as f:
                data = json.load(f)
                RUNTIME.CHECK_LIST = data.get('default_check_list', [])
                RUNTIME.CHECK_LIST = map(str, RUNTIME.CHECK_LIST)
                RUNTIME.ID = data.get('id', -1)
        finally:
            lock.release()

    @staticmethod
    def update():
        """ 更新运行数据存储文件 """
        lock = threading.Lock()
        lock.acquire()
        try:
            with open(RUNTIME.FILEPATH, 'w') as f:
                data = {
                    'default_check_list': RUNTIME.CHECK_LIST,
                    'id': RUNTIME.ID
                }
                json.dump(data, f, sort_keys=JSON.SORT, indent=JSON.INDENT)
        finally:
            lock.release()

    @staticmethod
    def add(domain):
        """ 往 CHECK_LIST 中添加一个域名 """
        lock = threading.Lock()
        lock.acquire()
        try:
            if domain in {None, ''}:
                return False
            if domain not in RUNTIME.CHECK_LIST:
                RUNTIME.CHECK_LIST.append(domain)
                return True
            return False
        finally:
            lock.release()

    @staticmethod
    def delete(domain):
        """ 往 CHECK_LIST 中删除一个域名 """
        lock = threading.Lock()
        lock.acquire()
        try:
            if domain in {None, ''}:
                return False
            if domain in RUNTIME.CHECK_LIST:
                RUNTIME.CHECK_LIST.remove(domain)
                return True
            return False
        finally:
            lock.release()

    @staticmethod
    def running(status):
        lock = threading.Lock()
        lock.acquire()
        try:
            RUNTIME.RUNNING = status
        finally:
            lock.release()


class OS(object):
    LINUX = 'Linux'
    WINDOWS = 'Windows'
    MACOS = 'Darwin'


def ip():
    ip = '127.0.0.1'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
        return ip


def dns():
    dns = []
    system = platform.system()
    if system in {OS.LINUX, OS.MACOS}:
        with open('/etc/resolv.conf', 'r') as dns_config:
            content = dns_config.readlines()
            dns = filter(lambda x: 'nameserver' in x, content)
            over = r'(\#.*)|nameserver|\s+'
            dns = map(lambda x: re.sub(over, '', x), dns)
    elif system in {OS.WINDOWS}:
        ipconfig = os.popen('ipconfig /all').read()
        regex = r'[d|D][n|N][s|S].*:(\s*((' + \
                IPV.IPV4_REGEX.pattern + ')|(' + \
                IPV.IPV6_REGEX.pattern + '))\s*\n?\s*)+'
        over = r'([d|D][n|N][s|S].*:\s+)|\s+|%.*'
        records = [rd.group() for rd in re.finditer(regex, ipconfig)]
        records = reduce(lambda x, y: x + '\n' + y, records).\
                  strip().split('\n')
        dns = map(lambda x: re.sub(over, '', x), records)
    return filter(lambda x: x not in {'127.0.0.1', '', None}, dns)


class CLIENT(object):
    """ 运行客户端配置 """

    OS = platform.system()
    IP = ip()
    DNS = dns()

    @staticmethod
    def update():
        lock = threading.Lock()
        lock.acquire()
        try:
            CLIENT.OS = platform.system()
            CLIENT.IP = ip()
            CLIENT.DNS = dns()
        finally:
            lock.release()
