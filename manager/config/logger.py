# coding: utf-8

import ConfigParser
import logging
import os
import sys
import thread
import threading
from config.constant import FILE


class LOG(object):
    # 运行日志基本配置
    PARSER = ConfigParser.ConfigParser()
    CONSOLE = 20
    FILE = 10
    LOWEST = 10
    OPEN_CONS = False
    OPEN_FILE = False

    @staticmethod
    def load(filename='base.conf'):
        """ 加载运行日志配置文件 """
        filepath = FILE.conf(filename)
        lock = threading.Lock()
        lock.acquire()
        try:
            LOG.PARSER.read(filepath)
            LOG.CONSOLE = LOG.PARSER.getint('logger', 'console')
            LOG.FILE = LOG.PARSER.getint('logger', 'file')
            LOG.LOWEST = LOG.PARSER.getint('logger', 'lowest')
            LOG.OPEN_CONS = LOG.PARSER.getboolean('logger', 'open_cons')
            LOG.OPEN_FILE = LOG.PARSER.getboolean('logger', 'open_file')
        except Exception:
            print 'Please check your logger configure file.'
        finally:
            lock.release()


def static_logger(**kwargs):
    """ 装饰器 - 添加属性

    @param kwargs: 待添加属性
    @type  kwargs: dict
    """
    LOG.load()

    def decrorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decrorate


@static_logger(logger={})
def getLogger(name='', FIN=False):
    """ 获取 全局静态Logger对象

    @param name: 日志标识名
    @type  name: string

    @param store: 开启文件日志
    @type  store: bool

    @param level: 指定日志的最低输出级别
    @type  level: int

    @param FIN: 当一个运行周期完成时, 注销 name 对应的 logger
    @type  FIN: bool

    @return: 日志标识名为 name 的 Logger 对象
    @rtype : logging.Logger
    """
    if name not in getLogger.logger.keys() and not FIN:
        # 获取 logger 实例, 如果参数为空则返回root logger
        logger = logging.getLogger(name)
        # 指定 logger 输出格式
        fmt = '[%(name)s]-%(asctime)s tid<%(thread)d> '\
              '[%(levelname)s] : %(message)s'
        datefmt = '%Y-%m-%d %H:%M:%S'
        formatter = logging.Formatter(fmt, datefmt)
        # 设置控制台日志处理器
        if LOG.OPEN_CONS:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            console_handler.setLevel(LOG.CONSOLE)
            logger.addHandler(console_handler)
        # 设置文件日志处理器
        if LOG.OPEN_FILE:
            file_handler = logging.FileHandler(FILE.new(name), mode='w')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(LOG.FILE)
            logger.addHandler(file_handler)
        # 设置最低日志级别
        logger.setLevel(LOG.LOWEST)
        # 将标识名为 name 的日志对象存储到 getLogger.logger 中
        getLogger.logger[name] = logger
    elif FIN:
        # 注销 name 对应的日志
        getLogger.logger.pop(name)
        return None

    return getLogger.logger[name]


class Logger(object):
    """ 注册域名 与 获取logger """
    # 记录已注册的 tid: client_id
    # 记录已注册的 pid: 进程名称
    RECORDS = {}

    @staticmethod
    def sign_up(name, TP=True):
        """ 一个 Id 只能注册一次

        @param TP: 线程ID: True or 进程ID: False
        @type  TP: bool
        """
        Id = thread.get_ident() if TP else os.getpid()
        lock = threading.Lock()
        lock.acquire()
        try:
            if Id not in Logger.RECORDS.keys():
                Logger.RECORDS[Id] = name
        finally:
            lock.release()

    @staticmethod
    def log_out(FIN=False):
        """ 注销 tid 与 domain 的关联并注销与 domain 关联的 logger.

        @param FIN: 完成一个运行周期的标识符
        @type  FIN: bool
        """
        tid = thread.get_ident()
        lock = threading.Lock()
        lock.acquire()
        try:
            if tid in Logger.RECORDS.keys():
                getLogger(Logger.RECORDS[tid], FIN=FIN)
                Logger.RECORDS.pop(tid)
        finally:
            lock.release()

    @staticmethod
    def get():
        """ 获取 logger

        说明:
        - 根据当前的 tid 从 RECORDS 中获取 domain;
        - 根据 domain 从 getLogger 获取 logger
        - 若不存在对应的 domain, 则默认返回 MAIN 对应的 logger
        """
        lock = threading.Lock()
        lock.acquire()
        try:
            id_ = thread.get_ident()
            if id_ not in Logger.RECORDS.keys():
                id_ = os.getpid()
            if id_ not in Logger.RECORDS.keys():
                return getLogger('MAIN')
            return getLogger(Logger.RECORDS[id_])
        finally:
            lock.release()
