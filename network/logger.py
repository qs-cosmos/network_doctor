# coding: utf-8

import logging
import sys
import thread
import threading
from config.function import get_runtime_file


def static_logger(**kwargs):
    """ 装饰器 - 添加属性

    @param kwargs: 待添加属性
    @type  kwargs: dict
    """
    def decrorate(func):
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decrorate


@static_logger(logger={})
def getLogger(name='', level=logging.DEBUG, FIN=False):
    """ 获取 全局静态Logger对象

    @param name: 日志标识名
    @type  name: string

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
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.WARNING)
        # 设置文件日志处理器
        file_handler = logging.FileHandler(get_runtime_file(name), mode='w')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        # 为 logger 添加 日志处理器
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        logger.setLevel(level)
        # 将标识名为 name 的日志对象存储到 getLogger.logger 中
        getLogger.logger[name] = logger
    elif FIN:
        # 注销 name 对应的日志
        getLogger.logger.pop(name)
        return None

    return getLogger.logger[name]


class Logger(object):
    """ 注册域名 与 获取logger """
    RECORDS = {}    # 记录已注册的 tid: domain

    @staticmethod
    def sign_up(domain):
        """ 一个 tid 只能注册一次 """
        tid = thread.get_ident()
        lock = threading.Lock()
        lock.acquire()
        try:
            if tid not in Logger.RECORDS.keys():
                Logger.RECORDS[tid] = domain
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
        tid = thread.get_ident()
        lock = threading.Lock()
        lock.acquire()
        try:
            if tid in Logger.RECORDS.keys():
                domain = Logger.RECORDS[tid]
                return getLogger(domain)
            else:
                return getLogger('MAIN')
        finally:
            lock.release()
