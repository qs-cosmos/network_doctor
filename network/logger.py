# coding: utf-8

import logging
import sys


class Logger(object):
    """ 常用日志标识名列表 待定... """
    pass


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
def getLogger(name='', level=logging.INFO):
    """ 获取 全局静态Logger对象

    @param name: 日志标识名
    @type  name: string

    @param level: 指定日志的最低输出级别
    @type  level: int

    @return: 日志标识名为 name 的 Logger 对象
    @rtype : logging.Logger
    """
    if name not in getLogger.logger.keys():
        # 获取 logger 实例, 如果参数为空则返回root logger
        logger = logging.getLogger(name)
        # 指定 logger 输出格式
        fmt = '[%(name)-6s]-%(asctime)s tid<%(thread)d> '\
              '[%(levelname)s] : %(message)s'
        datefmt = '%Y-%m-%d %H:%M:%S'
        formatter = logging.Formatter(fmt, datefmt)
        # 设置控制台日志处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.formatter = formatter
        # 为 logger 添加 日志处理器
        logger.addHandler(console_handler)
        # 指定日志的最低输出级别
        logger.setLevel(level)
        # 将标识名为 name 的日志对象存储到 getLogger.logger 中
        getLogger.logger[name] = logger

    return getLogger.logger[name]


#  if __name__ == '__main__':
#      logger = getLogger('1')
#      logger.info('hello')
