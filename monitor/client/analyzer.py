# coding: utf-8

""" 数据解析检查

基本思路:
- 数据来源: Spider 结果队列
- 数据解析: 一个结果队列拥有一个分析器, 一个分析器属于一个线程。
- 数据同步: 上传队列 和 状态列表
    - 上传队列: 待经过 通信框架 上传的数据
    - 状态列表: 用户界面展示内容
"""

import threading
from Queue import Queue
from client.network import STAMP
from client.spider import RESULT
from config.logger import Logger


class EVENT(object):
    UPLOAD = Queue()        # 上传队列
    STATUS = {}             # 状态列表

    @staticmethod
    def end():
        """ 添加 队列结束符 """
        EVENT.UPLOAD.put(False)


class Analyzer(object):
    """ 结果队列处理器 """
    def __init__(self):
        self.logger = Logger.get()
        self.dispatchers = []

    def __dns(self, dns):
        """ 分析 DNS 结果 """
        self.logger.info('Start analysing dns resolve result.')
        EVENT.UPLOAD.put((STAMP.DNS_RESOLVE, dns))
        self.logger.info('Add a dns resolve result to upload queue.')

    def __icmping(self, icmping):
        """ 分析 ICMPING 结果 """
        self.logger.info('start analysing imcping result.')
        EVENT.UPLOAD.put((STAMP.ICMPING, icmping))
        self.logger.info('Add a icmping result to upload queue.')

    def __dispatch(self, queue, target):
        """ 批处理 """
        while True:
            result = queue.get()
            if result is False:
                self.logger.info('...stop analysing...')
                break
            target(result)

    def __dispatcher(self, queue, target):
        """ 创建 数据分析线程 """
        args = (queue, target)
        dispatcher = threading.Thread(target=self.__dispatch, args=args)
        dispatcher.start()
        self.dispatchers.append(dispatcher)

    def run(self):
        """ 启动 数据解析线程 """
        # DNS 结果分析线程
        self.__dispatcher(RESULT.DNS, self.__dns)
        self.logger.info('Create a analyser thread for dns result.')
        self.__dispatcher(RESULT.ICMPING, self.__icmping)
        self.logger.info('Create a analyser thread for icmping result.')
