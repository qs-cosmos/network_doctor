# coding: utf-8
import time

from client.spider import Spider
from client.analyzer import Analyzer
from client.network import Reporter
from config.runtime import RUNTIME

if __name__ == '__main__':
    RUNTIME.load()
    print RUNTIME.CHECK_LIST
    # 数据监测
    spider = Spider()
    spider.run()
    # 数据分析
    analyser = Analyzer()
    analyser.run()
    # 网络通信
    reporter = Reporter()
    reporter.run()

    time.sleep(20)
    RUNTIME.end()
