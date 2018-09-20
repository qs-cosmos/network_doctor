# coding: utf-8
import time

from client.spider import Spider
from config.runtime import RUNTIME

if __name__ == '__main__':
    RUNTIME.load()
    print RUNTIME.CHECK_LIST
    spider = Spider()
    spider.run()

    time.sleep(20)
    RUNTIME.running(False)
