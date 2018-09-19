# coding: utf-8
import time

from client.spider import Spider
from config.runtime import RUNTIME

RUNTIME.load()
print RUNTIME.CHECK_LIST
spider = Spider()
spider.run()

time.sleep(30)
RUNTIME.running(False)
