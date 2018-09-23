# coding: utf-8

from config.constant import FILE
from config.runtime import RUNTIME
from core.packet.ip import REGEX

print(FILE.module(__file__))

RUNTIME.load()
print RUNTIME.CHECK_LIST

RUNTIME.add('www.baidu.com')
RUNTIME.delete('www.baidu.com')
RUNTIME.update()
