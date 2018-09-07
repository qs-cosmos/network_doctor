# coding: utf-8

from config.configure import IPV6_REGEX
from config.function import check_ip
from tools.ping import ICMPing

print IPV6_REGEX
print check_ip('10.8.120.252')

icmping = ICMPing('10.8.120.46')
icmping.ping()
