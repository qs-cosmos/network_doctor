# coding: utf-8

import socket
from core.packet.ip import IPV
from config.logger import Logger
from core.spider.https import DNSResolver
from core.spider.ping import ICMPing

print IPV.IPV6_REGEX
print IPV.check('10.8.120.252')

# Test ICMPing
domain = 'www.baidu.com'
Logger.sign_up(domain)

print '...Start testing ICMPing...'
ip = socket.gethostbyname(domain)
ip = '120.13.21.344'
#  icmping = ICMPing('2001:db8::1')
icmping = ICMPing()
icmping.config(ip)
icmping.config(interval=0.2)
for i in range(3):
    icmping.ping(seq=i)

print icmping.json()
print '...End testing ICMPing...'

# Test DNSResolver
resolver = DNSResolver()
resolver.config(domain)
resolver.resolve()
print resolver.json()
print resolver.ips()

# Test app
