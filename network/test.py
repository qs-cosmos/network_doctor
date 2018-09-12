# coding: utf-8

import socket
from config.configure import IPV6_REGEX
from config.function import check_ip
from tools.ping import ICMPing
from tools.https import DNSResolver

print IPV6_REGEX
print check_ip('10.8.120.252')

# Test ICMPing

print '...Start testing ICMPing...'
ip = socket.gethostbyname('www.baidu.com')
#  icmping = ICMPing('2001:db8::1')
icmping = ICMPing(ip)
icmping.config(interval=0.2)
for i in range(3):
    icmping.ping()
    icmping.output()
icmping.close()
print '...End testing ICMPing...'

# Test DNSResolver
domain = 'www.baidu.com'
resolver = DNSResolver(domain)
resolver.resolve()
for record in resolver.records:
    print record.json()
