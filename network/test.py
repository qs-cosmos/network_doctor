# coding: utf-8

import socket
from app import NetworkDoctorThread
from config.configure import IPV6_REGEX
from config.function import check_ip
from logger import Logger
from tools.ping import ICMPing
from tools.https import DNSResolver

print IPV6_REGEX
print check_ip('10.8.120.252')

# Test ICMPing
domain = 'www.baidu.com'
Logger.sign_up(domain)

print '...Start testing ICMPing...'
ip = socket.gethostbyname(domain)
#  icmping = ICMPing('2001:db8::1')
icmping = ICMPing()
icmping.config(ip)
icmping.config(interval=0.2)
for i in range(3):
    icmping.ping(seq=i)

print icmping.json()
icmping.close()
print '...End testing ICMPing...'

# Test DNSResolver
resolver = DNSResolver()
resolver.config(domain)
resolver.resolve()
print resolver.json()
print resolver.ips()

# Test app
