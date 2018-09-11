# coding: utf-8

from config.function import get_ip_regex, get_host_ip, get_dns_servers

# IPv4 / IPv6 正则表达式
IPV4_REGEX, IPV6_REGEX = get_ip_regex()

# 本机网络环境
HOST_IP = get_host_ip()
DNS_SERVERS = get_dns_servers()


class Port(object):
    """ 常用端口号 """
    DNS = 53
    HTTP = 80
