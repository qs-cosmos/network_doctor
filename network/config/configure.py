# coding: utf-8

from config.function import get_ip_regex, get_host_ip, get_dns_servers
from config.function import get_check_list


# 操作系统类型
class OSType(object):
    WINDOWS = 'Windows'
    LINUX = 'Linux'
    MACOS = 'Darwin'


# TCP/IP 协议常量枚举类
class Port(object):
    """ 常用端口号 """
    DNS = 53
    HTTP = 80


# IPv4 / IPv6 正则表达式
IPV4_REGEX, IPV6_REGEX = get_ip_regex()

# 本机网络环境
HOST_IP = get_host_ip()
DNS_SERVERS = get_dns_servers()

# 客户应用程序配置
CHECK_LIST = get_check_list()
