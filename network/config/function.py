# coding: utf-8

""" 定义常用的功能函数 和 功能类

- get_ip_regex():
  由于IPV4 和 IPv6 正则表达式过长, 因此将其分别放在配置文件 ipv4.regex 和
  ipv6.regex中, 使用该函数读取配置文件中的内容, 并转换成正则表达式。

- do_check_sum(packet):
  计算网络数据报文校验和。

- check_ip(ip):
  检查ip格式是否正确, 并区分ipv4/ipv6。

- get_host_ip():
  获取本机 ip
"""

import os
import re
import platform


def get_ip_regex():
    """ 获取 IPV4 和 IPV6 正则表达式 配置 """
    current_dir = os.path.dirname(os.path.realpath(__file__))

    def read(filename):
        ip_regex_file = current_dir + os.sep + filename
        with open(ip_regex_file, 'r') as f:
            return re.compile(f.readline().strip())
    return read('ipv4.regex'), read('ipv6.regex')


def do_check_sum(packet):
    """ 计算网络数据报文的校验和 """
    if not isinstance(packet, str):
        return 0
    packet = packet if len(packet) % 2 == 0 else packet + chr(0)
    chk_sum = 0
    location = 0
    while location < len(packet):
        # 将报文 划分成多个 16 位 的片段
        value = (ord(packet[location]) << 8) + ord(packet[location + 1])
        chk_sum = chk_sum + value
        location = location + 2
    chk_sum = (chk_sum >> 16) + (chk_sum & 0xffff)
    chk_sum = (chk_sum >> 16) + chk_sum
    return ~chk_sum & 0xffff


def check_ip(ip):
    """ 检查 ip 格式是否正确, 并区分ipv4/ipv6

    @param ip: ip
    @type  ip: string (ipv4/ipv6)

    @return: ip 的版本
    @rtype : IPV
    """
    from config.configure import IPV4_REGEX, IPV6_REGEX
    from packet import IPV
    if not isinstance(ip, str):
        return IPV.ERROR
    if re.match(IPV4_REGEX, ip) is not None:
        return IPV.IPV4
    if re.match(IPV6_REGEX, ip) is not None:
        return IPV.IPV6
    return IPV.ERROR


def get_host_ip():
    """ 获取 本机 ip """
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def get_dns_servers():
    """ 获取 本地 DNS 服务器 """
    name = platform.system()
    if name in {'Linux', 'Darwin'}:
        with open('/etc/resolv.conf', 'r') as dns_config:
            content = dns_config.readlines()
            dns_server = filter(lambda x: 'nameserver' in x, content)
            replace = r'(\#.*)|nameserver|\s+'
            dns_server = map(lambda x: re.sub(replace, '', x), dns_server)
            return dns_server
    elif name in {'Windows'}:
        pass
    else:
        return []


def get_check_list():
    """ 获取 需要检测的域名列表 """
    current_dir = os.path.dirname(os.path.realpath(__file__))
    check_list = current_dir + os.sep + 'check_list'
    with open(check_list, 'r') as f:
        comment = r'\s*#.*'
        domains = map(lambda x: x.strip(), f.readlines())
        domains = filter(lambda x: re.match(comment, x) is None, domains)
        return domains
