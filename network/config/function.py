# coding: utf-8

""" 定义常用的功能函数 和 功能类

- get_ipv6_regex():
  由于IPv6 正则表达式过长, 因此将其单独放在配置文件ipv6.regex中, 使用该函数读取
  配置文件中的内容, 并转换成正则表达式。

- do_check_sum(packet):
  计算网络数据报文校验和。

- check_ip(ip):
  检查ip格式是否正确, 并区分ipv4/ipv6。
"""

import os
import re


def get_ipv6_regex():
    """ 获取 IPV6 正则表达式 配置 """
    current_dir = os.path.dirname(os.path.realpath(__file__))
    ipv6_regex_file = current_dir + os.sep + 'ipv6.regex'
    with open(ipv6_regex_file, 'r') as f:
        return re.compile(f.readline().strip())


def do_check_sum(packet):
    """ 计算网络数据报文的校验和 """
    if not isinstance(packet, str):
        return 0
    packet = packet if len(packet) % 2 == 0 else packet + chr(0)
    chk_sum = 0
    location = 0
    while location < len(packet):
        # 将报文 划分成多个 16 位 的片段
        value = ord(packet[location] << 8) + ord(packet[location + 1])
        chk_sum = chk_sum + value
        location = location + 2
    chk_sum = (chk_sum >> 16) + (chk_sum & 0xffff)
    chk_sum = (chk_sum >> 16) + chk_sum
    chk_sum = ~chk_sum & 0xffff
    chk_sum = (chk_sum >> 8) + (chk_sum << 8 & 0xff00)
    return chk_sum


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
