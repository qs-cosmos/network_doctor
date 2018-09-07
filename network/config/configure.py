# coding: utf-8

from config.function import get_ipv6_regex

# IPv4 / IPv6 正则表达式
IPV4_REGEX = r'(\d{1,3}(\.\d{1,3}){3})'
IPV6_REGEX = get_ipv6_regex()
