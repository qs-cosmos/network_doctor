# coding: utf-8
""" 网络报文解析常量: 值 和 函数 """


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
