# coding: utf-8

import socket
from config.configure import CHECK_LIST
from tools.https import DNSResolver
from tools.ping import ICMPing


class Scheduler(object):
    """ 网络检查 调度器——One link One scheduler """
    def __init__(self, domain):
        self.domain = domain
        self.dns_resolver = DNSResolver(domain)
        self.icmpings = []

    def run(self, ping_count=100):
        """运行调度器

        @param ping_count: 进行 ICMPing 的次数
        @type  ping_count: int

        @return:  Description
        @rtype :  Type

        @raise e:  Description
        """
        try:
            self.dns_resolver.resolve()
            # 获取 DNS 解析结果
            # 此处暂由 socket.gethostbyname_ex 获取
            ips = socket.gethostbyname_ex(self.domain)[2]

            def icmping(ip):
                ping = ICMPing(ip)
                for i in range(ping_count):
                    ping.ping(seq=i)
                return {'ip': ip, 'records': map(self.json, ping.records)}
            self.icmpings = map(icmping, ips)
        except socket.error as e:
            print 'Error: %s' % e

    def json(self, record):
        return record.json()

    def result(self):
        """ 组织 网络检查 结果 """
        return {
            'dns': map(lambda x: x.json(), self.dns_resolver.records),
            'icmping': self.icmpings
        }


def run():
    """ 总调度程序 """
    result = {}
    for domain in CHECK_LIST:
        scheduler = Scheduler(domain)
        scheduler.run(ping_count=1)
        result[domain] = scheduler.result()
    return result


if __name__ == '__main__':
    with open('result.json', 'w') as store:
        import json
        store.write(json.dumps(run(), sort_keys=True,
                    indent=4, separators=(',', ':')))
