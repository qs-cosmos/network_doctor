# coding: utf-8

""" NetworkDoctor Client

    Version: 0.0.1
    Status : 测试版

开发说明:

  NetworkDoctor 属于I/O密集型应用, 采用 Multi Thread Programming 提高效率

  关于 运行日志 的处理逻辑 With Multi Thread Programming
  - 线程开始运行时, 进行 线程id 与 所处理的domain(域名) 的注册;
  - 日志收集:
    - 进行注册后, 每个类可通过 当前的 线程id 获取 域名;
    - getLogger 是全局的 logger 管理函数, 根据域名从中 产生 或 得到 一个 logger.
  - 当线程 结束时, 注销 线程id 与 domain 的绑定。

  身份识别

  同步过程
"""

import json
from multiprocessing.dummy import Pool as ThreadPool
from config.configure import CHECK_LIST, DNS_SERVERS
from config.function import get_runtime_file
from logger import Logger
from tools.https import DNSResolver
from tools.ping import ICMPing


class NetworkDoctorThread(object):
    """ One NetworkDoctor for One Domain. """
    def __init__(self):
        self.dns_resolver = None
        self.icmpings = {}
        self.domain = None

        # 运行周期参数设定
        # dns_resolver
        self.dns_resolver_params = {}
        # 超时时间
        self.dns_resolver_params['timeout'] = 0.5
        # 重试次数
        self.dns_resolver_params['retry'] = 2
        # ping
        self.ping_params = {}
        # 间隔时间 单位: s
        self.ping_params['interval'] = 0.5
        # 超时时间 单位: s
        self.ping_params['timeout'] = 1
        # 运行次数
        self.ping_params['count'] = 1

    def run(self, domain):
        if domain is None:
            return
        # 注册
        Logger.sign_up(domain)
        self.domain = domain
        # 检测 DNS 解析过程
        self.dns_resolver = DNSResolver()
        self.dns_resolver.config(domain=domain,
                                 timeout=self.dns_resolver_params['timeout'],
                                 retry=self.dns_resolver_params['retry'])
        self.dns_resolver.resolve()
        # 对 DNS 解析得到的 IP 进行 ICMPing
        for ip in self.dns_resolver.ips():
            icmping = ICMPing()
            icmping.config(dst=ip,
                           interval=self.ping_params['interval'],
                           timeout=self.ping_params['timeout'])
            for i in range(self.ping_params['count']):
                icmping.ping()
            self.icmpings[ip] = icmping
        self.store()
        # 注销
        Logger.log_out()

    def json(self):
        return {
            'dns_servers': DNS_SERVERS,
            'ips': self.dns_resolver.ips(),
            'dns_resolvers': self.dns_resolver.json(),
            'icmpings': {k: v.json() for k, v in self.icmpings.iteritems()}
        }

    def store(self):
        if self.domain is None:
            return
        filepath = get_runtime_file(archive=self.domain,
                                    dirname='result',
                                    filename='network_doctor',
                                    filetype='json')
        with open(filepath, 'w') as f:
            f.write(json.dumps(self.json(), sort_keys=True,
                    indent=4, separators=(',', ':')))


def scheduler(thread_amount=10):
    """ 总调度程序"""
    def run(domain):
        network_doctor = NetworkDoctorThread()
        network_doctor.run(domain)

    if thread_amount > len(CHECK_LIST):
        thread_amount = len(CHECK_LIST)

    thread_pool = ThreadPool(thread_amount)
    thread_pool.map(run, CHECK_LIST)
    thread_pool.close()
    thread_pool.join()


if __name__ == '__main__':
    scheduler()
    #  app = NetworkDoctorThread()
    #  app.run('www.baidu.com')
    #  with open('result.json', 'w') as store:
    #      import json
    #      store.write(json.dumps(run(), sort_keys=True,
    #                  indent=4, separators=(',', ':')))
