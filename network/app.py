# coding: utf-8

""" NetworkDoctor Client

    Name   : Network Doctor
    Version: 0.0.1
    Status : 测试版

开发说明:

  NetworkDoctor 属于I/O密集型应用, 采用 Multi Thread Programming 提高效率

  分阶段的 Multi Thread Programming
  - 第一阶段 : 检查 DNS 解析过程 —— One Domain One Thread
  - 第二阶段 : 检查 客户端 与 目的主机 ip 之间的网络 —— One IP One Thread
  - 第三阶段 : 存储 结果 —— One Doctor One Thread

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
import threading
from multiprocessing.dummy import Pool as ThreadPool
from config.configure import CHECK_LIST, DNS_SERVERS
from config.function import get_runtime_file
from logger import Logger
from tools.https import DNSResolver
from tools.ping import ICMPing


class NetworkDoctorThread(object):
    """ One NetworkDoctor for One Domain. """
    def __init__(self, domain):
        """ 运行周期: 开始阶段 """
        self.dns_resolver = None
        self.icmpings = {}
        self.domain = domain

        # 运行周期参数设定
        # dns_resolver
        self.dns_resolver_params = {}
        # 超时时间
        self.dns_resolver_params['timeout'] = 0.25
        # 重试次数
        self.dns_resolver_params['retry'] = 2
        # ping
        self.ping_params = {}
        # 间隔时间 单位: s
        self.ping_params['interval'] = 0.1
        # 超时时间 单位: s
        self.ping_params['timeout'] = 0.5
        # 运行次数
        self.ping_params['count'] = 10

    def resolve(self):
        """ 运行周期: 检测 DNS 解析过程 """
        if self.domain is None:
            return
        Logger.sign_up(self.domain)
        self.dns_resolver = DNSResolver()
        self.dns_resolver.config(domain=self.domain,
                                 timeout=self.dns_resolver_params['timeout'],
                                 retry=self.dns_resolver_params['retry'])
        self.dns_resolver.resolve()
        Logger.log_out()
        # 重新组织 DNS解析结果
        # 将每个ip与下一步运行的函数进行绑定
        # 目的: 便于开启新的线程池
        return map(self.run, self.dns_resolver.ips())

    def run(self, ip):
        """ 运行周期: 检测 客户端 与 目的主机ip 之间的网络"""
        def doctor():
            """ 作为中间函数, 不立即执行其中的检查过程, 便于进行多线程调度"""
            Logger.sign_up(self.domain)
            # 进行 ICMPing 检查
            icmping = ICMPing()
            icmping.config(dst=ip,
                           interval=self.ping_params['interval'],
                           timeout=self.ping_params['timeout'])
            for i in range(self.ping_params['count']):
                icmping.ping()
            lock = threading.Lock()
            lock.acquire()
            try:
                self.icmpings[ip] = icmping
            finally:
                lock.release()
            Logger.log_out()
        return doctor

    def store(self):
        """ 运行周期: 结束阶段

        基本说明:
        - 一个运行周期结束的标识是—— 当前运行周期内所有的结果都已经被保存下来;
        - 保存的形式多种多样, 将数据上传至指定服务器, 也属于 store 的一种形式;
        - 一个运行周期内, 以域名为单位生成运行日志, 运行周期结束时, 需要发送运行
          周期结束标识符, 注销日志对象, 为开启下一个运行周期作准备。
        """
        if self.domain is None:
            return
        Logger.sign_up(self.domain)

        filepath = get_runtime_file(archive=self.domain,
                                    dirname='result',
                                    filename='network_doctor',
                                    filetype='json')
        with open(filepath, 'w') as f:
            f.write(json.dumps(self.json(), sort_keys=True,
                    indent=4, separators=(',', ':')))

        # 发送运行周期结束标识符, 注销 logger
        Logger.log_out(FIN=True)

    def json(self):
        return {
            'dns_servers': DNS_SERVERS,
            'ips': self.dns_resolver.ips(),
            'dns_resolvers': self.dns_resolver.json(),
            'icmpings': {k: v.json() for k, v in self.icmpings.iteritems()}
        }


def scheduler(thread_amount=25):
    """ 运行周期 调度程序"""
    def thread_pool(run, tasks, amount=thread_amount):
        if len(tasks) < amount:
            amount = len(tasks)
        thread_pool = ThreadPool(amount)
        result = thread_pool.map(run, tasks)
        thread_pool.close()
        thread_pool.join()
        return result
    # 创建线程池 和 调度资源
    network_doctors = map(lambda x: NetworkDoctorThread(x), CHECK_LIST)
    # 检查 DNS 解析过程
    dst_ip_doctors = thread_pool(lambda x: x.resolve(), network_doctors)
    # 检查客户端 与 目的主机ip 之间的网络
    dst_ip_doctors = reduce(lambda x, y: x + y, dst_ip_doctors)
    thread_pool(lambda x: x(), dst_ip_doctors)

    # 存储结果
    thread_pool(lambda x: x.store(), network_doctors)


if __name__ == '__main__':
    scheduler()
    #  app = NetworkDoctorThread()
    #  app.run('www.baidu.com')
    #  with open('result.json', 'w') as store:
    #      import json
    #      store.write(json.dumps(run(), sort_keys=True,
    #                  indent=4, separators=(',', ':')))
