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
import socket
import threading
import time
from multiprocessing.dummy import Pool as ThreadPool
from config import server
from config.configure import CHECK_LIST, DNS_SERVERS, BUFF_SIZE
from config.function import get_runtime_file, check_ip
from config.function import get_client_id, update_client_id
from config.message import ClientMessage, ClientMessageType
from config.message import ServerMessage, ServerMessageType
from logger import Logger
from packet import IPV, Proto
from tools.https import DNSResolver
from tools.ping import ICMPing


class NetworkDoctorThread(object):
    """ One NetworkDoctor for One Domain. """
    def __init__(self, domain):
        """ 运行周期: 开始阶段 """
        self.logger = Logger.get()
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
        self.ping_params['count'] = 5

    def resolve(self):
        """ 运行周期: 检测 DNS 解析过程 """
        if self.domain is None:
            return
        Logger.sign_up(self.domain)
        self.logger = Logger.get()
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
            self.logger = Logger.get()
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

    def close(self):
        """ 运行周期: 结束阶段 """
        if self.domain is None:
            return
        Logger.sign_up(self.domain)
        # 发送运行周期结束标识符, 注销 logger
        Logger.log_out(FIN=True)

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
        self.logger = Logger.get()

        result = self.json()
        # 将检查结果存储到本地
        filepath = get_runtime_file(archive=self.domain,
                                    dirname='result',
                                    filename='network_doctor',
                                    filetype='json')
        with open(filepath, 'w') as f:
            f.write(json.dumps(result, sort_keys=True,
                    indent=4, separators=(',', ':')))

        # 发送运行周期结束标识符, 注销 logger
        Logger.log_out(FIN=True)

    def json(self):
        return {
            'domain': self.domain,
            'dns_servers': DNS_SERVERS,
            'ips': self.dns_resolver.ips(),
            'dns_resolvers': self.dns_resolver.json(),
            'icmpings': {k: v.json() for k, v in self.icmpings.iteritems()}
        }


def create_socket():
    """ 创建一个 进行 TCP 通信的 socket """
    logger = Logger.get()
    try:
        logger.info('Start to create a socket')
        ipv = check_ip(server.HOST)
        tcp = socket.getprotobyname(Proto.TCP)
        if ipv == IPV.ERROR:
            logger.error('Failed to create a socket ' +
                              'due to the wrong IP: %s' % (server.HOST))
            return None
        elif ipv == IPV.IPV4:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, tcp)
            sock.connect(server.ADDRESS)
            logger.info('Successfully connect to the server.')
            return sock
        elif ipv == IPV.IPV6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, tcp)
            sock.connect(server.ADDRESS)
            logger.info('Successfully connect to the server.')
            return sock
        else:
            logger.error('Failed to create a socket ' +
                              'due to a unknown error')
            return None
    except socket.error as e:
        logger.error('Failed to create a socket ' +
                          'due to the socket.error: %s' % (e))
        return None


def upload(doctors):
    """ 上传数据 """
    logger = Logger.get()
    logger.info('Start to upload the network doctors result.')
    sock = create_socket()
    if sock is None:
        return False
    # 进行身份身份认证
    client_id = get_client_id()
    client_message = ClientMessage.construct(
        Type=ClientMessageType.AUTHENTICATE, ID=client_id
    )
    # 暂未添加超时检测
    sock.send(client_message)
    server_message = eval(sock.recv(BUFF_SIZE))
    if server_message[ServerMessage.TYPE] == ServerMessageType.STATUS_NEW_ID:
        client_id = server_message[ServerMessage.ID]
        update_client_id(str(client_id))
    # 上传数据
    for doctor in doctors:
        message = ClientMessage.construct(
            Type=ClientMessageType.NETWORK_DATA, Message=doctor.json()
        )
        client_message = ClientMessage.construct(
            Type=ClientMessageType.DATA_LENGTH, Length=len(message)
        )
        sock.sendall(client_message)
        sock.sendall(message)
        server_message = eval(sock.recv(BUFF_SIZE))
        if server_message[ServerMessage.TYPE] ==\
                ServerMessageType.STATUS_FAILED:
            logger.error('Failed to upload the data.')
    client_message = ClientMessage.construct(
        Type=ClientMessageType.DATA_COMPLETED
    )
    sock.sendall(client_message)
    return True


def scheduler(thread_amount=25, sleep=10):
    """ 运行周期 调度程序"""
    def thread_pool(run, tasks, amount=thread_amount):
        if len(tasks) == 0:
            return []
        if len(tasks) < amount:
            amount = len(tasks)
        thread_pool = ThreadPool(amount)
        result = thread_pool.map(run, tasks)
        thread_pool.close()
        thread_pool.join()
        return result
    while True:
        # 创建线程池 和 调度资源
        network_doctors = map(lambda x: NetworkDoctorThread(x), CHECK_LIST)
        # 检查 DNS 解析过程
        dst_ip_doctors = thread_pool(lambda x: x.resolve(), network_doctors)
        # 检查客户端 与 目的主机ip 之间的网络
        dst_ip_doctors = reduce(lambda x, y: x + y, dst_ip_doctors)
        thread_pool(lambda x: x(), dst_ip_doctors)
        # 存储结果至本地
        # thread_pool(lambda x: x.store(), network_doctors)
        thread_pool(lambda x: x.close(), network_doctors)
        # 上传数据至服务器
        upload(network_doctors)
        time.sleep(sleep)


if __name__ == '__main__':
    scheduler()
    #  app = NetworkDoctorThread()
    #  app.run('www.baidu.com')
    #  with open('result.json', 'w') as store:
    #      import json
    #      store.write(json.dumps(run(), sort_keys=True,
    #                  indent=4, separators=(',', ':')))
