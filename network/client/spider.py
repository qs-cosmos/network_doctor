# coding: utf-8


""" 数据监测调度

基本思路:
- 采用 任务队列与调度器 机制
    - 每个调度器面向一个任务队列, 调度器内部多线程处理任务;
    - 不同调度器采取不同的休眠周期, 预留提前结束休眠机制;
    - 不同调度器之间通过任务队列同步处理信号;
    - 每个调度器维护一个公共的结果队列, 供外部访问。
"""

from queue import Queue
import threading
import time
import ConfigParser
from multiprocessing.dummy import Pool as ThreadPool
from config.constant import FILE
from config.logger import Logger
from config.runtime import RUNTIME
from core.spider.https import DNSResolver
from core.spider.ping import ICMPing


class CONF(object):
    """ 数据监测过程配置 """
    # 配置文件解析器
    PARSER = ConfigParser.ConfigParser()

    # 运行配置
    SPIDER_MAX_THREADS = 20
    SPIDER_MIN_THREADS = 5
    SPIDER_DNS = 300
    SPIDER_ICMPING = 10

    # DNS
    DNS_TIMEOUT = 0.25
    DNS_RETRY = 2

    # ICMPing
    ICMPING_INTERVAL = 0.1
    ICMPING_TIMEOUT = 0.5
    ICMPING_RETRY = 5

    @staticmethod
    def load(filename='spider.conf'):
        logger = Logger.get()
        filepath = FILE.module(__file__) + filename
        lock = threading.Lock()
        lock.acquire()
        try:
            logger.info('Start to load the spider configure.')
            CONF.PARSER.read(filepath)
            # 运行配置
            CONF.SPIDER_DNS = CONF.PARSER.getfloat('spider', 'dns')
            CONF.SPIDER_ICMPING = CONF.PARSER.getfloat('spider', 'icmping')
            CONF.SPIDER_MAX_THREADS = CONF.PARSER.getint('spider', 'max')
            CONF.SPIDER_MIN_THREADS = CONF.PARSER.getint('spider', 'min')
            # DNS Resolver
            CONF.DNS_TIMEOUT = CONF.PARSER.getfloat('dns_resolver', 'timeout')
            CONF.DNS_RETRY = CONF.PARSER.getint('dns_resolver', 'retry')
            # ICMPing
            CONF.ICMPING_INTERVAL = CONF.PARSER.getfloat('icmping', 'interval')
            CONF.ICMPING_TIMEOUT = CONF.PARSER.getfloat('icmping', 'timeout')
            CONF.ICMPING_RETRY = CONF.PARSER.getint('icmping', 'retry')
            logger.info('Successfully load the spider configure.')
            return True
        except Exception:
            logger.info('Please check your spider configure.')
            logger.exception('Failed to load the spider configure.')
            return False
        finally:
            lock.release()

    @staticmethod
    def update(section, option, value, filename='spider.conf'):
        logger = Logger.get()
        filepath = FILE.module(__file__) + filename
        lock = threading.Lock()
        lock.acquire()
        try:
            logger.info('Start to update the spider configure.')
            CONF.PARSER.read(filepath)
            CONF.PARSER.set(section, option, value)
            # DNS Resolver
            logger.info('Successfully update the spider configure.')
            return True
        except Exception:
            logger.exception('Failed to update the spider configure.')
            return False
        finally:
            lock.release()

    @staticmethod
    def apply(amount):
        """ 申请可用任务线程数 """
        lock = threading.Lock()
        lock.acquire()
        try:
            remain = CONF.SPIDER_MAX_THREADS - RUNTIME.THREADS
            if amount > remain and amount > CONF.SPIDER_MIN_THREADS:
                amount = CONF.SPIDER_MIN_THREADS
            RUNTIME.THREADS = RUNTIME.THREADS + amount
            return amount
        finally:
            lock.release()

    @staticmethod
    def release(amount):
        """ 释放任务线程数 """
        lock = threading.Lock()
        lock.acquire()
        try:
            RUNTIME.THREADS = RUNTIME.THREADS - amount
            if RUNTIME.THREADS < 0:
                RUNTIME.THREADS = 0
        finally:
            lock.release()


class TASK(object):
    """ 任务队列 """
    DNS = RUNTIME.CHECK_LIST
    IPS = []

    @staticmethod
    def load():
        """ 初始化加载 """
        TASK.DNS = RUNTIME.CHECK_LIST

    @staticmethod
    def add(queue, task):
        """ 向任务队列中添加一个任务

        @param queue: 任务队列
        @type  queue: []

        @param task: 任务
        @type  task: 与 任务队列 中的元素类型相同 或 []
        """
        logger = Logger.get()
        lock = threading.Lock()
        lock.acquire()
        try:
            def _add(t):
                if t not in queue:
                    queue.append(t)
            if isinstance(task, list):
                map(_add, task)
            else:
                _add(task)
        except Exception:
            logger.info('map: the type of task is: %s' % type(task))
            logger.exception('Maybe failed to map the task.')
        finally:
            lock.release()

    @staticmethod
    def die(queue, perk):
        """ 删除过期的任务

        @param queue: 任务队列
        @type  queue: []

        @param perk: 过滤器
        @type  perk: function
        """
        logger = Logger.get()
        lock = threading.Lock()
        lock.acquire()
        try:
            queue = filter(perk, queue)
        except Exception:
            logger.info('filter: the type of queue is: %s' % type(queue))
            logger.exception('Failed to filter the task queue.')
        finally:
            lock.release()


class RESULT(object):
    """ 结果队列 """
    DNS = Queue()
    ICMPING = Queue()

    @staticmethod
    def add(queue, result):
        """ 添加一个结果 """
        lock = threading.Lock()
        lock.acquire()
        try:
            queue.put(result)
        finally:
            lock.release

    @staticmethod
    def get(queue):
        """ 获取一个结果 """
        lock = threading.Lock()
        lock.acquire()
        result = None
        try:
            if len(queue) > 0:
                result = queue.get()
        finally:
            lock.release()
            return result


class Spider(object):
    """ 数据监测总调度类 """
    def __init__(self):
        CONF.load()
        TASK.load()

        self.logger = Logger.get()
        self.dispatchers = []

    def __dispatch(self, run, tasks):
        """ 线程池: 分发任务

        @param run: 任务执行方法
        @type  run: function

        @param tasks: 任务队列
        @type  tasks: []

        @param threads: 最大线程数
        @type  threads: int
        """
        lock = threading.Lock()
        lock.acquire()
        pool = None
        amount = 0
        try:
            amount = len(tasks)
            if amount == 0:
                return
            amount = CONF.apply(amount)
            pool = ThreadPool(amount)
            pool.map(run, tasks)
        except Exception:
            self.logger.exception('Failed to dispatch task.')
        finally:
            CONF.release(amount)
            lock.release()
        if pool is not None:
            pool.close()
            pool.join()

    def __dns(self, domain):
        """ DNS解析执行方法 """
        Logger.sign_up(domain)
        logger = Logger.get()
        resolver = DNSResolver()
        resolver.config(domain, CONF.DNS_TIMEOUT, CONF.DNS_RETRY)
        resolver.resolve()

        # 将解析结果导出结果队列
        result = {domain: resolver.json()}
        RESULT.add(RESULT.DNS, result)
        # 将得到的 ip 导入任务队列
        try:
            ips = map(lambda x: (domain, x), resolver.ips())

            def perk(ip):
                return ip not in ips
            TASK.die(TASK.IPS, perk)
            TASK.add(TASK.IPS, ips)
        except Exception:
            logger.info('map: the type of ips is: %s' % type(resolver.ips()))
            logger.exception('Failed to map the ips to (domain, ip).')
        finally:
            Logger.log_out()

    def __icmping(self, ip):
        """ ICMPing 执行方法 """
        domain, ip = ip
        Logger.sign_up(domain)
        icmping = ICMPing()
        icmping.config(ip, CONF.ICMPING_INTERVAL, CONF.DNS_TIMEOUT)
        for _ in range(CONF.ICMPING_RETRY):
            icmping.ping()
        result = {domain: {'ip': ip, 'icmping': icmping.json()}}
        RESULT.add(RESULT.ICMPING, result)
        Logger.log_out()

    def __dns_dispatch(self):
        """ DNS 批处理 """
        while RUNTIME.RUNNING:
            self.__dispatch(self.__dns, TASK.DNS)
            if not RUNTIME.RUNNING:
                break
            try:
                info = 'dns dispatcher: sleeping for %f s.'
                self.logger.info(info % CONF.SPIDER_DNS)
                time.sleep(CONF.SPIDER_DNS)
            except Exception:
                self.logger.exception('..dns dispatcher failed to sleep ..')

    def __icmping_dispatch(self):
        """ ICMPing 批处理 """
        while RUNTIME.RUNNING:
            self.__dispatch(self.__icmping, TASK.IPS)
            if not RUNTIME.RUNNING:
                break
            try:
                info = 'icmping dispatcher: sleeping for %f s.'
                self.logger.info(info % CONF.SPIDER_ICMPING)
                time.sleep(CONF.SPIDER_ICMPING)
            except Exception:
                self.logger.exception('..icmping dispatcher failed to sleep..')

    def __dispatcher(self, target, args=()):
        """ 创建调度线程 """
        dispatcher = threading.Thread(target=target, args=args)
        # 设置 守护线程, 当主线程退出时
        dispatcher.setDaemon(True)
        dispatcher.start()
        self.dispatchers.append(dispatcher)

    def run(self):
        """ 启动 网络监测线程 """
        # DNS 解析线器
        self.__dispatcher(self.__dns_dispatch)
        self.logger.info('Create a dispatcher for dns resolve.')
        # ICMPing 检查线程
        self.__dispatcher(self.__icmping_dispatch)
        self.logger.info('Create a dispatcher for icmping.')

    def join(self):
        for dispatcher in self.dispatchers:
            dispatcher.join()