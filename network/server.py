# coding: utf-8

""" NetworkDoctor Server

    Name   : Network Doctor
    Version: 0.0.1
    Status : 测试版

开发说明(v0.0.1 测试版):
  NetworkDoctor Server 分为主要分为两个处理进程:
  1. 数据接收与存储 进程 —— 负责与 Client 之间的通信
  - 进行 Client 的身份识别:
    Client 与 Server 第一次开始通信时, 由 Server 端随机生成一个10位数作为永久的
    Client ID。Server 端保存一个已分配 Client ID 列表, 每个 Client ID 的 TTL 为
    2 天, 如果某个 Client ID 已经2天没有与 Server 端进行过通信, 则从 Client ID
    列表中删除, Client ID 更新时间 00:00
  - 接收和存储 Client 上传的数据:
    存储形式: 文件列表
    存储结构:
    result | log
    - client id
      - network_doctor_date.json
  - 通信数据格式 (v0.0.1 测试版中暂不定义)
  2. 数据处理与展示 进程(v0.0.1 测试版中暂不支持)
"""

import json
import random
import select
import SocketServer
import time

from config.configure import BUFF_SIZE
from config.server import ADDRESS, CLIENT_IDS, MAX_ID, MIN_ID
from config.message import ClientMessage, ClientMessageType
from config.message import ServerMessage, ServerMessageType
from config.function import get_runtime_file
from logger import Logger


class ClientHandler(SocketServer.BaseRequestHandler):
    """ Client 通信处理类 """
    def init(self):
        message = eval(self.request.recv(BUFF_SIZE))
        if message[ClientMessage.TYPE] == ClientMessageType.AUTHENTICATE:
            Id = message[ClientMessage.ID]
            self.client_id = self.get_client_id(Id)
        Logger.sign_up(str(self.client_id))
        self.logger = Logger.get()

    def handle(self):
        self.init()
        self.logger.info('Start to listen client: %d' % self.client_id)

        # 初始化
        while True:
            message = eval(self.request.recv(BUFF_SIZE))

            if message[ClientMessage.TYPE] == ClientMessageType.DATA_LENGTH:
                length = message[ClientMessage.LENGTH]
                message = ''
                while length > 0:
                    receive = self.request.recv(BUFF_SIZE)
                    length = length - len(receive)
                    message = message + receive
                message = eval(message)

            if message[ClientMessage.TYPE] == ClientMessageType.NETWORK_DATA:
                result = message[ClientMessage.MESSAGE]
                domain = result['domain']
                import os
                archive = str(self.client_id) + os.sep + domain
                # 将检查结果存储到本地
                filepath = get_runtime_file(archive=archive,
                                            dirname='result',
                                            filename='network_doctor',
                                            filetype='json')
                with open(filepath, 'w') as f:
                    f.write(json.dumps(result, sort_keys=True,
                            indent=4, separators=(',', ':')))

                response = ServerMessage.construct(
                    Type=ServerMessageType.STATUS_OK
                )
                self.request.sendall(response)

            if message[ClientMessage.TYPE] == ClientMessageType.DATA_COMPLETED:

                self.logger.info('End listening client: %d' % self.client_id)
                break

    def get_client_id(self, ID):
        message = ''
        if ID not in CLIENT_IDS:
            # 获取 新的 ID 并发送给客户端
            ID = random.randint(MIN_ID, MAX_ID)
            while ID in CLIENT_IDS:
                ID = random.randint(MIN_ID, MAX_ID)
            CLIENT_IDS.add(ID)
            message = ServerMessage.construct(
                Type=ServerMessageType.STATUS_NEW_ID, ID=ID
            )
        else:
            message = ServerMessage.construct(Type=ServerMessageType.STATUS_OK)
        self.request.sendall(message)
        return ID


def run():
    """ 启动 Network Doctor 服务进程 """
    logger = Logger.get()
    logger.info('...Start server...')
    random.seed(time.time())
    server = SocketServer.ThreadingTCPServer(ADDRESS, ClientHandler)
    server.serve_forever()


if __name__ == '__main__':
    run()
