# coding: utf-8

""" 定义 Client 与 Server 通信的数据结构

Client 通信数据结构 —— json 格式:
  - TYPE    : 消息类型
  - ID      : 客户端 ID
  - MESSAGE : 消息内容
"""


class ClientMessageType(object):
    AUTHENTICATE = 1        # 请求身份验证
    NETWORK_DATA = 2        # 客户端检测的数据
    DATA_COMPLETED = 3      # 数据传输结束
    DATA_LENGTH = 4         # 数据长度


class ClientMessage(object):
    """ Client 发送的信息 """
    TYPE = 'TYPE'          # 消息类型
    ID = 'ID'              # Client ID
    MESSAGE = 'MESSAGE'    # 消息内容
    LENGTH = 'LENGTH'      # 指定消息长度

    @staticmethod
    def construct(Type=1, ID=-1, Message='', Length=0):
        """ 构建 Client 发送的消息 """
        new_message = {ClientMessage.TYPE: Type}
        if Type == ClientMessageType.AUTHENTICATE:
            new_message[ClientMessage.ID] = ID
        elif Type == ClientMessageType.NETWORK_DATA:
            new_message[ClientMessage.MESSAGE] = Message
        elif Type == ClientMessageType.DATA_LENGTH:
            new_message[ClientMessage.LENGTH] = Length
        return repr(new_message)


class ServerMessageType(object):
    STATUS_OK = 1           # 数据接收成功
    STATUS_FAILED = 2       # 数据接收失败
    STATUS_NEW_ID = 3       # 身份验证失败, 为 Client 重新分配 ID


class ServerMessage(object):
    """ Server 发送的信息 """
    TYPE = 'TYPE'
    ID = 'ID'

    @staticmethod
    def construct(Type=1, ID=-1):
        """ 构建 Server 发送的信息 """
        new_message = {ServerMessage.TYPE: Type}
        if Type == ServerMessageType.STATUS_NEW_ID:
            new_message[ServerMessage.ID] = ID
        return repr(new_message)
