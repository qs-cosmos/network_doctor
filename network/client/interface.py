# coding: utf-8

""" 客户端用户界面

Record  : Network Doctor v0.0.1 正式版
time    : 2018-09-20 14:30
Description :
    1. 添加 客户端 通知区域图标
    2. 提供 退出 客户端 按钮

"""
import os
from config.constant import FILE
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QDialog, QMenu, QSystemTrayIcon, QAction, qApp


class INTERFACE(object):
    """ 用户界面基本配置 """
    SOURCE = FILE.main() + 'resource' + os.sep
    ICON = SOURCE + 'bird.png'


class MainWindow(QDialog):
    """ 客户端主窗口 """
    def __init__(self):
        super(MainWindow, self).__init__()

        self.__component()
        self.__action()
        self.__show()

    def __component(self):
        """ 设置组件 """
        # 设置  System Tray 图标
        self.system_tray_icon = QIcon(INTERFACE.ICON)
        # 设置 System Tray 菜单
        self.system_tray_menu = QMenu(self)
        # 设置 System Tray Icon 通知区域
        self.system_tray = QSystemTrayIcon(self)
        self.system_tray.setIcon(self.system_tray_icon)
        self.system_tray.setContextMenu(self.system_tray_menu)

    def __action(self):
        """ 添加 Action """
        # 给 System Tray Menu 添加 Action
        # 退出
        quitAction = QAction(u'退出', self, triggered=self.__close)
        self.system_tray_menu.addAction(quitAction)

    def __show(self):
        """ 展示用户界面 """
        self.system_tray.setVisible(True)
        self.system_tray.show()

    def __close(self):
        """ 退出 """
        from config.runtime import RUNTIME
        RUNTIME.running(False)
        qApp.quit()
