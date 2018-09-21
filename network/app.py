# coding: utf-8
import sys
from PyQt5.QtWidgets import QApplication
from client.interface import MainWindow
from client.spider import Spider
from config.runtime import RUNTIME

if __name__ == '__main__':
    RUNTIME.load()
    # 开启数据监测线程
    spider = Spider()
    spider.run()

    # 运行 客户端 界面
    app = QApplication(sys.argv)
    QApplication.setQuitOnLastWindowClosed(False)

    window = MainWindow()

    sys.exit(app.exec_())
