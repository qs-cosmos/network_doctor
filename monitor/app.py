# coding: utf-8
import sys
from PyQt5.QtWidgets import QApplication
from client.interface import MainWindow
from client.spider import Spider
from client.analyzer import Analyzer
from client.network import Reporter
from config.runtime import RUNTIME

if __name__ == '__main__':
    RUNTIME.load()
    # 开启数据监测线程
    spider = Spider()
    spider.run()
    # 数据分析
    analyser = Analyzer()
    analyser.run()
    # 网络通信
    reporter = Reporter()
    reporter.run()
    # 运行 客户端 界面
    app = QApplication(sys.argv)
    QApplication.setQuitOnLastWindowClosed(False)

    window = MainWindow()

    sys.exit(app.exec_())
