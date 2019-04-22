# libpcap

## 编译安装

+ 下载地址: https://www.tcpdump.org/release/libpcap-1.8.1.tar.gz

+ 安装依赖
    - flex
    - byacc

+ ./configure

+ make

+ sudo make install

## 编程使用

+ gcc 编译
    - 添加参数: '-lpcap'
    - 向文件: '/etc/ld.so.conf' 中添加 '/usr/local/lib'
