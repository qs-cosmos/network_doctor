# ip

## 定义
    ip - 展示/定制路由, 网络设备、接口和隧道的信息。

## 简介
    ip [ OPTIONS ] OBJECT { COMMAND | help }

    ip [ -force ] -batch filename

    OBJECT := { link | address | addrlabel | route | rule | neigh | ntable |
    tunnel | tuntap | maddress | mroute | mrule | monitor | xfrm | netns | l2tp
    | tcp_metrics | token | macsec }

    OPTIONS := { -V[ersion] | -h[uman-readable] | -s[tatistics] | -d[etails] |
    -r[esolve] | -iec | -f[amily] {inet | inet6 | ipx | dnet | link } | -4 | -6
    | -I | -D | -B | -0 | -l[oops] {maximum-addr-flush-attempts } | -o[neline]
    | -rc[vbuf] [size] | -t[imestamp] | -ts[hort] | -n[etns] name | -a[ll] |
    -c[olor] -br[ief]}

## OPTIONS

    -V, -Version
        打印 ip 的有效版本并退出。

    -h, -human, -human-readable
        输出具有跟后缀的人类可读的统计数据

    -b, -batch <FILENAME>
        从提供的文件或标准输入流中读取数据并调用它们。
        第一个失败将会导致ip终止执行。

    -force
        在batch模式不要因错误而让ip终止执行。
        如果在命令的执行期间发生错误, 这个应用将返回非零值。

    -s, -stats, -statistics
        输出更多信息。如果这个选项出现过两次或更多, 信息的数量会增加。
        信息是统计信息或某些时间值。

    -d, -details
        输出更多详细信息。

    -l, -loops <COUNT>
        指定'ip address flush'的最大循环次数。默认值是10。
        零(0)表示一直循环直到所有的地址都被删除。

    -f, -family <FAMILY>
        指定使用的协议族(the protocol family)。协议族的标识符是inet, inet6,
        bridge, ipx, dnet, mpls 或者 link 中的一个。如果没有设置这个选项, 将
        会从其他的变量中猜测使用的协议族。如果剩下的命令中没有给足够的信息来
        猜测协议族, ip 将使用一个默认值, 通常是 inet 或 any。link 是一个特殊
        的族标识符, 表示不涉及任何网络协议。

    -4  -family inet 的缩写。

    -6  -family inet6 的缩写。

    -B  -family bridge 的缩写。

    -D  -family decnet 的缩写。

    -I  -family ipx 的缩写。

    -M  -family mpls 的缩写。

    -0  -family link 的缩写。

    -o, -oneline
        每行输出一个记录, 用'\'替换换行, 以便用 wc 或者 grep 对记录进行统计。

    -r, -resolve
        在输出结果中, 用DNS域名代替主机地址。

    -n, -netns <NETNS>
        把 ip 切换到特定网络名字空间 NETNS。事实上它只是简化了以下的命令:
        ip netns exec NETNS ip [ OPTIONS ] OBJECT { COMMAND | help }
        到
        ip -n[etns] NETNS [ OPTIONS ] OBJECT { COMMAND | help }

    -a, -all
        对所有的对象执行特定的命令, 取决于这个命令是否支持这个选项。

    -c, -color
        使用颜色输出。

    -t, -timestamp
        当使用监控选项时, 显示当前时间。

    -ts, -tshort
        类似于 -timestamp, 使用 shorter format。

    -rc, -rcvbuf<SIZE>
        设置网络连接套接字接收缓存大小, 默认为1MB。

    -iec 用IEC单位(例如, 1Ki = 1024)输出可读数据。

    -br, -brief
        为了提高可读性, 只输出基本信息并用表格展示。
        这个选项目前只支持 ip addr show 和 ip link show 命令。

## IP - COMMAND 语法

### OBJECT

    address
        - 设备的协议(IP 或 IPv6)地址。

    addrlabel
        - 协议地址选择的标签配置。

    l2tp
        - IP隧道以太网(L2TPv3)。

    link
        - 网络设备。

    maddress
        - 多播地址。

    monitor
        - 监控网络连接消息。

    mroute
        - 组播路由策略数据库中的规则。

    neighbour
        - 管理ARP或NDISC缓存条目。

    netns
        - 管理网络名字空间。

    ntable
        - 管理邻居缓存的操作。

    route
        - 路由表入口。

    tcp_metrics/tcpmetrics
        - 管理 TCP 指标。

    token
        - 管理符号化的接口识别码。

    tunnel
        - IP 隧道。

    tuntap
        - 管理TUN/TAP设备。

    xfrm
        - 管理IPSec策略。

    所有OBJECT的名称可以用完整或缩写形式书写, 例如 address 可以缩写为 addr 或 a。

### COMMAND

    指定要对OBJECT执行的操作。可用指令集合取决于OBJECT类型。通常有add, delete 和
    show (或者 list), 但有一些OBJECT不支持所有这些指令或者有其它的指令。help 指
    令对所有的OBJECT都有效。用于打印出可用的指令和参数语法约定的列表。

    如果没有给定指令, 则使用默认指令。通常是 list 或者 如果OBJECT不支持 list, 则
    使用 help。

## EXIT STATUS

    0 - 命令执行成功。
    1 - 语法错误。
    2 - 内核报告错误。

## 案例

    ip addr
        展示分配给各个网络接口的地址。

    ip neigh
        展示当前邻居/ARP解析列表。

    ip link set x up
        打开接口 x。

    ip link set x down
        关闭接口 x。

    ip route
        展示路由表

## 相关资料

    ip-address(8)

    ip-addrlable(8)

    ip-l2tp(8)

    ip-link(8)

    ip-maddress(8)

    ip-monitor(8)

    ip-mroute(8)

    ip-neighbour(8)

    ip-netns(8)

    ip-ntable(8)

    ip-route(8)

    ip-rule(8)

    ip-tcp_metrics(8)

    ip-token(8)

    ip-tunnel(8)

    ip-xfrm(8)

    IP Command reference ip-cref.ps


