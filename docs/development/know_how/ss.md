# ss

## 定义

    ss - 另一个查看套接字的实用工具

## 简介

    ss [OPTIONS] [FILTER]

## 描述

    ss 用于转储套接字统计信息。它能够展示类似于netstat的信息。
    还可以查看比其他工具更多的TCP和状态信息。

## OPTIONS

    当没有设置选项时, ss 显示已建立连接的打开的非侦听(例如TCP/UNIX/UDP)套接字列表。

    -h, --help
        显示选项摘要。

    -V, --version
        输出版本信息。

    -H, --no-header
        不显示标题行。

    -n, --numeric
        不解析服务名称。

    -r, --resolve
        将地址名/端口名解析成数字化的地址/端口。

    -a, --all
        同时显示侦听和非侦听(对于TCP, 这意味着建立连接)套接字。

    -l, listening
        仅展示侦听套接字(默认忽略)。

    -o, --options
        显示计时器信息, 对于TCP协议, 输出格式为:

        timer: (<timer_name>, <expire_time>, <retrans>)

        <timer_name>
            计时器名称, 有五种计时器名称:

            on: 下列计时器其中之一, 分别为TCP重传计时器、TCP早期重传计时器和
                尾部丢失探测计时器

            keepalive: TCP 保活计时器

            timewait: TIMEWAIT 阶段计时器

            persist: 零窗口探测计时器

            unknown: 未知计时器

        <expire_time>
            计时器到期时间

        <retrans>
            重传次数

    -e, --extended
        展示详细套接字信息。输出格式如下:

        uid:<uid_number> ino:<inode_number> sk:<cookie>

        <uid_number>
            套接字归属的用户ID

        <inode_number>
            VFS中套接字的inode编号

        <cookie>
            套接字的uuid

    -m, --memory
        显示套接字内存使用量。输出格式如下:
        skmem: (r<rmem_alloc>, rb<rcv_buf>, t<wmem_alloc>, tb<snd_buf>,
                f<fwd_alloc>, w<wmem_queued>, o<opt_mem>, bl<back_log>)

        <rmem_alloc>
            分配用于接收数据包的内存

        <rcv_buf>
            可分配用于接收数据包的总内存

        <wmem_alloc>
            用于发送数据包(已发送到网络层)的内存

        <snd_buf>
            可分配用于发送数据包的总内存

        <fwd_alloc>
            被套接字分配为缓存的内存, 但尚未用于接收/发送数据包。如果需要
            发送/接收数据包的内存, 将在分配额外内存之前, 先使用该缓存的内存。

        <wmem_queued>
            分配用于发送数据包(尚未发送到网络层)的内存

        <opt_mem>
            用于存储套接字选项的内存, 例如, TCP MD5签名密钥

        <back_log>
            用于sk backlog队列的内存。在一个进程的上下文, 如果进程正在接收数据
            包并且有一个新的数据包被接收, 就加入sk backlog队列, 这样这个数据包
            就可以立即被进程接收。

    -p, --processes
        显示进程所用的套接字。

    -i, --info
        显示内部TCP信息. 可能有以下的字段:

        ts 如果设置了timestamp选项, 显示字符串"ts"

        sack 如果设置了sack选项, 显示字符串"sack"

        ecn 如果设置了显示拥塞通知选项, 显示字符串"ecn"

        ecnseen 如果接收的数据包中包含ecn标志, 显示字符串"ecnseen"

        fastopen 如果设置了fastopen选项, 显示字符串"fastopen"

        cong_alg 拥塞算法名, 默认拥塞算法是"cubic"

        wscale:<snd_wscale>:<rcv_wscale>
            如果设置了窗口扩大选项, 该字段显示发送扩大指数和接收扩大指数

        rto:<icsk_rto>
            TCP重传超时时间, 单位是ms

        backoff:<icsk_backoff>
            用于指数退避重传, 实际的重传超时时间是 icsk_rto << icsk_backoff

        rtt:<rtt>/<rttvar>
            rtt是平均往返时间, rttvar是rtt的平均偏差, 单位都是ms

        ato:<ato>
            ack 超时时间, 单位是ms, 用于延迟ack模式

        mss:<mss>
            最大报文段

        cwnd:<cwnd>
            拥塞窗口大小

        pmtu:<pmtu>
            路径MTU大小

        ssthresh:<ssthresh>
            TCP拥塞窗口慢启动门限

        bytes_acked:<bytes_acked>
            确认字节数

        bytes_recevied:<bytes_received>
            接收字节数

        lastsnd:<lastsnd>
            自从上次发送数据包以来的时间, 单位是ms

        lastrcv:<lastrcv>
            自从上次接收数据包以来的时间, 单位是ms

        lastack:<lastack>
            自从上次接收到确认以来的时间, 单位是ms

        pacing_rate <pacing_rate>bps/<max_pacing_rate>bps
            Pacing Rate和最大Pacing Rate

        rcv_space:<rcv_space>
            TCP内部自动调整套接字接收缓存的辅助变量

    -K, --kill
        尝试强制关闭套接字。显示成功关闭的套接字, 静默跳过内核不支持
        关闭的套接字。仅支持IPv4和IPv6。

    -s, --summary
        打印摘要统计数据。此选项不解析从各种源获取摘要的套接字列表。
        当套接字的数量过于庞大以至于解析/proc/net/tcp很困难时, 这是很有用的。

    -Z, --context
        和-p选项相同, 但还显示进程安全上下文

        对于netlink(7)套接字,显示的初始化进程上下文如下所示:

        1. 如果pid有效, 显示进程上下文。

        2. 如果目地地址是内核(pid=0), 显示内核初始化上下文。

        3. 如果内核或netlink用户已分配唯一标识符, 显示内容为"unavailable"。
        这通常表示进程有多个netlink套接字处于活跃状态。

    -z, --contexts
        和-Z选项相同但还显示套接字上下文。套接字上下文取自于相关联的inode,
        而不是内核持有的实际套接字上下文。套接字通常用创建过程中的上下文标
        记, 但是显示的上下文将反映应用的任何策略角色、类型和/或范围转换规则,
        因此是有用的参考。

    -N NSNAME, --net=NSNAME
        切换至指定名称的网络命名空间。参见ip netns(8)。

    -b, --bpf
        显示套接字BPF过滤器(仅管理员能够获取这些信息)。

    -4, --ipv4
        仅显示IPv4套接字(-f inet 的别名)。

    -6, --ipv6
        仅显示IPv6套接字(-f inet6 的别名)。

    -0, --packet
        显示PACKET套接字(-f link的别名)。

    -t, --tcp
        显示TCP套接字。

    -u, --udp
        显示UDP套接字。

    -d, --dccp
        显示DCCP套接字。

    -w, --raw
        显示RAW套接字。

    -x, --unix
        显示Unix域名套接字(-f unix的别名)。

    -S, --sctp
        显示SCTP套接字

    --vsock
        显示vsock套接字(-f vsock的别名)

    -f FAMILY, --family=FAMILY
        显示制定类型FAMILY的套接字。目前支持的协议族有: unix, inet, inet6, link,
        netlink, vsock

    -A QUERY, --query=QUERY, --socket=QUERY
        待转储的套接字列表, 以逗号分隔。目前支持的标识符有: all, inet, tcp, udp,
        raw, unix, packet, netlink, unix_dgram, unix_stream, unix_seqpacket,
        packet_raw, packet_dgram, dccp, sctp, vsock_stream, vsock_dgram.

    -D FILE, --diag=FILE
        不显示任何信息, 在应用过滤器后, 仅将TCP套接字的原始信息转储至FILE。如果
        FILE是"-", 则是指使用标准输出(stdout)。

    -F FILE, --filter=FILE
        从FILE中读取过滤器信息。FILE中的每一行都被解释为单个命令行选项。如果FILE
        是"-", 则是指使用标准输入(stdin)。

    FILTER := [ state STATE-FILTER] [ EXPRESSION ]
            有关过滤器的详细信息, 请查看官方文档。

## STATE-FILTER

    STATE-FILTER 允许构造任意一组状态来进行匹配。语法是 state 关键字后加上一组
    state标识符序列。

    可用标识符有:

        所有的标准TCP状态: established, syn-sent, syn-recv, fin-wait-1,
        fin-wait-2, time-wait, closed, close-wait, last-ack, listening
        和 closing。

        all - 所有的状态

        connected - 除了listening 和 closed 外的所有状态

        synchronized - 除了 syn-sent 外的所有状态

        bucket - 用于维持最小套接字的状态, 例如: time-wait 和 syn-recv

        big - 与 bucket 恰好相反。

## 使用案例

    ss -t -a
        显示所有的TCP套接字

    ss -t -a -Z
        显示具有进程SELinux安全上下文的所有TCP套接字。

    ss -u -a
        显示所有的UDP套接字。

    ss -o state established '( dport = :ssh or sport = :ssh )'
        显示所有已建立的ssh连接。

    ss -x src /tmp/.X11-unix/*
        找到所有连接X服务器的本地进程。

    ss -o state fin-wait-1 '( sport = :http or sport = :https )' dst 193.233.7/24
        列出状态为FIN-WAIT-1且连接到193.233.7/24网络Apache服务的TCP套接字,
        并查看这些连接的定时器。

## 相关资料

    ip(8)

    RFC 793 - https://tools.ietf.org/rfc/rfc793.txt (TCP states)
