# nse-auto-all-wake-on-lan

一个零配置优先、偏激进的 Nmap NSE 脚本：自动收集直连局域网内可获得的 MAC 地址，并向每个候选设备发送 Wake-on-LAN（WOL）魔术包。

> 警告：本脚本会尝试改变局域网设备的电源状态。Nmap 没有正式的 `nosafe` 分类；本脚本使用 `intrusive`，并且明确不声明 `safe`，等价于项目所要求的 nosafe 定位。只应在你拥有或获授权管理的网络中运行。

## 使用

安装后，默认不需要记忆任何脚本参数：

```bash
sudo nmap --script auto-all-wake-on-lan
```

如果希望 Nmap 同时执行标准 ARP 主机发现，以额外补充本次扫描所见 MAC：

```bash
sudo nmap -sn -PR 192.168.1.0/24 --script auto-all-wake-on-lan
```

开发目录中可直接指定脚本文件，不必安装：

```bash
sudo nmap --script ./auto-all-wake-on-lan.nse
```

安装为可按名称调用的脚本：

```bash
# 将 /path/to/nmap-data/scripts 替换为本机 Nmap 数据目录下的 scripts 目录。
# Debian/Ubuntu 通常是 /usr/share/nmap/scripts；Windows、macOS 与自行编译的
# Nmap 的路径可能不同。
sudo install -m 0644 auto-all-wake-on-lan.nse /path/to/nmap-data/scripts/
sudo nmap --script-updatedb
sudo nmap --script auto-all-wake-on-lan
```

`sudo` 不是装饰：ARP、LLTD 抓包和原始二层 WOL 帧均需要原始套接字权限。

## 默认做什么

脚本自动处理所有已启用、具有 IPv4 地址的以太网接口；`-e eth0` 可将范围收窄到一个接口，但不是必需参数。

它在一次运行中合并并去重以下 MAC 来源：

| 来源 | 适用范围 |
|---|---|
| Nmap `host.mac_addr` | 在同次 `-sn -PR` 或其他本地扫描中识别出的主机 |
| 原始 ARP sweep | 直接相连、此刻会回应 ARP 的 IPv4 主机 |
| 被动 Ethernet 抓包 | 发现等待窗口内产生任意局域网帧的设备 |
| LLTD Quick Discovery | 支持并回应 Microsoft LLTD 的局域网设备 |
| Linux ARP 缓存 | 本机近期访问过、缓存尚未过期的邻居 |

对每一个候选 MAC，脚本经三种传输方式各发送 **4 次**：

1. 原始以太网 WOL 帧（EtherType `0x0842`）
2. 该接口的 IPv4 定向广播 UDP/9
3. IPv4 有限广播 `255.255.255.255:9`

因此一个同时可走三条路径的 MAC 最多收到 12 个魔术包。脚本仅向本机直接连接的二层网段发送，不尝试穿越路由器。

## 可选参数

零参数是推荐用法。以下仅用于特殊网络，不是日常使用所必需：

| 参数 | 默认值 | 用途 |
|---|---:|---|
| `auto-all-wake-on-lan.interface=eth0` | 所有适用接口 | 指定单个接口；也可使用 Nmap 的 `-e eth0` |
| `auto-all-wake-on-lan.repeat=3` | `4` | 每种传输的重复次数，仅接受 3 到 4 |
| `auto-all-wake-on-lan.timeout=3s` | `2s` | 每个发现阶段的收包时长 |
| `auto-all-wake-on-lan.max-hosts=4096` | `65534` | 限制自动 ARP sweep 的单接口地址数 |

## 能力边界

WOL 魔术包必须包含目标 MAC，协议没有“唤醒全部设备”的通配符。一个从未出现在本机 ARP 缓存、当前完全不回应 ARP/LLTD、且没有被本次 Nmap 扫描识别的睡眠设备，无法仅靠局域网广播推导出其 MAC。

路由器 DHCP 租约表、受管交换机的 FDB/MAC 表通常能补足这类设备，但它们没有跨厂商、无认证的统一查询协议；本项目不会猜测管理密码或枚举路由器凭据。若将来加入这类来源，会采用显式的、带认证的厂商适配器。

## 兼容性

核心功能仅使用 Nmap NSE 标准库的原始以太网、pcap 和接口 API，不依赖 Debian 或 Linux 特有命令，可用于 Nmap 支持这些能力的 Linux、macOS、BSD 和 Windows 环境。

Linux 上会额外读取 `/proc/net/arp` 作为候选来源；该文件不存在或不可读时会自动跳过，不影响 ARP、LLTD、Nmap 主机发现和 WOL 发送。

要求：Nmap 7.80+、IPv4、已启用的以太网接口，以及管理员/root 权限。Wi-Fi 驱动、虚拟网卡和交换机策略可能禁止原始二层帧或广播，这属于所在网络的限制。

## 开源协议

[MIT](LICENSE)
