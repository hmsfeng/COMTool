开发日记( development notes)
======

分功能将开发时的思路和方法记录在这里，如果有开发者想参与开发或者基于这个项目修改，可以先看本文档

如果你贡献了代码，也欢迎你把你贡献的功能模块的思路记录在这里


## 协议插件中的快捷键发送

给 key mode 按钮定义了一个 eventFilter, 拦截所有按钮按下和抬起按键的操作
> 代码为`protocol.py`中的`ModeButtonEventFilter`类



## 国际化支持

程序执行时先从文件加载配置，设置语言，再初始化其它内容，目的是保证在代码任何地方都能通过 i18n 模块正确地获取到翻译


## TCP UDP 连接支持

使用模块化（/插件化）开发， 在[conn/conn_tcp_udp.py](../conn/conn_tcp_udp.py) 中定义了这个类，可以直接执行 [conn/test_tcp_udp.py](../conn/test_tcp_udp.py) 测试模块

## 终端

使用了 `paramiko` 作为 `ssh`连接的后端，解析接收到的数据（`VT100`格式）使用了`pyte`， 根据`pyte`获取到的输出使用一个`pixmap`进行绘制，然后将`pixmap`刷到`QWidget`上实现显示

这里需要注意的是关于刷新和绘制，为了同步数据以及防止界面卡死：
接收和解析以及绘制`pixmap`都在`onReceived`函数中进行，这个函数在接收线程中执行，没在`UI`线程中执行，所以在绘制`pixmap`过程中不要直接调用任何直接操作界面的方法，所有操作都对这个`pixmap`进行操作，等绘制完成后再用`update()`函数通知`UI`线程，在`paintEvent`函数中将`pixmap`画到`widget`上


## ~~不同插件继承数据~~(已废弃此方案)

每个插件都可以使用连接，即用户在界面点击连接后，当前的插件就可以通过`send`和`onReceived`函数发送和接收数据了

另外也支持继承关系，比如`protocol`插件继承自`bdg`插件（即`protocol`插件的`connParent`为`dbg`），当我们使用`protocol`插件收发数据时，接收到数据会先发给`dbg`，然后`dbg`在`onReceived`函数中转发给`connChilds`即`protocol`插件，`protocol`发送数据时会先转发给`dbg`插件的`sendData`。

需要注意的是这个功能是一个试验性的功能，目前只支持两级，比如这里的`dbg`插件的`connParent`是`main`， `protocol`的`connParent`是`dbg`，**不可以**再有继承于`protocol`的插件了，因为是试验性功能，如果要支持更多层级继承需要修改代码使用递归实现

另外也需要注意，这里在`protocol`收发消息会经过`dbg`，但是在`dbg`收发不会转发给子插件也就是`protocol`


## BootLoader 升级插件（Ymodem 上位机）

配合 APM32E103 BootLoader 升级 APP 固件的内置插件，详细说明（协议规格、架构、界面、
使用步骤、踩坑记录、故障排查、打包）见 [bootloader_zh.md](./bootloader_zh.md)。

要点概括：

- 上位机是标准 Ymodem（CRC-16）发送方，但升级文件最前面要由上位机补 32 字节固件头
  （`magic/fw_type/hw_id/version/size/header_crc`），设备会先鉴权再接收，并据此做防降级
- COMTool 插件接口是全异步的，而 Ymodem 是锁步协议，因此加了一层 `_PortAdapter`
  把「入队发送 + 接收线程回调」适配成同步阻塞的串口风格接口
- 设备会把启动 banner 和升级日志以文本形式与协议字节混发，所以协议核心里做了
  「文本行 / 协议字节」解复用（否则设备文本 `RECOVER OK` 里的 `C` 会被当成邀请）
- 协议核心（`plugins/bootloader_ymodem.py`）不依赖 Qt，内置设备模拟器，
  可直接 `python COMTool/plugins/bootloader_ymodem.py` 做无硬件回归










