#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bootloader_ymodem.py —— APM32E103 BootLoader 上位机 Ymodem 发送核心

本模块只做两件事：把「裸 APP 固件」加上固件头后按 Ymodem 协议发送出去，
并把设备回传的字节流解复用成「协议事件」与「设备日志文本」。

设计要点：
  * 纯逻辑，不依赖 Qt / pyserial。I/O 通过鸭子类型的 port 对象完成，
    因此既能跑在 COMTool 的异步串口插件里，也能用 MockPort 离线回归。
  * 设备在打印启动 banner、接收进度、结果日志时，会把 UTF-8 文本与
    Ymodem 控制字节混在同一条串口流里，所以这里实现了「文本行 / 协议字节」
    解复用：{SOH,STX,EOT,ACK,NAK,CAN} 恒判为协议；'\\r'/\\n' 结束文本行；
    'C'(0x43) 只有在「当前无未闭合文本行」时才当作邀请 —— 这样设备文本
    "RECOVER OK: run APP restored" 里的 'C' 不会被误判成邀请。
  * 结束握手之后继续收集设备日志，解析设备端 size/CRC32 与 UPDATE 结论，
    供上层做端到端核对。

与设备端实现的对应关系（仓库 F:/Code/TH/Bms_FBL）：
  * 固件头      : Bootloader/Include/boot_protocol.h   fw_header_t
  * 分区/常量   : Bootloader/Include/boot_config.h
  * 接收状态机  : Bootloader/Source/boot_protocol.c    ymodem_receive()
  * 上位机参考  : tools/host_updater.py                ymodem_send()

离线自测（无需硬件，含 MockPort 设备模拟器）：
    python bootloader_ymodem.py
"""
import re
import struct
import sys
import threading
import time
import zlib

# ==================== Ymodem 控制字符 ====================
SOH = 0x01
STX = 0x02
EOT = 0x04
ACK = 0x06
NAK = 0x15
CAN = 0x18
C_CH = 0x43

YMO_PKT_128 = 128
YMO_PKT_1024 = 1024

# 协议字面量集合：这些字节永远按协议解释（0x0A/0x0D 换行单独处理）
PROTO_BYTES = frozenset((SOH, STX, EOT, ACK, NAK, CAN))

_PROTO_NAMES = {
    SOH: "SOH", STX: "STX", EOT: "EOT", ACK: "ACK",
    NAK: "NAK", CAN: "CAN", C_CH: "C",
}


def proto_name(v):
    """协议字节的可读名；None 表示超时。"""
    if v is None:
        return "TIMEOUT"
    return _PROTO_NAMES.get(v, "0x%02X" % v)


# ==================== 固件头（与 boot_config.h / boot_protocol.h 一致） ====================
FW_MAGIC = 0x424D5331          # "BMS1"
FW_TYPE_APP = 1                # 固件类型：APP
FW_HW_ID = 0x00000001          # 硬件型号 ID
FW_HEADER_SIZE = 32            # 固件头大小(字节)
FW_HEADER_CRC_COVER = 20       # 头部 CRC 覆盖字节数（前 20 字节）

# 设备侧容量约束（boot_config.h）
APP_MAX_SIZE = 0x19000         # 运行区/备份区 100KB
BL_WAIT_MS = 3000              # 运行区有效时的邀请窗口(ms)

# 升级文件（含固件头）的合法总长范围。设备端判定：
#   file_size <= FW_HEADER_SIZE || file_size > (APP_MAX_SIZE + FW_HEADER_SIZE) -> 拒绝
PKG_MIN_SIZE = FW_HEADER_SIZE + 1
PKG_MAX_SIZE = FW_HEADER_SIZE + APP_MAX_SIZE

# ==================== 超时与重试（与 host_updater.py 对齐） ====================
T_C = 10.0                     # 等待 'C' 邀请
T_ACK = 5.0                    # 等待 ACK/NAK/CAN
T_NAME_ACK = 30.0              # 文件名包 ACK：设备要先擦除整片备份区，单独放宽
RETRY_MAX = 5                  # 单包最大重传次数
_POLL_STEP = 0.1               # 读轮询步长（秒）
_TEXT_LINE_MAX = 512           # 设备日志单行最大缓存字节
_RESULT_TIMEOUT = 12.0         # 结束握手后收集设备结果日志的时长

# 设备结果日志形如 "YMODEM: 接收完成 size=102400 crc=0x1A2B3C4D"
_RE_RESULT = re.compile(r"size=(\d+)\s+crc=0x([0-9A-Fa-f]{8})")

# ==================== CRC16/XMODEM ====================
_CRC16_TABLE = []
for _i in range(256):
    _c = _i << 8
    for _ in range(8):
        _c = ((_c << 1) ^ 0x1021) & 0xFFFF if (_c & 0x8000) else (_c << 1) & 0xFFFF
    _CRC16_TABLE.append(_c)


def crc16_xmodem(data):
    """CRC-16/XMODEM：poly 0x1021、init 0x0000、无反射、无结果异或。

    校验向量：crc16_xmodem(b"123456789") == 0x31C3
    """
    crc = 0
    table = _CRC16_TABLE
    for b in data:
        crc = ((crc << 8) & 0xFFFF) ^ table[((crc >> 8) ^ b) & 0xFF]
    return crc


# ==================== 固件头构造 / 解析 ====================
def build_fw_header(version, size, fw_type=FW_TYPE_APP, hw_id=FW_HW_ID, magic=FW_MAGIC):
    """生成 32 字节固件头。

    布局（小端）：magic / fw_type / hw_id / version / size / header_crc / reserved[2]
    header_crc 为前 FW_HEADER_CRC_COVER(20) 字节的 CRC32（zlib/PKZIP 兼容，
    与设备端 crc32_calc 完全一致）。
    """
    core = struct.pack(
        "<5I",
        magic & 0xFFFFFFFF,
        fw_type & 0xFFFFFFFF,
        hw_id & 0xFFFFFFFF,
        version & 0xFFFFFFFF,
        size & 0xFFFFFFFF,
    )
    header_crc = zlib.crc32(core) & 0xFFFFFFFF
    return core + struct.pack("<3I", header_crc, 0, 0)


def parse_fw_header(header):
    """解析 32 字节固件头，返回 dict（供 UI 展示与自测断言）。"""
    if len(header) < FW_HEADER_SIZE:
        raise ValueError("firmware header too short")
    magic, fw_type, hw_id, version, size = struct.unpack("<5I", header[:20])
    header_crc, r0, r1 = struct.unpack("<3I", header[20:FW_HEADER_SIZE])
    return {
        "magic": magic,
        "fw_type": fw_type,
        "hw_id": hw_id,
        "version": version,
        "size": size,
        "header_crc": header_crc,
        "reserved": (r0, r1),
        "header_crc_ok": header_crc == (zlib.crc32(header[:FW_HEADER_CRC_COVER]) & 0xFFFFFFFF),
    }


def looks_like_fw_header(data):
    """判断一段数据是否已经是「含固件头」的升级包（仅用于 UI 提示，避免重复加头）。"""
    return len(data) >= FW_HEADER_SIZE and struct.unpack("<I", data[:4])[0] == FW_MAGIC


# ==================== 文件名包 ====================
# 允许出现在文件名里的字符：设备端 ymo_parse_name() 以第一个 NUL 结束文件名，
# 并以 ';' 作为版本后缀分隔符，因此必须剔除 ';'，同时避免中文/全角名导致
# 主机侧 latin-1 编码异常。
_FILENAME_OK = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)


def sanitize_filename(name, max_len=56):
    """把文件名规整成设备端可安全解析的 ASCII 名。

    规则：只保留 [A-Za-z0-9._-]，其余字符替换为 '_' 并合并连续 '_'，
    再去掉首尾的 '.'/'_'/' '；结果为空时回落到 "app.bin"。
    """
    base = (name or "").replace("\\", "/").split("/")[-1]
    out = []
    last_underscore = False
    for ch in base:
        if ch in _FILENAME_OK:
            out.append(ch)
            last_underscore = False
        elif not last_underscore:
            out.append("_")
            last_underscore = True
    safe = "".join(out).strip(". _") or "app.bin"
    return safe[:max_len]


def build_name_field(filename, file_size, version=0):
    """构造文件名包数据区： "name[;V=XXXX]\\0<十进制大小>\\0" 补 0 到 128 字节。

    注意 file_size 必须是「含固件头」的整个升级文件长度：设备端据此擦除备份区并
    在后续用 file_size == h->size + FW_HEADER_SIZE 校验固件头。
    """
    suffix = (";V=%X" % version) if version else ""
    field = ("%s%s" % (filename, suffix)).encode("latin-1") + b"\x00"
    field += str(int(file_size)).encode("latin-1") + b"\x00"
    if len(field) > YMO_PKT_128:
        raise ValueError("filename field too long")
    return field + b"\x00" * (YMO_PKT_128 - len(field))


def build_packet(seq, payload):
    """构造一个 SOH/STX 帧：<marker><seq><~seq><payload><CRC16 大端>。"""
    marker = SOH if len(payload) == YMO_PKT_128 else STX
    crc = crc16_xmodem(payload)
    return bytes((marker, seq & 0xFF, (~seq) & 0xFF)) + payload + struct.pack(">H", crc)


def build_data_payload(firmware, offset, packet):
    """取出一个数据包并按 Ymodem 约定用 0x1A 补齐到 packet 字节。

    设备端按 wlen = min(datalen, rem) 截断，填充字节不会写入 Flash。
    """
    chunk = firmware[offset:offset + packet]
    if len(chunk) < packet:
        chunk = chunk + b"\x1a" * (packet - len(chunk))
    return chunk


# ==================== 发送结果 ====================
class YmodemResult(object):
    """一次升级会话的结果。

    reason 取值（供上层做多语言映射）：
        ok / pkg_size / no_invite / name_timeout / name_nak / name_can /
        name_unknown / no_data_invite / pkt_fail / device_cancel /
        eot1_fail / eot1_no_invite / eot2_fail / eot2_no_invite /
        end_pkt_fail / cancelled / write_error / unknown
    """

    def __init__(self):
        self.ok = False
        self.reason = "unknown"
        self.detail = ""            # 附加信息（异常文本 / 出错字节等）
        self.total = 0              # 升级包总长（含固件头）
        self.sent = 0               # 已发送字节
        self.elapsed = 0.0          # 耗时(秒)
        self.retries = 0            # 累计重传次数
        self.fail_seq = 0           # 失败时的包序号（用于判断是否首包就被拒）
        self.device_size = None     # 设备回报的固件数据长度（不含头）
        self.device_crc = None      # 设备回报的 CRC32（不含头）
        self.update_ok = None       # None=未收到结论 / True / False
        self.update_msg = ""        # 设备结论原文
        self.device_lines = []      # 采集到的设备日志（仅保留尾部若干行）

    def note_line(self, text, keep=20):
        self.device_lines.append(text)
        if len(self.device_lines) > keep:
            del self.device_lines[0]

    def __repr__(self):
        return ("<YmodemResult ok=%s reason=%s sent=%d/%d dev_size=%s dev_crc=%s update=%s>"
                % (self.ok, self.reason, self.sent, self.total,
                   self.device_size, self.device_crc, self.update_ok))


# ==================== 字节流 <-> 事件 解复用层 ====================
class YmodemLink(object):
    """把「只提供读写字节的端口」包装成 Ymodem 所需的事件接口。

    port 需实现（鸭子类型，见插件里的 _PortAdapter）：
        timeout               属性，读超时(秒)，每次读前由本类设置
        write(data: bytes)    写入数据
        flush()               刷出（可为 no-op）
        read(n) -> bytes      读最多 n 字节，超时返回 b''
        reset_input_buffer()  清空输入缓冲

    回调：
        on_text(str)      设备日志文本行（UTF-8 解码，失败用 replace）
        on_proto(int)     收到的协议字节（供「显示协议细节」用）
        log(code, *args)  协议过程日志（code 由上层做多语言映射）
        stop_check()      返回 True 立即中止
    """

    def __init__(self, port, on_text=None, on_proto=None, on_write=None,
                 log=None, stop_check=None):
        self.port = port
        self.on_text = on_text
        self.on_proto = on_proto
        self.on_write = on_write
        self.log = log if log is not None else (lambda code, *a: None)
        self.stop_check = stop_check
        self._text = bytearray()
        self._pending_text = None
        self._pending_proto = None
        # 低速兼容模式：chunk_size>0 时把一帧拆成 chunk_size 字节分块发送，块间插入 chunk_gap
        self.chunk_size = 0
        self.chunk_gap = 0.0

    # ---------- 写入 ----------
    def _emit_write(self, data):
        """一帧只通知一次（分块发送时不重复），供上层记录串口发送数据。"""
        if self.on_write is not None:
            try:
                self.on_write(data)
            except Exception:
                pass

    def write_frame(self, data):
        """写出一帧（整包，或按低速兼容模式分块）。"""
        self._emit_write(data)
        if self.chunk_size and len(data) > self.chunk_size:
            for i in range(0, len(data), self.chunk_size):
                self.port.write(data[i:i + self.chunk_size])
                self.port.flush()
                if self.chunk_gap > 0:
                    time.sleep(self.chunk_gap)
        else:
            self.port.write(data)
            self.port.flush()

    def abort_device(self):
        """向设备发双 CAN 礼貌取消，并清空输入缓冲。"""
        try:
            self.write_frame(bytes((CAN, CAN)))
        except Exception:
            pass
        self.reset_input()
        time.sleep(0.05)

    def reset_input(self):
        """清空输入缓冲与解复用缓存（用于丢掉残留的 'C'）。"""
        try:
            self.port.reset_input_buffer()
        except Exception:
            pass
        del self._text[:]
        self._pending_text = None
        self._pending_proto = None

    # ---------- 解复用 ----------
    def _stopped(self):
        return bool(self.stop_check is not None and self.stop_check())

    def _take_text(self):
        if not self._text:
            return None
        raw = bytes(self._text)
        del self._text[:]
        return raw.decode("utf-8", errors="replace")

    def _emit_text(self, text):
        if text and self.on_text is not None:
            try:
                self.on_text(text)
            except Exception:
                pass

    def _emit_proto(self, v):
        if self.on_proto is not None:
            try:
                self.on_proto(v)
            except Exception:
                pass

    def _read_token(self, deadline):
        """返回 ("proto", int) / ("text", str) / (None, None)。"""
        if self._pending_text is not None:
            t = self._pending_text
            self._pending_text = None
            return ("text", t)
        if self._pending_proto is not None:
            p = self._pending_proto
            self._pending_proto = None
            return ("proto", p)
        while True:
            if self._stopped():
                return (None, None)
            now = time.monotonic()
            if now >= deadline:
                t = self._take_text()
                return ("text", t) if t is not None else (None, None)
            try:
                self.port.timeout = min(_POLL_STEP, max(0.005, deadline - now))
            except Exception:
                pass
            b = self.port.read(1)
            if not b:
                continue
            v = b[0]
            if v == 0x0A or v == 0x0D:
                t = self._take_text()
                if t is not None:
                    return ("text", t)
                continue
            if v in PROTO_BYTES:
                t = self._take_text()
                if t is not None:
                    self._pending_text = t
                return ("proto", v)
            if v == C_CH and not self._text:
                return ("proto", v)
            self._text.append(v)
            if len(self._text) >= _TEXT_LINE_MAX:
                t = self._take_text()
                if t is not None:
                    return ("text", t)

    # ---------- 上层等待原语 ----------
    def wait_proto(self, timeout, ignore_c=True):
        """等待一个协议字节；期间把设备文本旁路到 on_text。超时返回 None。"""
        deadline = time.monotonic() + (timeout if timeout and timeout > 0 else _POLL_STEP)
        while True:
            kind, val = self._read_token(deadline)
            if kind is None:
                return None
            if kind == "text":
                self._emit_text(val)
                continue
            self._emit_proto(val)
            if ignore_c and val == C_CH:
                continue
            return val

    def wait_invite(self, timeout=T_C):
        """等待设备 'C' 邀请（强制升级模式下设备会反复发送）。"""
        v = self.wait_proto(timeout, ignore_c=False)
        return v if v == C_CH else None

    def read_line(self, timeout):
        """读一行设备日志文本；协议字节旁路到 on_proto。超时返回 None。"""
        deadline = time.monotonic() + (timeout if timeout and timeout > 0 else _POLL_STEP)
        while True:
            kind, val = self._read_token(deadline)
            if kind is None:
                return None
            if kind == "text":
                self._emit_text(val)
                return val
            self._emit_proto(val)


# ==================== 主流程 ====================
def ymodem_send(link, data, filename, *,
                packet=YMO_PKT_1024,
                timeout=None,
                packet_gap=0.0,
                retry_max=RETRY_MAX,
                on_progress=None,
                stop_check=None,
                collect_result=True,
                result_timeout=_RESULT_TIMEOUT):
    """按 BootLoader 约定发送一个「已含固件头」的升级包。

    @param link           YmodemLink 实例
    @param data           升级包内容：build_fw_header(...) + 裸 APP bin
    @param filename       文件名（内部用 sanitize_filename 规整）
    @param packet         128 或 1024
    @param timeout        秒；None 表示使用默认 T_C / T_ACK（文件名包另有更宽的超时）
    @param packet_gap     每包发送后额外等待（秒），给设备留处理余量
    @param on_progress    回调 on_progress(fraction, label_code, *args)
    @param collect_result 结束握手后是否继续收集设备结果日志并解析 size/CRC32
    @return YmodemResult
    """
    t_start = time.monotonic()
    res = YmodemResult()
    res.total = len(data)

    if packet not in (YMO_PKT_128, YMO_PKT_1024):
        packet = YMO_PKT_1024

    if not isinstance(data, (bytes, bytearray)) or len(data) < PKG_MIN_SIZE or len(data) > PKG_MAX_SIZE:
        res.reason = "pkg_size"
        res.detail = str(len(data) if data is not None else 0)
        return res
    data = bytes(data)

    # stop_check 只保留一个来源：显式传入时覆盖 link 上的设置
    if stop_check is not None:
        link.stop_check = stop_check
    else:
        stop_check = link.stop_check

    log = link.log

    def stopped():
        return bool(stop_check is not None and stop_check())

    def prog(fraction, label, *args):
        if on_progress is not None:
            try:
                on_progress(fraction, label, *args)
            except Exception:
                pass

    def finish(reason, detail=""):
        res.reason = reason
        res.detail = detail
        res.elapsed = time.monotonic() - t_start
        return res

    def cancelled():
        log("cancelled")
        link.abort_device()
        return finish("cancelled")

    tc = float(timeout) if timeout is not None else T_C
    tack = float(timeout) if timeout is not None else T_ACK
    # 文件名包：设备要先擦除整片备份区再回 ACK（数秒），单独放宽
    t_name = max(tack, T_NAME_ACK)

    try:
        filename = sanitize_filename(filename)

        # ---------- 1) 等待设备邀请 ----------
        log("wait_invite")
        prog(0.0, "wait_invite")
        if link.wait_invite(tc) is None:
            if stopped():
                return cancelled()
            log("no_invite")
            return finish("no_invite")
        # 强制升级模式下设备持续发 'C'，残留的 'C' 会排在后续 ACK 之前，
        # 这里清空输入缓冲，且后续等待全部忽略 'C'。
        link.reset_input()
        log("invite_ok")
        prog(0.02, "name")
        if stopped():
            return cancelled()

        # ---------- 2) 文件名包 ----------
        link.write_frame(build_packet(0, build_name_field(filename, len(data))))
        if packet_gap:
            time.sleep(packet_gap)
        r = link.wait_proto(t_name, ignore_c=True)
        if r != ACK:
            if r is None and stopped():
                return cancelled()
            if r is None:
                log("name_timeout")
                return finish("name_timeout")
            if r == NAK:
                log("name_nak")
                return finish("name_nak")
            if r == CAN:
                log("name_can")
                return finish("name_can")
            log("name_unknown", "0x%02X" % r)
            return finish("name_unknown", "0x%02X" % r)
        log("name_ok")
        prog(0.04, "name_ok")

        # ---------- 3) 等待数据邀请 ----------
        if link.wait_invite(tc) is None:
            if stopped():
                return cancelled()
            log("no_data_invite")
            return finish("no_data_invite")
        if stopped():
            return cancelled()

        # ---------- 4) 数据包 ----------
        total = len(data)
        seq = 1
        sent = 0
        while sent < total:
            if stopped():
                return cancelled()
            chunk = build_data_payload(data, sent, packet)
            got_ack = False
            for attempt in range(1, retry_max + 1):
                link.write_frame(build_packet(seq, chunk))
                if packet_gap:
                    time.sleep(packet_gap)
                r = link.wait_proto(tack)
                if r != ACK and stopped():
                    return cancelled()
                if r == ACK:
                    got_ack = True
                    break
                if r == CAN:
                    # 设备在首包就取消，通常是固件头鉴权失败（含防降级拒绝）
                    res.fail_seq = seq
                    log("device_cancel")
                    res.ok = False
                    res.reason = "device_cancel"
                    res.elapsed = time.monotonic() - t_start
                    _collect_device_result(link, res, min(result_timeout, 3.0), log)
                    return res
                res.retries += 1
                log("pkt_retry", seq, proto_name(r), attempt, retry_max)
            if not got_ack:
                res.fail_seq = seq
                log("pkt_fail", seq)
                return finish("pkt_fail")
            sent += len(chunk)
            seq = (seq + 1) & 0xFF
            res.sent = sent
            prog(0.04 + 0.90 * (min(sent, total) / float(total)),
                 "progress", min(sent, total), total)

        # ---------- 5) 双 EOT 握手 ----------
        link.write_frame(bytes((EOT,)))
        if packet_gap:
            time.sleep(packet_gap)
        r = link.wait_proto(tack)
        if r != ACK:
            if r is None and stopped():
                return cancelled()
            log("eot1_fail", proto_name(r))
            return finish("eot1_fail", proto_name(r))
        if link.wait_invite(tc) is None:
            if stopped():
                return cancelled()
            log("eot1_no_invite")
            return finish("eot1_no_invite")

        link.write_frame(bytes((EOT,)))
        if packet_gap:
            time.sleep(packet_gap)
        r = link.wait_proto(tack)
        if r != ACK:
            if r is None and stopped():
                return cancelled()
            log("eot2_fail", proto_name(r))
            return finish("eot2_fail", proto_name(r))
        if link.wait_invite(tc) is None:
            if stopped():
                return cancelled()
            log("eot2_no_invite")
            return finish("eot2_no_invite")

        # ---------- 6) 结束空包 ----------
        link.write_frame(build_packet(0, b"\x00" * YMO_PKT_128))
        if packet_gap:
            time.sleep(packet_gap)
        r = link.wait_proto(tack)
        if r != ACK:
            if r is None and stopped():
                return cancelled()
            log("end_pkt_fail", proto_name(r))
            return finish("end_pkt_fail", proto_name(r))

        res.ok = True
        prog(0.98, "verify")
        log("transfer_done")

        # ---------- 7) 收集设备结论（size / CRC32 / UPDATE 结果） ----------
        if collect_result:
            _collect_device_result(link, res, result_timeout, log)

        prog(1.0, "done")
        return finish("ok")

    except Exception as e:      # 串口写失败、断线等
        log("write_error", str(e))
        return finish("write_error", str(e))


def _collect_device_result(link, res, duration, log):
    """收集设备结果日志，解析 size/CRC32 与 UPDATE 成功/失败结论。

    设备在结束空包 ACK 之后打印（见 boot_main.c）：
        YMODEM: 接收完成 size=<fw_size> crc=0x<8hex>
        UPDATE OK, jump to APP...     ← 成功
        UPDATE: xxx失败                ← 失败（拷贝/校验/写标志位）
    其中 size 与 CRC32 都只针对固件数据（不含 32 字节固件头）。
    """
    deadline = time.monotonic() + duration
    while True:
        remain = deadline - time.monotonic()
        if remain <= 0:
            break
        line = link.read_line(remain)
        if line is None:
            break
        res.note_line(line)
        m = _RE_RESULT.search(line)
        if m:
            res.device_size = int(m.group(1))
            res.device_crc = int(m.group(2), 16)
            log("result_size_crc", res.device_size, res.device_crc)
        if "UPDATE OK" in line:
            res.update_ok = True
            res.update_msg = line.strip()
            log("result_ok")
            break
        if "UPDATE:" in line:
            res.update_ok = False
            res.update_msg = line.strip()
            log("result_fail", res.update_msg)
            break
    if res.update_ok is None and res.device_crc is not None:
        log("no_result")


# ============================================================================
#  以下为离线自测（MockPort 设备模拟器），仅在直接运行本文件时执行
# ============================================================================
class _MockPort(object):
    """模拟 BootLoader 设备端的 Ymodem 接收方，用于无硬件回归。

    行为对齐 boot_protocol.c / boot_main.c：
      * 传输开始前持续回 'C' 邀请，且先插入一段启动 banner 文本
      * 文件名包 -> ACK（设备"先 ACK 再擦除"），擦除完成后回 'C'
      * 数据包 -> 校验 ~seq 与 CRC16 -> ACK；前 32 字节作为固件头先鉴权
      * EOT -> ACK + 'C'（双次）；空包 -> ACK，然后打印 size/crc 与 UPDATE 结论
      * 末包 0x1A 填充按 h->size 截断（不计入接收数据与 CRC32）
    """

    def __init__(self, min_version=0, reject_header=False, banner=True,
                 cancel_after_seq=None, nak_seq=None, drop_ack_seq=None,
                 result_ok=True):
        self.timeout = 0.1
        self.rx = bytearray()        # 设备 -> 主机
        self.host_writes = []        # 主机写出的原始数据块
        self.frames = []             # 已解析的主机帧
        # 真实串口是「驱动侧串行化」的：主机写入与主机读取可并发，
        # 因此模拟器内部状态必须加锁，否则测试会因竞争出现假失败。
        self._lock = threading.RLock()
        self.pkg_total = None        # 升级包总长（由文件名包得出）
        self._min_version = min_version
        self._reject_header = reject_header
        self._banner = banner
        self._cancel_after_seq = cancel_after_seq
        self._nak_seq = nak_seq
        self._drop_ack_seq = drop_ack_seq
        self._result_ok = result_ok
        self._started = False
        self._eot_count = 0
        self._expect_end = False
        self._seq_expected = 1
        self._hdr_buf = bytearray()
        self._fw_size = None
        self._fw = bytearray()
        self._crc = 0                # zlib.crc32 增量
        self.result_text = None

    # ---------- 端口接口 ----------
    def write(self, data):
        data = bytes(data)
        with self._lock:
            self.host_writes.append(data)
            self._process(data)
        return len(data)

    def flush(self):
        pass

    def read(self, n=1):
        if n <= 0:
            n = 1
        with self._lock:
            self._idle()
            if not self.rx:
                return b""
            out = bytes(self.rx[:n])
            del self.rx[:n]
            return out

    def reset_input_buffer(self):
        with self._lock:
            del self.rx[:]

    # ---------- 设备侧逻辑 ----------
    def _idle(self):
        """邀请阶段：主机来读时若环空，就再发一个 'C'（强制升级模式的行为）。"""
        if self.rx or self._started:
            return
        if self._banner:
            self.rx.extend(b"BootLoader V1.1\r\n")
            self.rx.extend(b"==== BootLoader: UPGRADE MODE (Ymodem) ====\r\n")
            self._banner = False
        self.rx.append(C_CH)

    def _ack(self):
        self.rx.append(ACK)

    def _emit_result(self):
        if self._reject_header:
            self.rx.extend("YMODEM: 接收失败\r\n".encode("utf-8"))
            self.rx.extend("UPDATE: 运行区校验失败\r\n".encode("utf-8"))
            return
        crc = self._crc & 0xFFFFFFFF
        line = "YMODEM: 接收完成 size=%d crc=0x%08X\r\n" % (len(self._fw), crc)
        self.rx.extend(line.encode("utf-8"))
        self.result_text = line.strip()
        if self._result_ok:
            self.rx.extend("UPDATE OK, jump to APP...\r\n".encode("utf-8"))
        else:
            self.rx.extend("UPDATE: 运行区校验失败\r\n".encode("utf-8"))

    def _hdr_check(self):
        h = parse_fw_header(bytes(self._hdr_buf))
        if self._reject_header:
            return False
        if h["magic"] != FW_MAGIC or h["fw_type"] != FW_TYPE_APP:
            return False
        if self.pkg_total is None or h["size"] + FW_HEADER_SIZE != self.pkg_total:
            return False
        if not h["header_crc_ok"]:
            return False
        if self._min_version and h["version"] < self._min_version:
            return False
        self._fw_size = h["size"]
        return True

    def _parse_frame(self, data):
        if len(data) < 5:
            return None
        marker = data[0]
        if marker not in (SOH, STX):
            return None
        datalen = YMO_PKT_128 if marker == SOH else YMO_PKT_1024
        if len(data) < 3 + datalen + 2:
            return None
        seq, nseq = data[1], data[2]
        if (seq + nseq) & 0xFF != 0xFF:
            return None
        payload = bytes(data[3:3 + datalen])
        crc = struct.unpack(">H", bytes(data[3 + datalen:3 + datalen + 2]))[0]
        if crc16_xmodem(payload) != crc:
            return None
        self.frames.append({"seq": seq, "payload": payload})
        return {"seq": seq, "payload": payload}

    def _process(self, data):
        if not data:
            return

        # 结束阶段：等待空包
        if self._expect_end:
            if data[0] == SOH:
                self._ack()
                self._emit_result()
            return

        if not self._started:
            # 文件名包 -> ACK，然后"擦除备份区"，擦完发 'C' 邀请数据
            frame = self._parse_frame(data)
            if frame is None:
                return
            total = 0
            try:
                body = frame["payload"].split(b"\x00", 1)[1]
                total = int(body.split(b"\x00", 1)[0].decode("latin-1"))
            except Exception:
                total = 0
            if total <= FW_HEADER_SIZE or total > PKG_MAX_SIZE:
                self.rx.append(NAK)
                return
            self.pkg_total = total
            self._started = True
            self._ack()
            self.rx.append(C_CH)
            return

        # EOT 握手
        if data[0] == EOT:
            self._eot_count += 1
            self._ack()
            self.rx.append(C_CH)
            if self._eot_count >= 2:
                self._expect_end = True
            return

        frame = self._parse_frame(data)
        if frame is None:
            self.rx.append(NAK)
            return
        seq = frame["seq"]

        # 固件头鉴权失败：设备发双 CAN + 打印原因
        if self._cancel_after_seq is not None and seq >= self._cancel_after_seq:
            self.rx.extend(bytes((CAN, CAN)))
            self._started = False
            self.rx.extend("YMODEM: 固件头非法魔数型号版本CRC\r\n".encode("utf-8"))
            return

        if seq != self._seq_expected:
            self.rx.append(NAK)
            return

        # 模拟"包 CRC 错/未接受"：回 NAK 且不消费数据、不推进期望序号，
        # 主机重传同一包后即可正常接受。
        if self._nak_seq is not None and seq == self._nak_seq:
            self._nak_seq = None
            self.rx.append(NAK)
            return

        payload = frame["payload"]
        rest = payload
        if len(self._hdr_buf) < FW_HEADER_SIZE:
            need = FW_HEADER_SIZE - len(self._hdr_buf)
            self._hdr_buf.extend(payload[:need])
            rest = payload[need:]
            if len(self._hdr_buf) == FW_HEADER_SIZE and not self._hdr_check():
                self.rx.extend(bytes((CAN, CAN)))
                self._started = False
                self.rx.extend("YMODEM: 固件头非法魔数型号版本CRC\r\n".encode("utf-8"))
                return
        # 按固件数据长度截断末包填充
        if rest and self._fw_size is not None:
            room = self._fw_size - len(self._fw)
            if room <= 0:
                rest = b""
            elif len(rest) > room:
                rest = rest[:room]
        if rest:
            self._fw.extend(rest)
            self._crc = zlib.crc32(rest, self._crc)

        self._seq_expected = (self._seq_expected + 1) & 0xFF
        # 模拟"设备已接受但 ACK 丢失"：数据被消费、序号已推进，只是不回 ACK。
        # 主机重传同一包会因序号不连续被 NAK，属 Ymodem 固有限制。
        if self._drop_ack_seq is not None and seq == self._drop_ack_seq:
            self._drop_ack_seq = None
            return
        self._ack()

    # ---------- 断言用 ----------
    @property
    def firmware(self):
        return bytes(self._fw)

    @property
    def firmware_crc(self):
        return self._crc & 0xFFFFFFFF


def _run_case(app_bin, version=0x0100, fw_type=FW_TYPE_APP, hw_id=FW_HW_ID,
              packet=YMO_PKT_1024, **mock_kw):
    """跑一个用例：把裸 bin 加头后发送，返回 (result, mock_port, texts, logs)。"""
    pkg = build_fw_header(version, len(app_bin), fw_type=fw_type, hw_id=hw_id) + app_bin
    port = _MockPort(**mock_kw)
    texts, logs, protos, prog = [], [], [], []
    link = YmodemLink(port, on_text=texts.append, on_proto=protos.append,
                      log=lambda c, *a: logs.append((c, a)))
    res = ymodem_send(link, pkg, "app.bin", packet=packet, timeout=1.0,
                      on_progress=lambda f, lab, *a: prog.append((round(f, 3), lab)))
    return res, port, texts, logs


def _self_test():
    ok_all = True

    def case(cond, msg, extra=""):
        print("  [%s] %s%s" % ("OK" if cond else "FAIL", msg, ("  " + extra) if extra else ""))
        return cond

    print("=" * 70)
    print("bootloader_ymodem 离线自测")
    print("=" * 70)

    # ---- 1) CRC / 固件头参考向量 ----
    print("\n[1] 参考向量")
    c16 = crc16_xmodem(b"123456789")
    ok_all &= case(c16 == 0x31C3, "CRC16/XMODEM('123456789') = 0x%04X (expect 0x31C3)" % c16)
    z32 = zlib.crc32(b"123456789") & 0xFFFFFFFF
    ok_all &= case(z32 == 0xCBF43926, "CRC32('123456789') = 0x%08X (expect 0xCBF43926)" % z32)

    hdr = build_fw_header(0x0100, 4096)
    h = parse_fw_header(hdr)
    ok_all &= case(len(hdr) == 32 and h["magic"] == FW_MAGIC and h["header_crc_ok"],
                   "固件头 32B magic=0x%08X type=%d hw=%d ver=0x%04X size=%d crc_ok=%s"
                   % (h["magic"], h["fw_type"], h["hw_id"], h["version"], h["size"], h["header_crc_ok"]))

    # ---- 2) 包格式 ----
    print("\n[2] 包格式")
    nf = build_name_field("app.bin", 102432, 0x0100)
    ok_all &= case(len(nf) == 128 and nf.startswith(b"app.bin;V=100\x00") and b"\x00102432\x00" in nf,
                   "文件名包 128B: %r" % bytes(nf[:20]))
    seq_crc = build_packet(1, b"\x00" * 1024)
    ok_all &= case(seq_crc[0] == STX and seq_crc[1] == 1 and seq_crc[2] == 0xFE and len(seq_crc) == 1029,
                   "数据包 marker=STX len=%d seq/~seq=%d/%d" % (len(seq_crc), seq_crc[1], seq_crc[2]))
    ok_all &= case(sanitize_filename("固件 v1;2.bin") == "v1_2.bin",
                   "文件名规整: %r" % sanitize_filename("固件 v1;2.bin"))
    ok_all &= case(sanitize_filename("") == "app.bin" and sanitize_filename("a" * 80) == "a" * 56,
                   "空名回落 app.bin、超长截断到 56")

    # ---- 3) 端到端多尺寸（含 banner 文本干扰、末包填充） ----
    print("\n[3] 端到端多尺寸")
    for size in (1024, 3000, 5000, 102400):
        app = bytes(((i * 7 + 3) % 256) for i in range(size))
        res, port, texts, logs = _run_case(app)
        cond = (res.ok and res.reason == "ok" and res.device_size == size
                and res.device_crc == (zlib.crc32(app) & 0xFFFFFFFF)
                and res.update_ok is True and port.firmware == app)
        ok_all &= case(cond, "size=%-6d ok=%s reason=%-6s dev_size=%-6s dev_crc=%s update=%s"
                       % (size, res.ok, res.reason, res.device_size,
                          ("0x%08X" % res.device_crc) if res.device_crc is not None else "None",
                          res.update_ok))

    # ---- 4) 文本 / 协议解复用 ----
    print("\n[4] 文本与协议解复用")
    app = bytes(2048)
    res, port, texts, logs = _run_case(app)
    ok_all &= case(any("BootLoader V1.1" in t for t in texts),
                   "banner 文本被正确分离（未干扰邀请识别）", "lines=%d" % len(texts))
    ok_all &= case(any("UPGRADE MODE" in t for t in texts), "第二条 banner 行完整")
    ok_all &= case(any("接收完成" in t for t in texts), "接收完成日志已捕获")

    # ---- 5) NAK 重传后可恢复 ----
    print("\n[5] NAK 重传")
    app = bytes(((i * 5 + 1) % 256) for i in range(4096))
    res, port, texts, logs = _run_case(app, nak_seq=2)
    ok_all &= case(res.ok and res.retries >= 1 and port.firmware == app
                   and port.firmware_crc == (zlib.crc32(app) & 0xFFFFFFFF),
                   "第 2 包被 NAK 后重传成功 retries=%d crc=0x%08X" % (res.retries, port.firmware_crc or 0))

    # ---- 6) 固件头被拒 -> 双 CAN ----
    print("\n[6] 固件头鉴权失败")
    res, port, texts, logs = _run_case(bytes(1024), cancel_after_seq=1)
    ok_all &= case((not res.ok) and res.reason == "device_cancel" and res.fail_seq == 1
                   and any("固件头非法" in t for t in texts),
                   "设备双 CAN -> reason=%s fail_seq=%d 已读出设备原因" % (res.reason, res.fail_seq))

    # ---- 7) 防降级 ----
    print("\n[7] 防降级（设备要求 >= 0x0200，固件为 0x0100）")
    res, port, texts, logs = _run_case(bytes(1024), version=0x0100, min_version=0x0200)
    ok_all &= case((not res.ok) and res.reason == "device_cancel",
                   "被拒 reason=%s" % res.reason)

    # ---- 8) 自定义 fw_type / hw_id ----
    print("\n[8] 自定义 fw_type / hw_id")
    app = bytes(((i * 3 + 7) % 256) for i in range(2048))
    res, port, texts, logs = _run_case(app, fw_type=1, hw_id=1, version=0x0301)
    ok_all &= case(res.ok and res.device_size == 2048,
                   "fw_type=1/hw_id=1 -> ok=%s dev_size=%s" % (res.ok, res.device_size))
    hh = parse_fw_header(build_fw_header(0x0301, 2048, fw_type=2, hw_id=9))
    ok_all &= case(hh["header_crc_ok"] and hh["fw_type"] == 2 and hh["hw_id"] == 9,
                   "fw_type=2/hw_id=9 头部 CRC 自洽 hdr_crc=0x%08X" % hh["header_crc"])

    # ---- 9) 主机侧取消 ----
    print("\n[9] 主机侧取消（stop_check）")
    app = bytes(((i * 11 + 5) % 256) for i in range(20000))
    pkg = build_fw_header(0x0100, len(app)) + app
    stop = {"v": False}

    class _HookPort(_MockPort):
        def write(self, data):
            if len(self.frames) > 3:
                stop["v"] = True
            return _MockPort.write(self, data)

    port = _HookPort()
    link = YmodemLink(port, log=lambda c, *a: None, stop_check=lambda: stop["v"])
    res = ymodem_send(link, pkg, "app.bin", timeout=1.0, collect_result=False)
    can_sent = any(w[:2] == bytes((CAN, CAN)) for w in port.host_writes)
    ok_all &= case((not res.ok) and res.reason == "cancelled" and can_sent,
                   "reason=%s 已发双 CAN=%s" % (res.reason, can_sent))

    # ---- 10) 非法包长度 ----
    print("\n[10] 非法升级包长度")
    link = YmodemLink(_MockPort(), log=lambda c, *a: None)
    r1 = ymodem_send(link, b"\x00" * (PKG_MAX_SIZE + 1), "a.bin", timeout=1.0)
    r2 = ymodem_send(link, b"\x00" * 16, "a.bin", timeout=1.0)
    ok_all &= case(r1.reason == "pkg_size" and r2.reason == "pkg_size",
                   "超容量=%s 过短=%s" % (r1.reason, r2.reason))

    # ---- 11) 无邀请超时 ----
    print("\n[11] 无邀请（设备未进入升级模式）")

    class _SilentPort(object):
        timeout = 0.1

        def write(self, data):
            return len(data)

        def flush(self):
            pass

        def read(self, n=1):
            return b""

        def reset_input_buffer(self):
            pass

    link = YmodemLink(_SilentPort(), log=lambda c, *a: None)
    res = ymodem_send(link, build_fw_header(1, 100) + bytes(100), "a.bin",
                      timeout=0.3, collect_result=False)
    ok_all &= case((not res.ok) and res.reason == "no_invite",
                   "reason=%s elapsed=%.2fs" % (res.reason, res.elapsed))

    # ---- 12) ACK 丢失（Ymodem 固有限制，应快速失败而非挂死） ----
    print("\n[12] ACK 丢失（已知协议局限，应很快失败）")
    app = bytes(((i * 13 + 9) % 256) for i in range(8192))
    res, port, texts, logs = _run_case(app, drop_ack_seq=2)
    ok_all &= case((not res.ok) and res.reason == "pkt_fail",
                   "reason=%s fail_seq=%d retries=%d" % (res.reason, res.fail_seq, res.retries))

    # ---- 13) 设备 UPDATE 失败结论 ----
    print("\n[13] 设备 UPDATE 失败")
    res, port, texts, logs = _run_case(bytes(2048), result_ok=False)
    ok_all &= case(res.ok and res.update_ok is False and "运行区校验失败" in res.update_msg,
                   "主机传输成功但设备结论=失败: %r" % res.update_msg)

    print("\n" + "=" * 70)
    print("自测结果：%s" % ("全部通过" if ok_all else "存在失败项，请检查上面的 [FAIL]"))
    print("=" * 70)
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(_self_test())
