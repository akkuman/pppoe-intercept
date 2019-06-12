# coding:utf-8

'''
@author Akkuman
@date 2019.6.12
@update 2019.6.12
'''

import tkinter as tk
from tkinter import ttk
import scapy.all as scapy
import re
import threading
import pppoe_intercept

def start_sniff():
    def intercept_callback(username, password):
        ui_edtusername.set(username)
        ui_edtpassword.set(password)
    pppoe_intercept.CALLBACK = intercept_callback
    pppoe_intercept.MAC_ADDRESS = pppoe_intercept.get_mac_address()
    n = pppoe_intercept.PPPoEServer()
    n.start(iface=comboIface.get())

def fn_btnStartSniff():
    start_sniff_thread = threading.Thread(target=start_sniff)
    start_sniff_thread.start()

pattern = re.compile(r'\[(.+?)\]')

app = tk.Tk()
#app.geometry('500x300+500+200')
# 标题
app.title("PPPoE intercept----by:Akkuman")

# 标签
labelTop = tk.Label(app, text = "选择捕获网卡")
labelTop.grid(column=0, row=0, columnspan=2)

# 下拉框
if_list = [pattern.search(str(scapy.ifaces.data[i])).group(1) for i in scapy.ifaces.data]

comboIface = ttk.Combobox(app, width = 60, values = if_list)

comboIface.grid(column=0, row=1, columnspan=2)
for i in range(len(if_list)):
    if 'Realtek' in if_list[i]:
        comboIface.current(i)
    else:
        comboIface.current(0)

# 按钮
btnStartSniff = ttk.Button(app, text = "开始捕获", command = fn_btnStartSniff)
btnStartSniff.grid(column=0, row=2, columnspan=2)

# 文本输入框
lbl_username = tk.Label(app, text = "账号")
lbl_username.grid(column=0, row=3)

ui_edtusername = tk.StringVar()
edt_username = ttk.Entry(app, width=60, textvariable=ui_edtusername)
edt_username.grid(column=1, row=3)

lbl_password = tk.Label(app, text = "密码")
lbl_password.grid(column=0, row=4)

ui_edtpassword = tk.StringVar()
edt_password = ttk.Entry(app, width=60, textvariable=ui_edtpassword)
edt_password.grid(column=1, row=4)

print(comboIface.current(), comboIface.get())

app.mainloop()