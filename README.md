## PPPoE-Intercept

### 效果

拦截 PPPoE 拨号过程中的账号密码

### 使用

1. Python，我的本地环境是 3.x

2. 安装 winpcap，注意不要使用 npcap，存在不知名问题

3. 然后安装 scapy，目前采用 pip 安装的是 2.4.2，只支持 npcap，我们需要改为手动安装

```
git clone https://github.com/secdev/scapy.git
cd scapy
python setup.py install
```

然后执行本项目中的 pppoe-intercept.py 即可