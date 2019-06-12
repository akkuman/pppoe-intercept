## PPPoE-Intercept

## 喷

我开源的东西，这么快就有人商用了，我在群里看到一个 Crazy 的东西，很明显就是我这个东西，一模一样，加了个激活码机制开始卖了，
多的我不说了，只是希望大家广为流传，以后如果有时候我会更新的，但请你不要吵我，不能用了说一声即可，有时候有精力我自然会更新。

多说的，暂定一个交流群吧，462693866，就像我之前说的，请你不要一直吵着更新，不能用了说一声即可，有时候有精力我自然会更新。

## exe和用法

https://github.com/akkuman/pppoe-intercept/releases


电脑上先安装 winpcap
下载 pppoe-intercept.exe 后直接双击运行，选择你要捕获的网卡，点击开始捕获，然后打开电脑客户端拨号即可。

## 原理

自己实现了从 PPPoE 发现阶段到 PPPoE 会话阶段（LCP 和 IPCP）

### 效果

拦截 PPPoE 拨号过程中的账号密码

并欺骗客户端登录成功（拿湖北客户端做的测试，其他地区可能不太行，但是拦截应该通用）

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