#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import argparse
import socket
import random
import queue
import threading
import hashlib
import time
from datetime import datetime

#数据报最大接收字节数
MAX_BYTES = 65535
#保留字段，禁止注册
keep_str = ['REGR','REGRSUCCESS','REGRFAIL','LOGIN','LOGINSUCCESS','LOGINFAIL','ALL','EXIT','SHOW','CHECK','CHECKSUCCESS','CHECKFAIL','PVT','PVTFAIL','SCHECK','(end)']
keep_str2 = ['EXIT','SHOW','CHECK']
global clients_on
global db
global recv_packets
global recv_check_packets


########################### 客户端代码部分 ##############################
#注册函数：发送和接收注册的数据报
def register(server,sock):
    username = input('Input your username, Please: ')
    password = input('Input your password, Please: ')
    print('[*] Logining...')
    message = "REGR" + "!@#" + "None" + "!@#" + username + "!:" + password
    sock.sendto(message.encode('utf-8'), server)
    delay= 1
    sock.settimeout(delay) #设置接收延迟

    while True:
        try:
            datagram, addr = sock.recvfrom(MAX_BYTES)
            datagram = datagram.decode('utf-8').split("!@#", 2)
            if len(datagram) == 2 and addr == server: #验证消息来源和消息格式
                status = datagram[0]
                data = datagram[1]
                break
        except socket.timeout:
            delay *= 2
            if delay > 2.0:
                raise RuntimeError("I think its a wrong server.")
        else:
            pass

    if status=='REGRSUCCESS':
        return username, data
    elif status=='REGRFAIL':
        print('[!] Username has been registered :)\n')
        return 0, 0
    else:
        return 0, 0


# 登陆函数：发送和接收登陆的数据报
def login(server,sock):
    username = input('Input your username, Please: ')
    password = input('Input your password, Please: ')
    print('[*] Logining...')
    message =  "LOGIN" + "!@#" + "None" + "!@#" + username +"!:"+ password
    sock.sendto(message.encode('utf-8'), server)
    delay = 1
    sock.settimeout(delay)  # 设置接收延迟

    while True:
        try:
            datagram, addr = sock.recvfrom(MAX_BYTES)
            datagram = datagram.decode('utf-8').split("!@#", 1)
            if len(datagram) == 2 and addr == server:  # 验证消息来源和消息格式
                status = datagram[0]
                data = datagram[1]
                break
        except socket.timeout:
            delay *= 2
            if delay > 2.0:
                raise RuntimeError("I think its a wrong server.")
    else:
        pass

    if status=='LOGINSUCCESS':
        return username, data
    elif status=='LOGINFAIL':
        print('[!] Username or Password is wrong :)\n')
        return 0, 0
    else:
        return 0, 0


# 客户端处理接收到的包的函数
def ClientRecvData(sock, server, cusername, cookie):
    while True:
        try:
            datagram, addr = sock.recvfrom(MAX_BYTES)
            datagram = datagram.decode('utf-8').split("!@#",1)
            if len(datagram)==2 and addr==server:  #验证消息来源和消息格式
                status = datagram[0]
                data = datagram[1]
                if status == 'ALL':
                    fusername, text = data.split("!:",1)
                    print('[{} TO ALL] ({}) {}'.format(fusername, str(datetime.now()).split(".",1)[0].split("-",1)[1], text))
                elif status == 'PVT':
                    fusername, text = data.split("!:", 1)
                    print('[{} TO YOU!] ({}) {}'.format(fusername, str(datetime.now()).split(".", 1)[0].split("-", 1)[1], text))
                elif status == 'PVTFAIL':
                    print('[!] Your message send to *{}* failed. Maybe this user isn\'t online or exit.'.format(data))
                elif status == 'CHECKSUCCESS':
                    print('[SERVER] You\'re online.')
                elif status == 'CHECKFAIL':
                    print('[!] [SERVER] You\'re offline, quit now.')
                    sock.close()
                    os._exit(0)
                elif status=='SCHECK':
                    message =  "SCHECK!@#" + cookie + "!@#None"
                    sock.sendto(message.encode('utf-8'), server)
                elif status== 'SHOW':
                    data = data.split("!@#")
                    names = ""
                    for name in data:
                        if name != cusername:
                            names = names + name + " "
                    print('[SHOW] ({}) ONLINE Users is -> {}'.format(str(datetime.now()).split(".", 1)[0].split("-", 1)[1], names))
                elif status == 'EXIT':
                    sock.close()
                    os._exit(0)
        except:
            pass

def client(sport, saddr):
    # 获取客户端ip并尝试依靠随机数设置端口
    caddr = socket.gethostbyname(socket.gethostname())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server = (str(saddr), sport)
    while (True):
        try:
            cport = random.randint(49152, 65535)
            sock.bind((caddr, cport))
        except OSError:
            pass
        else:
            break
    print("[*] Your IP is:", caddr, "  Your Port is:", cport)

    # 用户连接到服务器并获得cookie
    while(True):
        infunction = input('$ Welcome, what do you want to do?[login/register]\n> ')
        # 登陆/登陆模块
        if(infunction == 'login' or infunction == 'register'):
            infunction = {'login': login,'register':register}[infunction]
            result1, result = infunction(server,sock)
            if (result==0):
                continue
            else:
                cookie = result
                cusername = result1
                break
        # 非登陆或操作命令
        else:
            print('[!] Error Input :)')

    ## 开始聊天室会话模块 ##
    print('''
     _        _   _
 ___| |_ ___ |_[l]_| ___ ___ ___ _____  +{0.0.1#dev-client}
| ._| . | .'|  [y]  /  _| . | . | , . | +My github -> https://github.com/hducaiji
|___|_| |__||  [f]  |_| |___|___|_|_|_| +thanks for my love: LSN                                 
    ''')
    print('Hey, {}! Welcome to chaTroom!!!'.format(cusername))
    print('[*] your cookie is:', cookie, '(If you need it.)')
    print('''[*] [HELP for beginner] Type: /<cmd> xxxxxx 
[*] [HELP for beginner] Here is all *cmds*: 
[*] [HELP for beginner] /ALL xxx -> send message to all people online.
[*] [HELP for beginner] /<username> xxx -> send message to your person who your choose.
[*] [HELP for beginner] /SHOW -> show all people's username who is online.
[*] [HELP for beginner] /CHECK -> check the net between c and s whether is connected.
[*] [HELP for beginner] /EXIT -> offline and quit.
Now Enjoy :)
''')
    # 监听服务器方向的数据
    t = threading.Thread(target=ClientRecvData, args=(sock, server, cusername, cookie))
    t.setDaemon(True) # 把当前进程设置为守护进程，主线程执行完毕，该线程均停止
    t.start()

    while True:
        cinput = input()
        try:
            cinput1, cinput2 = cinput.split(' ',1)
            if cinput1[0] == '/':
                message = cinput1.split('/',1)[1] + "!@#" + cookie + "!@#" + cinput2
                sock.sendto(message.encode('utf-8'), server)
        except:
            if cinput.split('/',1)[1] in keep_str2:
                message = cinput.split('/', 1)[1] + "!@#" + cookie + "!@#None"
                sock.sendto(message.encode('utf-8'), server)
            else:
                print('[!] Error input :)')

    sock.close()
########################### 客户端代码结束 ##############################



########################### 服务器端代码部分 ########3###################
# 固定时间间隔检测用户连接情况线程函数
def CheckClientNet(sock):
    global clients_on
    global recv_check_packets
    while True:
        new_clients_on = {}
        check_clients = []
        backed_clients = []
        time.sleep(20) #间隔20s检测一次
        for check_client in clients_on:
            check_clients.append(check_client)
            message = "SCHECK" + "!@#None"  # SCHECK-None
            sock.sendto(message.encode('utf-8'), check_client)
        time.sleep(1)  #若1s内没有回复，服务器端该用户下线
        while not recv_check_packets.empty():
            addr = recv_check_packets.get()
            backed_clients.append(addr)
        for i in check_clients:
            if i not in backed_clients:
                del clients_on[i]

        print("[*] Clients Online Updated:",clients_on)

# 服务器端退出函数
def Quit(sock):
    while True:
        sinput = input()
        if sinput in ['quit','QUIT','exit','EXIT']:
            print('[-] Bye~')
            sock.close()
            os._exit(1)

# 服务器端监听并接收数据线程的函数
def RecvData(sock):
    global recv_packets
    while True:
        try:
            datagram, caddr = sock.recvfrom(MAX_BYTES)
            datagram = datagram.decode('utf-8').split("!@#",2)
            if len(datagram)==3:
                func = datagram[0]
                cookie = datagram[1]
                data = datagram[2]
                recv_packets.put((func, cookie, data, caddr))
        except:
            pass

# 服务器端处理响应函数
def SolvData(sock, cookiebase):
    global clients_on
    global db
    global recv_packets
    global recv_check_packets
    while not recv_packets.empty():
        func, cookie, data, caddr = recv_packets.get()
        # 登陆功能响应
        if func=='LOGIN':
            username,password = data.split("!:",1)
            if (username not in db) or (password != db[username]):
                message = "LOGINFAIL" + "!@#" + "None"
                sock.sendto(message.encode('utf-8'), caddr)
                print('[{}] [LOGIN-FAIL] Request from {}'.format(str(datetime.now()).split(".",1)[0], caddr))
            else:
                print('[{}] [LOGIN-SUCCESS] Request from {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
                # 更新clientson
                for key,temp in list(clients_on.items()):
                    if temp.split("!@#",1)[0] == username: #删除同一用户名的登陆用户
                        print('[*] So {} offline Because of multiple logging in.'.format(key))
                        del clients_on[key]
                cookiebase.update(bytes(str(time.time()), encoding='utf-8'))
                clients_on[caddr] = username + "!@#" + cookiebase.hexdigest()
                # 发送成功登陆消息和cookie
                message = "LOGINSUCCESS" + "!@#" + cookiebase.hexdigest()
                sock.sendto(message.encode('utf-8'), caddr)
        #注册功能响应
        elif func=='REGR':
            username,password = data.split("!:",1)
            if (username in db) or (username in keep_str): #验证是否注册的用户名在数据库或保留字段
                message = "REGRFAIL" + "!@#" + "None"
                sock.sendto(message.encode('utf-8'), caddr)
                print('[{}] [REGR-FAIL] Request from {}'.format(str(datetime.now()).split(".",1), caddr)[0])
            else:
                print('[{}] [REGR-SUCCESS] Request from {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
                # 更新数据库和clientson，并把数据库保存到本地txt
                for key,temp in list(clients_on.items()):
                    if temp.split("!@#",1)[0] == username: #删除同一用户名的登陆用户
                        del clients_on[key]
                cookiebase.update(bytes(str(time.time()), encoding='utf-8'))
                clients_on[caddr] = username + "!@#" + cookiebase.hexdigest()
                db[username] = password
                f = open('db.txt', 'w')
                f.write(str(db))
                f.close()
                # 发送成功注册消息和cookie
                message = "REGRSUCCESS" + "!@#" + cookiebase.hexdigest()
                sock.sendto(message.encode('utf-8'), caddr)
        #发送给全部人功能响应
        elif func=='ALL':
            if caddr in clients_on and clients_on[caddr].split("!@#",1)[1] == cookie: #用cookie验证会话
                print('[{}] [ALL-SUCCESS] Send from {} : {}'.format(str(datetime.now()).split(".",1)[0], caddr, data))
                # 转发消息
                message = "ALL" + "!@#" + clients_on[caddr].split("!@#", 1)[0] + "!:" + data  # ALL-username-text
                for cs in clients_on:
                    if cs != caddr:
                        sock.sendto(message.encode('utf-8'), cs)
            else:
                print('[{}] [ALL-FAIL] Send from {} : {}'.format(str(datetime.now()).split(".",1)[0], caddr, data))
        #@test start
        #退出功能响应
        elif func=='EXIT':
            if caddr in clients_on and clients_on[caddr].split("!@#", 1)[1] == cookie:
                del clients_on[caddr]
                message = "EXIT" + "!@#None"  # EXIT-
                sock.sendto(message.encode('utf-8'), caddr)
                print('[{}] [EXIT] Request from {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
        #显示在线人名字功能响应
        elif func=='SHOW':
            if caddr in clients_on and clients_on[caddr].split("!@#", 1)[1] == cookie:
                message = "SHOW" + "!@#"
                for temp in clients_on.values():
                    message = message + temp.split("!@#",1)[0] + "!@#"
                message += "(end)"
                sock.sendto(message.encode('utf-8'),caddr)
        #客户端请求检查网络通信的功能
        elif func=='CHECK':
            if caddr in clients_on and clients_on[caddr].split("!@#", 1)[1] == cookie:
                message = "CHECKSUCCESS" + "!@#None"  # CHECKSUCCESS-None
                sock.sendto(message.encode('utf-8'), caddr)
                print('[{}] [CHECK-SUCCESS] Request from {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
            else:
                message = "CHECKFAIL" + "!@#None"  # CHECKSUCCESS-None
                sock.sendto(message.encode('utf-8'), caddr)
                print('[{}] [CHECK-FAIL] Request from {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
        # 服务器定时检查用户是否在线的功能
        elif func=='SCHECK':
            if caddr in clients_on and clients_on[caddr].split("!@#", 1)[1] == cookie:
                recv_check_packets.put((caddr))
        #私发响应
        else:
            if caddr in clients_on and clients_on[caddr].split("!@#", 1)[1] == cookie:
                for key,temp in clients_on.items():
                    if temp.split("!@#",1)[0] == func: #查看私发的用户名是否在线
                        print('[{}] [PVT-SUCCESS] Send from {} to {}: {}'.format(str(datetime.now()).split(".", 1)[0], caddr, func, data))
                        # 转发消息
                        message = "PVT" + "!@#" + clients_on[caddr].split("!@#", 1)[0] + "!:" + data  # PVT-username-text
                        sock.sendto(message.encode('utf-8'), key)
                        return 1
                print('[{}] [PVT-FAIL] Send from {} to {}: {}'.format(str(datetime.now()).split(".", 1)[0], caddr, func, data))
                message = "PVTFAIL" + "!@#" + func  # PVTFAIL-username
                sock.sendto(message.encode('utf-8'), caddr)
            else:
                print('[!][{}] WRONG DARAGRAM FROM {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
            #@test end

# 服务器端主函数
def server(port):
    print('''     _       ._. ._.                   _____
 ___| |_ ___ |_[l]_| ___ ___ ___ _____|  ___| +{0.0.1#dev-server}
| ._| . | .'|  [y]  /  _| . | . | , . |___. | +My github -> https://github.com/hducaiji
|___|_| |__||  [f]  |_| |___|___|_|_|_|_____| +thanks for my love: LSN

        ''')
    # 创建必要变量
    global clients_on
    global db
    global recv_packets
    global recv_check_packets
    # 读取本地txt（作为数据库）中的用户名密码，没有txt就创建新txt并初始化
    try:
        f = open('db.txt', 'r')
        db = eval(f.read())
        f.close()
    except:
        db = {'root': 'toor'}  # 创建用户名密码数据库
        f = open('db.txt', 'w')
        f.write(str(db))
        f.close()
    clients_on = {}  # 创建已登陆用户的字典 (addr,port):[username,cookie]
    recv_packets = queue.Queue()  # 为收到的消息创建一个队列
    recv_check_packets = queue.Queue()
    cookiebase = hashlib.md5() # 生成md5，为之后生成cookie作准备
    print('[*] Sever Init finished...')

    # 创建监听 与 接收数据报线程
    myhost = socket.gethostbyname(socket.gethostname())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((myhost, port))
    t1 = threading.Thread(target=RecvData, args=(sock, )) #跑一个线程，收消息进队列
    t2 = threading.Thread(target=Quit, args=(sock, ))  # 跑一个线程，等待退出
    t3 = threading.Thread(target=CheckClientNet, args=(sock, ))  # 跑一个线程，检测用户在线状态
    t1.setDaemon(True) # 设置为守护线程
    t2.setDaemon(True)
    t3.setDaemon(True)
    t1.start()
    t2.start()
    t3.start()
    print('[*] Server start listening at {}...'.format(sock.getsockname()))

    # 信息的处理与转发
    while True:
        SolvData(sock, cookiebase)

    sock.close()
########################### 服务端代码结束 ##############################

if __name__ == '__main__':
    # 参数创建主要有三个步骤：
    # 1.创建 ArgumentParser() 对象、
    # 2.调用 add_argument() 方法添加参数
    # 3.使用 parse_args() 解析添加的参数
    parser = argparse.ArgumentParser(description='An B2B UDP chatroom based on python :)\n')  #生成命令行对象parser
    parser.add_argument('c_or_s', choices={'client':client, 'server':server}, help='choose whether it\'s a server or a client.')  #创建定位参数c_ro_s，必填
    parser.add_argument('-p', metavar='PORT', type=int, default=8887, help='UDP port of server (default 8887)')  #创建可选短参数-p
    parser.add_argument('-i', metavar='IP', type=str, help='IP of chatroom server[Input if you are CLIENT!]') #创建客户端需求参数-i
    args = parser.parse_args()  # 解析参数
    # function = choices[args.c_or_s]  #定义function为server()或者client()其一
    # function(args.p)  #使用function并给其赋值-p参数的值
    if args.c_or_s == 'client':
        if args.i == None:
            print('[!] [MISSING PARAM]Run Client:-> /udp-chat-room.py client -i <ServerIP> [-p <SeverPORT>]')
        else:
            client(args.p, args.i)
    elif args.c_or_s == 'server':
        server(args.p)
