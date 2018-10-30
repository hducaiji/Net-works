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

# 数据报最大接收字节数
MAX_BYTES = 65535
####### 保留字段，禁止注册，可以防止注册用户名和状态字冲突导致私聊功能存在问题 ######
keep_str = ['REGR', 'REGRSUCCESS', 'REGRFAIL', 'LOGIN', 'LOGINSUCCESS', 'LOGINFAIL', 'ALL', 'EXIT', 'SHOW', 'CHECK',
            'CHECKSUCCESS', 'CHECKFAIL', 'PVT', 'PVTFAIL', 'SCHECK', '(end)']
keep_str2 = ['EXIT', 'SHOW', 'CHECK']
global clients_on
global db
global recv_packets
global recv_check_packets


# **************************** 客户端代码部分 *******************************#
# 函数：注册，发送和接收注册的数据报
def register(server, sock):
    username = input('Input your username, Please: ')
    password = input('Input your password, Please: ')
    print('[*] Logining...')
    message = "REGR" + "!@#" + "None" + "!@#" + username + "!:" + password
    sock.sendto(message.encode('utf-8'), server)
    #########################################################################
    # 注册时有延时检测，保证如果服务器不存在或网络拥塞时不会永远等待                   ##
    # 在此，我感谢《python网络编程》作者在书p24页对我的启发和帮助，以下是部分参考其的代码段#
    ############################## START ####################################
    delay = 1
    sock.settimeout(delay)  # 设置接收延迟

    while True:
        try:
            datagram, addr = sock.recvfrom(MAX_BYTES)
            datagram = datagram.decode('utf-8').split("!@#", 2)
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
    ##############################  END  ####################################

    if status == 'REGRSUCCESS':
        return username, data
    elif status == 'REGRFAIL':
        print('[!] Username has been registered :)\n')
        return 0, 0
    else:
        return 0, 0


# 函数：登陆，发送和接收登陆的数据报
def login(server, sock):
    username = input('Input your username, Please: ')
    password = input('Input your password, Please: ')
    print('[*] Logining...')
    message = "LOGIN" + "!@#" + "None" + "!@#" + username + "!:" + password
    sock.sendto(message.encode('utf-8'), server)

    ########### 同上，延时检测代码段 ###
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
    ################################
    if status == 'LOGINSUCCESS':
        return username, data
    elif status == 'LOGINFAIL':
        print('[!] Username or Password is wrong :)\n')
        return 0, 0
    else:
        return 0, 0


################################################################
# 作用：客户端处理接收到的包的函数                                   #
# 说明：此函数作为子线程在后台不断接收报文，并且处理后查看消息格式是否正确， #
#      查看是否来自服务器，查看cookie是否和会话cookie相同以防止数据包伪造#
#      然后根据status决定如何处理该报文。                           #
# ！创新！：每个sendto的message统一格式如下：                       #
# 服务端发来的正确包格式：Status!@#Data!@#Cookie                   #
#                 这是我自己思考的格式，这些参数是正确处理每个报文必须的 #
################################################################
def ClientRecvData(sock, server, cusername, cookie):
    while True:
        try:
            datagram, addr = sock.recvfrom(MAX_BYTES)
            datagram = datagram.decode('utf-8').split("!@#", 2)
            if len(datagram) == 3 and addr == server and datagram[2] == cookie:  # 验证消息来源和消息格式
                status = datagram[0]
                data = datagram[1]
                if status == 'ALL':
                    fusername, text = data.split("!:", 1)
                    print('[{} TO ALL] ({}) {}'.format(fusername, str(datetime.now()).split(".", 1)[0].split("-", 1)[1],
                                                       text))
                elif status == 'PVT':
                    fusername, text = data.split("!:", 1)
                    print(
                        '[{} TO YOU!] ({}) {}'.format(fusername, str(datetime.now()).split(".", 1)[0].split("-", 1)[1],
                                                      text))
                elif status == 'PVTFAIL':
                    print('[!] Your message send to *{}* failed. Maybe this user isn\'t online or exit.'.format(data))
                elif status == 'CHECKSUCCESS':
                    print('[SERVER] You\'re online.')
                elif status == 'CHECKFAIL':
                    print('[!] [SERVER] You\'re offline, quit now.')
                    sock.close()
                    os._exit(0)
                elif status == 'SCHECK':
                    message = "SCHECK!@#" + cookie + "!@#None"
                    sock.sendto(message.encode('utf-8'), server)
                elif status == 'SHOW':
                    data = data.split("!@#")
                    names = ""
                    for name in data:
                        if name != cusername:
                            names = names + name + " "
                    print('[SHOW] ({}) ONLINE Users is -> {}'.format(
                        str(datetime.now()).split(".", 1)[0].split("-", 1)[1], names))
                elif status == 'EXIT':
                    sock.close()
                    os._exit(0)
        except:
            pass


#################### 客户端主函数 #########################
def client(sport, saddr):
    #######################################################################
    # ！小改进！：获取客户端ip并尝试依靠随机数设置端口，若端口被占用就生成另一个随机端口 #
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
    ###################################################################

    # 用户通过登陆/注册连接到服务器并获得cookie
    while (True):
        infunction = input('$ Welcome, what do you want to do?[login/register]\n> ')
        # 登陆/注册操作
        if (infunction == 'login' or infunction == 'register'):
            infunction = {'login': login, 'register': register}[infunction]
            result1, result = infunction(server, sock)
            if (result == 0):
                continue
            else:
                cookie = result
                cusername = result1
                break
        # 若非登陆或操作
        else:
            print('[!] Error Input :)')

    ###### 开始聊天室会话模块 ########
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
    ############# 监听服务器方向的数据的函数 ###############
    # ！改进！：把当前进程设置为守护进程，主线程执行完毕，该线程均停止#
    #      可以防止程序意外结束后子线程还在运行。             #
    t = threading.Thread(target=ClientRecvData, args=(sock, server, cusername, cookie))
    t.setDaemon(True)
    t.start()
    ####################################################

    # 发消息模块：循环接受用户输入，处理后若格式正确就发包
    while True:
        cinput = input()
        try:
            cinput1, cinput2 = cinput.split(' ', 1)
            if cinput1[0] == '/':
                message = cinput1.split('/', 1)[1] + "!@#" + cookie + "!@#" + cinput2
                sock.sendto(message.encode('utf-8'), server)
        except:
            if cinput.split('/', 1)[1] in keep_str2:
                message = cinput.split('/', 1)[1] + "!@#" + cookie + "!@#None"
                sock.sendto(message.encode('utf-8'), server)
            else:
                print('[!] Error input :)')

    sock.close()


# **************************** 客户端代码结束 *******************************#


# **************************** 服务端代码部分 *******************************#
####################################################
#  函数：固定时间间隔检测用户连接情况线程函数。            #
# ！改进！：这个函数在服务端程序里作为子线程执行，          #
#         隔一段时间就对所有在线的用户发包检查其是否还在线, #
#         防止有用户没有请求下线就意外退出/网络不畅。      #
def CheckClientNet(sock):
    global clients_on
    global recv_check_packets
    while True:
        new_clients_on = {}
        check_clients = []
        backed_clients = []
        time.sleep(20)  # 间隔20s检测一次
        for check_client in clients_on:
            check_clients.append(check_client)
            message = "SCHECK" + "!@#None" + "!@#" + clients_on[check_client].split("!@#", 1)[1]  # SCHECK-None-cookie
            sock.sendto(message.encode('utf-8'), check_client)
        time.sleep(1)  # 若1s内没有回复，服务器端该用户下线
        while not recv_check_packets.empty():
            addr = recv_check_packets.get()
            backed_clients.append(addr)
        for i in check_clients:
            if i not in backed_clients:
                del clients_on[i]

        print("[*] Clients Online Updated:", clients_on)


#######################################################
### 函数：服务器端退出函数
### 功能：监听服务端是否输入类似退出的字符串，从而正常退出
def Quit(sock):
    while True:
        sinput = input()
        if sinput in ['quit', 'QUIT', 'exit', 'EXIT']:
            print('[-] Bye~')
            sock.close()
            os._exit(1)


### 函数：服务器端监听并接收数据线程的函数
### 功能/说明：作为子线程不断在后台接受包并放入队列中，
###          这就将收包和发包分离了，很有udp特色，并不面向连接。
def RecvData(sock):
    global recv_packets
    while True:
        try:
            datagram, caddr = sock.recvfrom(MAX_BYTES)
            datagram = datagram.decode('utf-8').split("!@#", 2)
            if len(datagram) == 3:
                func = datagram[0]
                cookie = datagram[1]
                data = datagram[2]
                recv_packets.put((func, cookie, data, caddr))
        except:
            pass


#####################################################
# 函数：服务器端处理响应函数                             #
# 功能：存在于主线程循环，若队列不空，从队列中取出处理过的消息，#
#      然后根据func头放入响应if语句中执行。               #
# ！创新！：每个sendto的message统一格式如下：            #
# 客户端传来的正确格式：Func!@#Cookie!@#Data            #
#                   这是我自己思考的报文格式             #
####################START############################
def SolvData(sock, cookiebase):
    global clients_on
    global db
    global recv_packets
    global recv_check_packets
    while not recv_packets.empty():
        func, cookie, data, caddr = recv_packets.get()
        # 登陆功能响应
        if func == 'LOGIN':
            username, password = data.split("!:", 1)
            if (username not in db) or (password != db[username]):
                message = "LOGINFAIL" + "!@#" + "None"
                sock.sendto(message.encode('utf-8'), caddr)
                print('[{}] [LOGIN-FAIL] Request from {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
            else:
                print('[{}] [LOGIN-SUCCESS] Request from {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
                # 更新clientson
                for key, temp in list(clients_on.items()):
                    if temp.split("!@#", 1)[0] == username:  # 删除同一用户名的登陆用户
                        print('[*] So {} offline Because of multiple logging in.'.format(key))
                        del clients_on[key]
                cookiebase.update(bytes(str(time.time()), encoding='utf-8'))
                clients_on[caddr] = username + "!@#" + cookiebase.hexdigest()
                # 发送成功登陆消息和cookie
                message = "LOGINSUCCESS" + "!@#" + cookiebase.hexdigest()
                sock.sendto(message.encode('utf-8'), caddr)
        # 注册功能响应
        elif func == 'REGR':
            username, password = data.split("!:", 1)
            if (username in db) or (username in keep_str):  # 验证是否注册的用户名在数据库或保留字段
                message = "REGRFAIL" + "!@#" + "None"
                sock.sendto(message.encode('utf-8'), caddr)
                print('[{}] [REGR-FAIL] Request from {}'.format(str(datetime.now()).split(".", 1), caddr)[0])
            else:
                print('[{}] [REGR-SUCCESS] Request from {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
                # 更新数据库和clientson，并把数据库保存到本地txt
                for key, temp in list(clients_on.items()):
                    if temp.split("!@#", 1)[0] == username:  # 删除同一用户名的登陆用户
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
        # 发送给全部人功能响应
        elif func == 'ALL':
            if caddr in clients_on and clients_on[caddr].split("!@#", 1)[1] == cookie:  # 用cookie验证会话
                print('[{}] [ALL-SUCCESS] Send from {} : {}'.format(str(datetime.now()).split(".", 1)[0], caddr, data))
                # 转发消息
                message = "ALL" + "!@#" + clients_on[caddr].split("!@#", 1)[0] + "!:" + data  # ALL-username-text
                for cs in clients_on:
                    if cs != caddr:
                        message += "!@#" + clients_on[cs].split("!@#", 1)[1]
                        sock.sendto(message.encode('utf-8'), cs)
            else:
                print('[{}] [ALL-FAIL] Send from {} : {}'.format(str(datetime.now()).split(".", 1)[0], caddr, data))
        # 退出功能响应
        elif func == 'EXIT':
            if caddr in clients_on and clients_on[caddr].split("!@#", 1)[1] == cookie:
                del clients_on[caddr]
                message = "EXIT" + "!@#None" + "!@#" + cookie  # EXIT- -cookie
                sock.sendto(message.encode('utf-8'), caddr)
                print('[{}] [EXIT] Request from {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
        # 显示在线人名字功能响应
        elif func == 'SHOW':
            if caddr in clients_on and clients_on[caddr].split("!@#", 1)[1] == cookie:
                message = "SHOW" + "!@#"
                for temp in clients_on.values():
                    message = message + temp.split("!@#", 1)[0] + "!@#"
                message += "(end)" + "!@#" + cookie
                sock.sendto(message.encode('utf-8'), caddr)
        # 客户端请求检查网络通信的功能
        elif func == 'CHECK':
            if caddr in clients_on and clients_on[caddr].split("!@#", 1)[1] == cookie:
                message = "CHECKSUCCESS" + "!@#None" + "!@#" + cookie  # CHECKSUCCESS-None
                sock.sendto(message.encode('utf-8'), caddr)
                print('[{}] [CHECK-SUCCESS] Request from {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
            else:
                message = "CHECKFAIL" + "!@#None" + "!@#" + cookie  # CHECKSUCCESS-None
                sock.sendto(message.encode('utf-8'), caddr)
                print('[{}] [CHECK-FAIL] Request from {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
        # 服务器定时检查用户是否在线的功能
        elif func == 'SCHECK':
            if caddr in clients_on and clients_on[caddr].split("!@#", 1)[1] == cookie:
                recv_check_packets.put((caddr))
        # 私发响应
        else:
            if caddr in clients_on and clients_on[caddr].split("!@#", 1)[1] == cookie:
                for key, temp in clients_on.items():
                    if temp.split("!@#", 1)[0] == func:  # 查看私发的用户名是否在线
                        print('[{}] [PVT-SUCCESS] Send from {} to {}: {}'.format(str(datetime.now()).split(".", 1)[0],
                                                                                 caddr, func, data))
                        # 转发消息
                        message = "PVT" + "!@#" + clients_on[caddr].split("!@#", 1)[0] + "!:" + data + "!@#" + \
                                  clients_on[key].split("!@#", 1)[1]  # PVT-username-text
                        sock.sendto(message.encode('utf-8'), key)
                        return 1
                print('[{}] [PVT-FAIL] Send from {} to {}: {}'.format(str(datetime.now()).split(".", 1)[0], caddr, func,
                                                                      data))
                message = "PVTFAIL" + "!@#" + func + "!@#" + clients_on[caddr].split("!@#", 1)[
                    1]  # PVTFAIL-sendto_username
                sock.sendto(message.encode('utf-8'), caddr)
            else:
                print('[!][{}] WRONG DARAGRAM FROM {}'.format(str(datetime.now()).split(".", 1)[0], caddr))
#######################SolvData() END#############################

#################### 服务端主函数 #########################
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

    ############ 读取本地txt（作为数据库）中的用户名密码，没有txt就创建新txt并初始化 #####################
    ### ！改进！：启动服务器的同时导入/创建用户名密码的本地存储，方便导入和防止服务器端异常退出后用户名密码丢失 ##
    ###         同时，用户注册成功的时会将最新的数据库实时保存到本地。                                 ##
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
    cookiebase = hashlib.md5()  # 生成md5，为之后生成cookie作准备
    print('[*] Sever Init finished...')
    ##########################################################################################

    ###############  创建监听 与 接收数据报线程  ###################
    # ！改进！：把所有子线程进程设置为守护进程，主线程执行完毕，该线程均停止#
    #      可以防止服务端意外结束后子线程还在运行接受和处理数据         #
    myhost = socket.gethostbyname(socket.gethostname())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((myhost, port))
    t1 = threading.Thread(target=RecvData, args=(sock,))  # 跑一个线程，收消息进队列
    t2 = threading.Thread(target=Quit, args=(sock,))  # 跑一个线程，等待退出
    t3 = threading.Thread(target=CheckClientNet, args=(sock,))  # 跑一个线程，检测用户在线状态
    t1.setDaemon(True)  # 设置为守护线程
    t2.setDaemon(True)
    t3.setDaemon(True)
    t1.start()
    t2.start()
    t3.start()
    ###########################################################
    print('[*] Server start listening at {}...'.format(sock.getsockname()))

    # 信息的处理与转发
    while True:
        SolvData(sock, cookiebase)

    sock.close()
# **************************** 服务端代码结束 *******************************#


if __name__ == '__main__':
    #########################################################################
    # 在此，我感谢《python网络编程》作者在书p20页对我的启发和帮助，以下是部分参考的代码段 #
    ################################################# START #################
    parser = argparse.ArgumentParser(description='An B2B UDP chatroom based on python :)\n')  # 生成命令行对象parser
    parser.add_argument('c_or_s', choices={'client': client, 'server': server},
                        help='choose whether it\'s a server or a client.')  # 创建定位参数c_ro_s，必填
    parser.add_argument('-p', metavar='PORT', type=int, default=8887,
                        help='UDP port of server (default 8887)')  # 创建可选短参数-p
    parser.add_argument('-i', metavar='IP', type=str,
                        help='IP of chatroom server[Input if you are CLIENT!]')  # 创建客户端需求参数-i
    args = parser.parse_args()  # 解析参数
    ################################################# END ###################
    if args.c_or_s == 'client':
        if args.i == None:
            print('[!] [MISSING PARAM]Run Client:-> /udp-chat-room.py client -i <ServerIP> [-p <SeverPORT>]')
        else:
            client(args.p, args.i)
    elif args.c_or_s == 'server':
        server(args.p)
