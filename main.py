import os
import re
import socket
import sqlite3
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Callable, Union, Tuple

from _secret import WHITE_LIST_IP, SECRET_KEY

# 常量区
PORT = 56789
SAVE_FILE_PATH = './file/%s'
DATABASE_PATH = './copier_server_database.db'
RE_MD5 = re.compile(r'^[0-9A-Fa-z]{32}$')


def change_stdout(status: bool):
    """
    False 为恢复, True 为切换为。。。
    :param status: 状态
    """
    if status:
        sys.stdout = app
        sys.__stdout__ = app
    else:
        sys.stdout = saved_stdout
        sys.__stdout__ = saved_stdout_


class App:
    def __init__(self):
        # 创建套接字
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 绑定端口
        self.server_socket.bind(('', PORT))
        #
        self.treat = Treat(self)
        self.db = DataBase(DATABASE_PATH)
        self.db.create_table()
        #
        self.root = tk.Tk()
        self.root.minsize(500, 200)
        self.root.geometry('1000x500')
        self.root.title('copier_server GUI--by XN')
        #
        ttk.Sizegrip(self.root).place(relx=1, rely=1, anchor='se')
        # P
        self.paned = tk.PanedWindow(self.root, showhandle=True, sashrelief="sunken")
        self.paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        # -------------------- 左侧信息 --------------------
        # 总框架
        self.frame1 = tk.Frame(self.paned)
        # 上方提示（标签）
        tk.Label(self.frame1, text='网络连接信息:', font='Consolas').pack(anchor='w')
        # 下方关闭服务按钮
        tk.Button(self.frame1, text='关闭服务', font=('Consolas', 20), command=self.close_server).pack(side=tk.BOTTOM)
        # 信息显示框
        self.frame11 = tk.Frame(self.frame1)
        self.frame11.pack(fill=tk.BOTH, expand=True)
        self.scroll1 = tk.Scrollbar(self.frame11)
        self.scroll1.pack(side=tk.RIGHT, fill=tk.Y)
        self.text1 = tk.Text(self.frame11, state=tk.DISABLED, font='Consolas', yscrollcommand=self.scroll1.set)
        self.text1.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.scroll1.config(command=self.text1.yview)
        # P
        self.paned.add(self.frame1, minsize=300)
        # -------------------- 右侧交互 --------------------
        # 总框架
        self.frame2 = tk.Frame(self.paned)
        # 上方标签
        tk.Label(self.frame2, text='交互式管理:', font='Consolas').pack(anchor='w')
        # 下方输入框
        self.text3 = tk.Entry(self.frame2, font='Consolas')
        self.text3.pack(side=tk.BOTTOM, fill=tk.X)
        self.text3.bind("<Return>", lambda e: self.run_code())
        tk.Label(self.frame2, text='输入:', font='Consolas').pack(anchor='w', side=tk.BOTTOM)
        # 信息显示框
        self.frame21 = tk.Frame(self.frame2)
        self.frame21.pack(fill=tk.BOTH, expand=True)
        self.scroll2 = tk.Scrollbar(self.frame21)
        self.scroll2.pack(side=tk.RIGHT, fill=tk.Y)
        self.text2 = tk.Text(self.frame21, state=tk.DISABLED, font='Consolas', yscrollcommand=self.scroll2.set)
        self.text2.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.scroll2.config(command=self.text2.yview)
        # P
        self.paned.add(self.frame2, minsize=300)

    def run(self):
        # 先创建一个文件夹用来存文件
        if not os.path.exists(SAVE_FILE_PATH % ''):
            os.mkdir(SAVE_FILE_PATH % '')
        # 监听
        self.server_socket.listen()
        # 等待连接
        self.write1('等待连接\n%s\n' % ('*' * 40))
        threading.Thread(target=self.server_main).start()
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            pass
        finally:
            self.close_server()

    def run_code(self):
        code = self.text3.get()
        print(code)
        if code.isspace():
            return
        try:
            res = eval(code)
        except Exception:
            try:
                exec(code, globals(), globals())
            except Exception as e:
                print('无法解析/运行 "%s", 原因: %s' % (code, repr(e)))
        else:
            print(repr(res))
        finally:
            print('>>> ', end='')

    def write(self, content: str):
        self.text2.config(state=tk.NORMAL)
        self.text2.insert(tk.END, content)
        self.text2.yview_moveto(1)
        self.text2.config(state=tk.DISABLED)

    def write1(self, *content):
        self.text1.config(state=tk.NORMAL)
        self.text1.insert(tk.END, ' '.join(str(x) for x in content))
        self.text1.yview_moveto(1)
        self.text1.config(state=tk.DISABLED)

    def flush(self):
        pass

    def close_server(self):
        # 换回来
        change_stdout(False)
        self.server_socket.close()
        print('程序正常退出')
        os._exit(0)

    def server_main(self):
        while True:
            try:
                ci = self.server_socket.accept()  # ci: client_info, 包括 cs 和 ca
            except OSError:
                continue
            else:
                threading.Thread(target=self.treat.main, args=ci).start()


class Treat:
    hash_map = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F')

    def __init__(self, app_obj: 'App'):
        self.app_obj = app_obj
        self.ver_map: Dict[bytes, Callable[[socket.socket], int]] = {
            bytes([0o211]): self.version_2_1
        }

    def o(self, formatter: str, *args):
        """
        o: output
        """
        self.app_obj.write1('%s <%s> %s' % (
            time.strftime('[%Y-%m-%d %H-%M-%S]', time.localtime()),
            threading.current_thread().name,
            formatter % args))

    def main(self, cs: socket.socket, ca: Tuple[str, int]):  # cs: client_socket, ca: client_addr
        # 过滤掉非法访问
        if ca[0] not in WHITE_LIST_IP:
            cs.close()
            self.o('该地址 %s 不在白名单里, 已拒绝连接! \n%s\n', ca[0], '-' * 40)
            return
        self.o('已连接! %s\n', ca)
        # 接收的消息
        # 1 B -> version
        ver = cs.recv(1)
        self.o('-> version: %s\n', ver)
        if ver in self.ver_map:
            if (signal := self.ver_map[ver](cs)) == 0:
                self.o('已完成通信!\n%s\n', '-' * 40)
            else:
                self.o('未完成通信! 原因: %s\n%s\n', signal, '-' * 40)
        else:
            self.o('版本不支持, 已断开连接!\n%s\n', '-' * 40)
        cs.close()

    def version_2_1(self, cs: socket.socket) -> Union[int, str]:
        try:
            # 1 B -> what
            # 8 B -> sk
            recv: Dict[str, bytes] = {'what': cs.recv(1), 'sk': cs.recv(8)}
            sk_correct = recv['sk'] in SECRET_KEY
            if recv['what'] == b'\x00':  # 检查网连
                self.o('-> what: %s (检查网络连接)\n', recv['what'])
                if sk_correct:
                    self.o('-> sk: %s (密码正确)\n', recv['sk'])
                    cs.send(b'\x00')
                else:
                    self.o('-> sk: %s (密码不正确)\n', recv['sk'])
                    cs.send(b'\x01')
            elif recv['what'] == b'\x01':  # 通信
                if not sk_correct:
                    cs.close()
                    self.o('-> sk: %s (密码不正确)\n', recv['sk'])
                    return '密码不正确'
                self.o('-> what: %s (传输)\n', recv['what'])
                recv['MD5'] = cs.recv(16)
                recv['name_size'] = cs.recv(2)
                recv['content_size'] = cs.recv(4)
                # 接收数据的处理
                md5 = ''.join([self.hash_map[x >> 4 & 0xf] + self.hash_map[x & 0xf] for x in recv['MD5']])
                self.o('-> MD5: %s\n', md5)
                if not RE_MD5.match(md5):
                    return 'MD5值不正确'
                if md5 == 'F' * 32:
                    return '客户端计算MD5失败！'
                name_size = self.bytes_2_int(recv['name_size'])
                content_size = self.bytes_2_int(recv['content_size'])
                self.o('-> name_size: %d\n', name_size)
                self.o('-> content_size: %d\n', content_size)
                # 接收文件名
                recv['name'] = cs.recv(name_size)
                name = recv['name'].decode('GBK', errors='ignore')
                _t = time.time()
                path = SAVE_FILE_PATH % (time.strftime('[%Y-%m-%d %H-%M-%S] %%s', time.localtime(_t)) % name)
                self.o('-> name: %s\n', name)
                self.o('-> file_path (on server): %s\n', path)
                # 查找数据库, 看看是否已经存在
                query = self.app_obj.db.query_one_data(md5)
                if query is None:  # 还没存, 这就存下
                    self.o('-> 服务器中还没有, 这就存下\n')
                    cs.send(b'\x01')
                    self.app_obj.db.add_data(md5, _t, path)
                    already_recv = 0
                    with open(path, 'wb') as f:
                        while already_recv < content_size:
                            r = cs.recv(1024)
                            f.write(r)
                            already_recv += len(r)
                else:  # 已经存了
                    self.o('-> 服务器中已经有了\n')
                    cs.send(b'\x00')
                    path_origin = query[2]
                    os.rename(path_origin, path)  # 文件重命名
                    self.app_obj.db.set_data(md5, _t, path)  # 修改数据库
        except Exception as e:
            return repr(e)
        else:
            return 0

    @staticmethod
    def bytes_2_int(data: bytes) -> int:
        res = 0
        n = len(data)
        for i, v in enumerate(data):
            res |= v << (n - i - 1) * 8
        return res


class DataBase:
    """
    每进行一次操作, 都要先连接、操作、最后关闭数据库。虽然消耗资源, 但是...方便!
    """

    def __init__(self, db_path: str):
        self.path = db_path

    def create_table(self) -> int:
        """
        创建表
        :return: 0 表示创建成功, -1 表示创建失败
        """
        # 连接数据库
        con = sqlite3.connect(self.path)
        cur = con.cursor()
        sql = """CREATE TABLE IF NOT EXISTS copier_server (
                     MD5       TEXT    NOT NULL PRIMARY KEY,
                     save_time INTEGER NOT NULL,
                     file_path TEXT    NOT NULL
                 );"""
        try:
            cur.execute(sql)
            return 0
        except Exception as e:
            print('[DataBase] 创建表失败:', e)
            return -1
        finally:
            cur.close()
            con.close()

    def add_data(self, md5: str, save_time: Union[int, float], file_path: str) -> int:
        """
        添加数据
        :return: 0 表示插入数据成功, -1 表示插入失败（很有可能是重复主键）
        """
        save_time = int(save_time)
        # 连接数据库
        con = sqlite3.connect(self.path)
        cur = con.cursor()
        sql = '''INSERT INTO copier_server (MD5, save_time, file_path) VALUES (?,?,?);''', (md5, save_time, file_path)
        try:
            cur.execute(*sql)
            # 千万别忘了提交, 不然像我一样排查半天找不到错误原因
            con.commit()
            return 0
        except Exception as e:
            print('[DataBase] 插入数据失败:', e)
            return -1
        finally:
            cur.close()
            con.close()

    def delete_data(self, md5: str) -> int:
        """
        删除该项数据
        :return: 0 表示删除数据成功, -1 表示删除失败（很有可能是数据库内没有该主键）
        """
        # 连接数据库
        con = sqlite3.connect(self.path)
        cur = con.cursor()
        sql = '''DELETE FROM copier_server WHERE MD5 = ?;''', (md5,)
        try:
            cur.execute(*sql)
            # 千万别忘了提交, 我然像我一样排查半天找不到错误原因
            con.commit()
            return 0
        except Exception as e:
            print('[DataBase] 删除数据失败:', e)
            return -1
        finally:
            cur.close()
            con.close()

    def set_data(self, md5: str, save_time: Union[int, float], file_path: str) -> int:
        """
        修改该项数据
        :return: 0 表示修改数据成功, -1 表示修改失败（很有可能是数据库内没有该主键）
        """
        save_time = int(save_time)
        # 连接数据库
        con = sqlite3.connect(self.path)
        cur = con.cursor()
        sql = '''UPDATE copier_server SET save_time = ?, file_path = ? WHERE MD5 = ?;''', (save_time, file_path, md5)
        try:
            cur.execute(*sql)
            # 千万别忘了提交, 我然像我一样排查半天找不到错误原因
            con.commit()
            return 0
        except Exception as e:
            print('[DataBase] 修改数据失败:', e)
            return -1
        finally:
            cur.close()
            con.close()

    def query_all_data(self) -> List[Tuple[str, int, str]]:
        """
        返回数据库中所有的数据
        :return: 所有数据
        """
        # 连接数据库
        con = sqlite3.connect(self.path)
        cur = con.cursor()
        sql = '''SELECT * FROM copier_server;'''
        try:
            cur.execute(sql)
            res = cur.fetchall()
            return res
        except Exception as e:
            print('[DataBase] 查询失败:', e)
            return []
        finally:
            cur.close()
            con.close()

    def query_one_data(self, md5: str) -> Union[Tuple[str, int, str], None]:
        # 连接数据库
        con = sqlite3.connect(self.path)
        cur = con.cursor()
        sql = '''SELECT * FROM copier_server WHERE MD5 = ?;''', (md5,)
        try:
            cur.execute(*sql)
            res = cur.fetchone()
            return res
        except Exception as e:
            print('[DataBase] 查询失败:', e)
            return None
        finally:
            cur.close()
            con.close()


if __name__ == '__main__':
    app = App()
    # 修改标准输出
    saved_stdout = sys.stdout
    saved_stdout_ = sys.__stdout__
    change_stdout(True)
    print('>>> ', end='')

    app.run()
