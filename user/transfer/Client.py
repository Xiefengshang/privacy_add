from socket import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import base64
import string
import random
import sys
import os

sys.path.append('transfer')

class RSAsys:
    public_pem = "./public.pem"  # 公钥文件路径

    # 加密
    @classmethod
    def rsa_encrypt(cls, message):
        rsakey = RSA.importKey(open(cls.public_pem).read())
        cipher = Cipher_pkcs1_v1_5.new(rsakey)  # 创建用于执行pkcs1_v1_5加密或解密的密码
        cipher_text = base64.b64encode(cipher.encrypt(message.encode('utf-8')))
        return cipher_text.decode('utf-8')


class AESsys(object):
    def __init__(self, key, iv):
        """
        密钥和偏移量
        :param key:密钥：长度需要大于16,满足8的倍数
        :param iv:偏移量
        """
        if len(key) in [16, 24, 32]:
            self.key = key  # AES加密密钥
        else:
            raise Exception(f"密钥字符串长度需要在[16, 24, 32]中, 当前长度: key={key}, len={len(key)}")  # 密钥
        if len(iv) in [16]:
            self.iv = iv  # CBC模式的偏移量
        else:
            raise Exception(f"偏移量字符串长度需要在[16]中, 当前长度: key={iv}, len={len(iv)}")  # 密钥

    # 如果text不足16位的倍数就用空格补足为16位
    @staticmethod
    def _add_to_16(text):
        if len(text.encode('utf-8')) % 16:
            add = 16 - (len(text.encode('utf-8')) % 16)
        else:
            add = 0
        text = text + ('\0' * add)
        return text.encode('utf-8')

    # 加密, CBC模式
    def aes_cbc_encrypt(self, text):
        key = self.key.encode('utf-8')
        mode = AES.MODE_CBC
        iv = self.iv.encode('utf-8')
        text = self._add_to_16(text)
        cryptos = AES.new(key, mode, iv)
        cipher_text = cryptos.encrypt(text)
        return b2a_hex(cipher_text)

    # 解密,CBC模式，去掉补足的空格用strip() 去掉
    def aes_cbc_decrypt(self, text):
        key = self.key.encode('utf-8')
        iv = self.iv.encode('utf-8')
        mode = AES.MODE_CBC
        cryptos = AES.new(key, mode, iv)
        plain_text = cryptos.decrypt(a2b_hex(text))
        return bytes.decode(plain_text).rstrip('\0')


class SocketClient(object):
    def __init__(self, host, port, data1):
        self.HOST = host
        self.PORT = port
        self.DATA = data1
        self._BUFSIZ = 1024
        self._ADDR = (self.HOST, self.PORT)
        self._tcpCliSock = socket(AF_INET, SOCK_STREAM)
        self._tcpCliSock.connect(self._ADDR)
        self.key = ''.join(random.sample(string.ascii_letters + string.digits, 32))
        self.iv = ''.join(random.sample(string.ascii_letters + string.digits, 16))
        self.aes = AESsys(self.key, self.iv)

    def sent_data(self, data=None):
        """
        :param data: 要发送的数据 [str]
        :return: 收到的服务端发来的数据或状态 [str]
        """
        if data:
            self._tcpCliSock.sendall(self._en_data(data))
            recv = self._recv_data()
            self.close()
            return recv
        else:
            print("The sent data is empty or not sent!")

    def close(self):
        """
        关闭连接对象
        """
        self._tcpCliSock.close()

    def _recv_data(self):
        """
        接收服务端数据
        :return: 接收服务端数据-ERROR=None
        """
        data = b''
        while True:
            try:
                self._tcpCliSock.settimeout(10)  # 设置超时时间为10s超过10s判定为服务端没有返回状态，未收到数据
                recv_data = self._tcpCliSock.recv(self._BUFSIZ)
                if len(recv_data) > 0:
                    if recv_data[-1:] == b'#':
                        data += recv_data[:-1]
                        break
                    else:
                        data += recv_data
                else:
                    break
            except Exception as e:
                print("Socket receiving data error! | "+str(e))
                return None  # 出现异常返回None

        if len(data) != 0:
            return self._de_data(data)
        else:
            return ""  # 非异常无数据，返回空字符串

    def sent_data_user(self):
        """
        发送数据
        """
        k=str(self.DATA)
        self._tcpCliSock.sendall(self._en_data(k))
        recv = self._recv_data()
        print(recv)
        print("Client端已退出！")

    def sent_data_pending_input(self):
        """
        发送数据，长连接
        """
        lastdata = ''
        while lastdata != "quit":
            lastdata = input("请输入要发送的数据：")
            if len(lastdata) > 0:
                self._tcpCliSock.sendall(self._en_data(lastdata))
                recv = self._recv_data()
                print(recv)
            else:
                print("The sent data is empty or not sent!")
        print("Client端已退出！")

    def _en_data(self, data):
        """
        构造bytes数据, RSA+AES混合加密通信数据
        :param data: str
        :return: base64-bytes
        """
        cipher_key = RSAsys.rsa_encrypt(f'{{"aes_key":"{self.key}", "aes_iv":"{self.iv}"}}')
        cipher_data = self.aes.aes_cbc_encrypt(data).decode()
        format_data = f'{{"key":"{cipher_key}", "data":"{cipher_data}"}}'
        return base64.b64encode(format_data.encode())+b"#"

    def _de_data(self, data):
        """
        解析base64-bytes数据
        :param data: base64-bytesS
        :return: str
        """
        recv_data = base64.b64decode(data)
        decrypto_data = self.aes.aes_cbc_decrypt(recv_data)
        return decrypto_data

def send_m(host, port, data1):
    cli_obj = SocketClient(host, port, data1)
    cli_obj.sent_data_user()
if __name__ == '__main__':
    # Cloud
    send_m('127.0.0.1', 18989, "./privkey.pub")
   # print(cli_obj.sent_data("testdata"))  # 发送一次连接断开socket，短链接测试
    #cli_obj.sent_data_pending_input()  # 持续发送，长连接测试
    #cli_obj.sent_data_pending_key()

