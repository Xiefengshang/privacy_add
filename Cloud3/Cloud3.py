import time
from socketserver import BaseRequestHandler, ThreadingTCPServer
import base64
import ast
import sys
import Client
import pailliar

sys.path.append('transfer')

from models import DataCrypto

rsa = DataCrypto.RSAsys
BUF_SIZE = 1024
ANS = 0
pubkey = None

class Handler(BaseRequestHandler):
    def __init__(self, request, client_address, server):
        super(Handler, self).__init__(request, client_address, server)
        self.aes_key = ''
        self.aes_iv = ''
        self.aes_obj = None

    def en_data(self, data):
        """
        构造bytes数据
        :param data: str
        :return: base64-bytes
        """
        cipher_data = self.aes_obj.aes_cbc_encrypt(data)
        return base64.b64encode(cipher_data)+b"#"

    def de_data(self, data):
        """
        解析base64-bytes数据
        :param data: base64-bytes
        :return: str
        """
        receive_data = base64.b64decode(data).decode()
        deserialization = ast.literal_eval(receive_data)
        keys = ast.literal_eval(rsa.rsa_decrypt(deserialization.get("key")))
        self.aes_key = keys.get("aes_key")
        self.aes_iv = keys.get("aes_iv")
        self.aes_obj = DataCrypto.AESsys(self.aes_key, self.aes_iv)
        decrypto_data = self.aes_obj.aes_cbc_decrypt(deserialization.get("data"))
        return decrypto_data

    def handle(self):
        while True:
            try:
                data = b''
                while True:
                    try:
                        recv_data = self.request.recv(BUF_SIZE)
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
                        break
            except Exception as e:
                print("断开连接！")
                break  # 跳出while循环
            if len(data) != 0:
                recv = self.de_data(data)
                print(recv)
                global pubkey
                pubkey, ans2 = pailliar.envec_load_json(recv)
                global ANS
                ANS = ANS + ans2[0]
                #print('收到数据：', recv)
                #print('现在的值：', ANS)
                self.request.sendall(self.en_data("服务端已收到数据: "+str(recv)))
            else:
                print("Client Close")
                break




def monitor(host, port):
    ADDR = (host, port)
    server = ThreadingTCPServer(ADDR, Handler)
    num = 2 # 同学数量
    print('Server Start!')
    for i in range(0,num):
        server.handle_request()
    time.sleep(1)
    global ANS
    print("ANS",ANS)
    k = pailliar.envec_dump_json(pubkey, [ANS])
    #Cloud2 IP和端口
    Client.send_m("192.168.75.128", 8989, k)


if __name__ == '__main__':
    #Cloud3 接受用户数据的IP和端口
    monitor("192.168.75.138", 8989)
