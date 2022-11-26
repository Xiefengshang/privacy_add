from socketserver import BaseRequestHandler, ThreadingTCPServer
import base64
import ast
import sys
import pailliar
import time

sys.path.append('transfer')

from models import DataCrypto

rsa = DataCrypto.RSAsys
BUF_SIZE = 1024
PRIV_KEY = ""

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

            if len(data) != 0:
                global PRIV_KEY
                recv = self.de_data(data)
                PRIV_KEY = recv
                print('收到数据：', recv)
                self.request.sendall(self.en_data("服务端已收到数据: "+str(recv)))
            else:
                print("Client Close")
                break


def monitor(host, port):
    ADDR = (host, port)
    server = ThreadingTCPServer(ADDR, Handler)
    print('Server Start!')
    server.handle_request()
    time.sleep(1)
    global PRIV_KEY
    pailliar.savekey(PRIV_KEY)


if __name__ == '__main__':
    monitor("192.168.75.128", 48989)
