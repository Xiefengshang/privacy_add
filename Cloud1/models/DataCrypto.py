from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Hash import SHA
import base64

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
        # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
        return b2a_hex(cipher_text)

    # 解密,CBC模式，去掉补足的空格用strip() 去掉
    def aes_cbc_decrypt(self, text):
        key = self.key.encode('utf-8')
        iv = self.iv.encode('utf-8')
        mode = AES.MODE_CBC
        cryptos = AES.new(key, mode, iv)
        plain_text = cryptos.decrypt(a2b_hex(text))
        return bytes.decode(plain_text).rstrip('\0')

class RSAsys:
    public_pem = './public.pem'  # 公钥文件路径
    private_pem = './private.pem'  # 私钥文件路径

    # 加密
    @classmethod
    def rsa_encrypt(cls, message):
        rsakey = RSA.importKey(open(cls.public_pem).read())
        cipher = Cipher_pkcs1_v1_5.new(rsakey)  # 创建用于执行pkcs1_v1_5加密或解密的密码
        cipher_text = base64.b64encode(cipher.encrypt(message.encode('utf-8')))
        return cipher_text.decode('utf-8')

    # 解密
    @classmethod
    def rsa_decrypt(cls, cipher_text):
        encrypt_text = cipher_text.encode('utf-8')
        rsakey = RSA.importKey(open(cls.private_pem).read())
        cipher = Cipher_pkcs1_v1_5.new(rsakey)  # 创建用于执行pkcs1_v1_5加密或解密的密码
        text = cipher.decrypt(base64.b64decode(encrypt_text), "解密失败")
        return text.decode('utf-8')

    # 加签
    @classmethod
    def sign_add(cls, message):
        rsakey = RSA.importKey(open(cls.private_pem).read())
        signer = Signature_pkcs1_v1_5.new(rsakey)
        digest = SHA.new()
        digest.update(message.encode("utf-8"))
        sign = signer.sign(digest)
        signature = base64.b64encode(sign)
        return signature.decode('utf-8')

    # 验签
    @classmethod
    def sign_verify(cls, message_verify, signature):
        rsakey = RSA.importKey(open(cls.public_pem).read())
        verifier = Signature_pkcs1_v1_5.new(rsakey)
        hsmsg = SHA.new()
        hsmsg.update(message_verify.encode("utf-8"))
        try:
            verifier.verify(hsmsg, base64.b64decode(signature))
            return True
        except Exception as e:
            return False


if __name__ == '__main__':
    message = 'testfordemo'
    cipher = RSAsys.rsa_encrypt(message)
    print("加密", cipher)
    text = RSAsys.rsa_decrypt(cipher)
    print("解密", text)
    sign = RSAsys.sign_add(message)
    print("加签", sign)
    sign_ver = RSAsys.sign_verify(message, sign)
    print("验签", sign_ver)
