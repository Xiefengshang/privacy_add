from phe import paillier
import numpy as np
from transfer import pailliar
from transfer import Client
from phe.util import base64_to_int
import chardet
#data1为明文成绩
data1 = 30
enc_data1=pailliar.enc(data1)
# 用户数据发送给Cloud3的IP和端口
Client.send_m("192.168.75.138", 8989, enc_data1)