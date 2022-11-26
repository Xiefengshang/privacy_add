# privacy_add
BUPT 大数据作业 同态加密加法处理平台通信
使用场景：
多个`user`需要计算其数据和，但不想让他人知晓各自成绩。
# 各代码块作用
## pailliar.py
生成json格式的用于同态加密的秘钥对
## Cloud1.py
发送同态加密的私钥给Cloud2。
## Cloud2_savekey.py
保存Cloud1发送的私钥到本地的privkey.pub
## Cloud2_dec.py
解密Cloud3传过来的密文。
## Cloud3.py
接收user.py发送的成绩的密文，并进行计算。
## user.py
发送成绩给Cloud3
具体使用见文档。
