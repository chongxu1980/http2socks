# http2sock

**不支持python2**

使用了新版协程所以需要**python3 >= 3.7**

依赖**pysocks**



## 用法：

```bash
usage: http2socks.py [-h] [-H host] [-P port] [-sh socks_host] [-sp socks_port]

simple socks server

optional arguments:
  -h, --help      show this help message and exit
  -H host         IP or hostname for http_proxy (default "127.0.0.1")
  -P port         port for http_proxy (default 18080)
  -sh socks_host  socks_proxy IP or hostname (default "127.0.0.1")
  -sp socks_port  socks_proxy port (default 1080)
```



### 示例

```bash
#查看使用说明
python3 http2socks.py -h

#开启地址为‘127.0.0.1’，端口为18080的http/https代理，并连接到地址为‘127.0.0.1’,端口为1080的socks代理
python3 http2socks.py

#开启地址为‘127.0.1.1’，端口为18081的http/https代理，并连接到地址为‘127.0.1.1’,端口为1081的socks代理
python3 http2socks.py -H '127.0.1.1' -P 18081 -sh '127.0.1.1' -sp 1081
```





## 感谢：

https://github.com/playay/http_proxy