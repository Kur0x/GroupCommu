# GroupCommu
基于群签名和群密钥的安全通信系统。


## 环境搭建
本项目依赖于3个库，GMP，NTL，MMX。

GMP（GNU MP Bignum Library）为开源数学运算库。它可以满足任意精度的数学运算，包括有有理数、浮点数和符号整数。被NTL库所依赖。

安装方法：
```
$ sudo apt install libgmp-dev
```
NTL（Number Theory Library）是一个用于数论的库它是一个高性能，便携式的C ++库，提供数据结构和算法，用于处理带符号的任意长度整数，以及整数和有限域上的向量，矩阵和多项式。

安装方法：
```
$ wget http://www.shoup.net/ntl/ntl-10.5.0.tar.gz
$ tar xf ntl-*.tar.gz
$ cd ntl-*/src
$ ./configure 
$ make
$ make check
$ sudo make install
```
MMX为自主编写的密码学相关的库，其中具有rsa的密钥生成，加解密和密钥数据结构的定义，以及一些常用的函数，如NTL的ZZ大整数类与string类的互相转换。

安装方法：进入```lib/MMXlib```后执行```make```。

## 项目编译方法

按照上述步骤搭建好环境后，进入项目文件夹执行如下命令：
```
$ mkdir build
$ cd build
$ cmake ..
$ make
```
编译后生成可执行文件为```GroupCommu```

## 软件运行方法
### 语法
```./GroupCommu``` (选项)(参数)
### 选项
```
-g: 以GM的身份运行
-m: 以Member的身份运行（默认）
-i <ip>: 指定GM的ip
-n: 指定Member的id
-p <PSK>: 指定PSK 
-l <level>: 指定log的等级{debug|info|warn|err|critical}
```
