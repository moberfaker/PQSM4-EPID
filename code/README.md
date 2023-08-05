# 代码运行说明

下列列出文件为源码文件，其生成的可执行文件存放于`./可执行文件`目录下。若需要检查运行源码，需先运行**EasyX_20220901.exe**安装相关环境。

**EPIDCilent**：充电认证客户端与ui设计

> 双击`./code/EPIDCilent/EPID.sln`运行源码

> 在Realease模式下运行！

> 生成客户端exe可执行文件保存于`.\EPIDCilent\x64\Release`

**EPIDServer**:充电认证服务端与ui设计

> 双击`./code/EPIDServer/EPID.sln`运行源码

> 在Debug模式下运行！

> 生成客户端exe可执行文件保存于`.\EPIDServer\x64\Debug`

```
注意1

若需要关闭客户端服务端运行时的cmd命令窗口，可进行如下操作： 
server.cpp(16行)修改#define SHOWCONSOLES 0
cilent.cpp(20行)修改#define SHOWCONSOLES 0
若需要重新开启cmd命令窗口显示，修改为1即可。

注意2

由于群签名中为线性表管理，仅1人时无法进行群签名，需要运行两个以上客户端
可执行文件。
```

**EPIDLib**:EPID协议框架相关函数，生成EPID.lib文件

**Picnic-master**:PQSM4-EPID与PQSM4算法相关函数，生成libpicnic.lib

**EasyX_20220901.exe**：ui环境