# 国密workshop
这个demo旨在启动一个国密的服务器（公钥）并且通过命令行来执行对应的操作从而体验非对称加密过程中的签名，验证，加密，解密过程。

## 项目结构
- client 客户端代码
- server 服务器代码
- 其他

## 步骤
1. 编译项目
### terminal 1
`cd server && go build .`
### terminal 2
`cd client && go build .`
1. 生成密钥并配置
### terminal 2
`./client ./ generate`
`mv pub.pem ../server`
1. 启动服务器
### terminal 1
`./server ./`
1. 通过命令行发送请求
### terminal 2
`./client ./ sign 127.0.0.1:8080`
`./client ./ decrypt 127.0.0.1:8080`
`./client ./ sm4 127.0.0.1:8080`
## 设计
- server/client restapi接口
- 通用load key，sign，verify接口
- 底层基础库实现（支撑）

## 相关资源
- [课件1](./国密1030.pdf)
- [课件2](./国密workshop.pdf)