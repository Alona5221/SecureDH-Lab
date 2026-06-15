# SecureDH-Lab

SecureDH-Lab 是“网络空间安全设计与实践 I”课程设计原型，演示 POSIX TCP Socket、pthread 多客户端服务端、实验型 Diffie-Hellman 密钥协商、AES-256-GCM 风格认证加密传输、DH 中间人攻击，以及使用 PSK + HMAC-SHA256 认证握手后抵抗中间人攻击的效果。

> 重要说明：本项目只用于本地课程实验与课堂讲解，不用于真实生产安全系统。DH 使用 `uint64_t` 实验参数；项目未依赖 OpenSSL/libsodium/mbedTLS/Crypto++ 等第三方密码库。

## 四个阶段

1. **阶段一：弱认证 DH + 加密通信**：client/server 执行 DH，KDF 派生 32 字节会话密钥，并发送 AES-GCM 密文。
2. **阶段二：MITM 攻击**：mitm 分别与 client/server 建立两套 DH，会解密并重加密弱模式流量。
3. **阶段三：改进协议**：使用外部 `psk.bin`，通过 HMAC-SHA256 认证 `ClientHello`/`ServerHello` 握手 transcript。
4. **阶段四：验证攻击失败**：mitm 替换 DH 公钥后无法伪造 HMAC，client 打印认证失败并断开。

## 编译与测试

```bash
make clean
make
make test
```

生成四个程序：`./server`、`./client`、`./mitm`、`./keygen`。

## 阶段一运行

```bash
./server --host 0.0.0.0 --port 9000 --mode weak --verbose
./client --host 127.0.0.1 --port 9000 --mode weak --message "Hello Diffie-Hellman AES-GCM"
```

或自动脚本：

```bash
scripts/run_stage1.sh
```

预期 server 输出包含：`[server] DH shared key established` 和 `[server] decrypted message: Hello Diffie-Hellman AES-GCM`。

## 阶段二 MITM 攻击

```bash
./server --host 0.0.0.0 --port 9000 --mode weak --verbose
./mitm --listen-port 9001 --target-host 127.0.0.1 --target-port 9000 --mode attack --verbose
./client --host 127.0.0.1 --port 9001 --mode weak --message "My secret data"
```

或：

```bash
scripts/run_stage2_mitm.sh
```

mitm 预期输出：`[mitm] decrypted client plaintext: My secret data`。

## 阶段三改进协议

```bash
./keygen --psk-file psk.bin --bytes 32
./server --host 0.0.0.0 --port 9000 --mode secure --psk-file psk.bin --verbose
./client --host 127.0.0.1 --port 9000 --mode secure --psk-file psk.bin --message "Secure message after improvement"
```

client 预期输出：`[client] server handshake authentication passed`。server 预期输出：`[server] client handshake authentication passed`。

## 阶段四验证 MITM 失败

```bash
scripts/run_stage3_secure.sh
```

预期 client 输出：`[client] server authentication failed`；mitm 输出：`[mitm] attack failed: cannot forge authenticated DH transcript`。

## 后台运行示例

```bash
./server --host 0.0.0.0 --port 9000 --mode secure --psk-file psk.bin --daemon --log logs/server.log
./mitm --listen-port 9001 --target-host 127.0.0.1 --target-port 9000 --mode attack --daemon --log logs/mitm.log
```

## 密钥周期性更新示例

命令行已接受参数，日志会在触发重新握手设计点输出 rekey 信息；课程演示可使用：

```bash
./server --host 0.0.0.0 --port 9000 --mode secure --psk-file psk.bin --rekey-sec 30 --rekey-msg 5
```

## 目录结构

```text
include/   协议、网络、DH、SHA256、HMAC、AES/GCM、KDF、认证、日志头文件
src/       server/client/mitm/keygen 与模块实现
tests/     crypto 和 protocol smoke tests
scripts/   四个演示/清理脚本
logs/      运行日志目录
```

## 清理

```bash
scripts/clean_logs.sh
make clean
```
