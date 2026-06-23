# WakeUp Share Import PoC

WakeUp 课程表分享口令导入流程的逆向 PoC。

当前脚本会从原始 APK 中读取渠道、public token 和签名证书信息，并模拟：

- antispam signA/signB
- getdid 注册请求
- 分享口令请求签名
- 服务端返回解密

## 使用

```powershell
python -m pip install -r requirements.txt

python .\wakeup_share_import.py `
  --code <分享口令> `
  --android-id <曾经使用过 WakeUp 的 android_id> `
  --register-did
```

可按需要补充设备参数，例如：

```powershell
python .\wakeup_share_import.py `
  --code <分享口令> `
  --android-id <android_id> `
  --register-did `
  --sdk 36 `
  --os-version 16 `
  --device 24129PN74C `
  --brand Xiaomi `
  --screensize 2670x1200
```

## 说明

- `wakeup_share_import.py` 是主入口。
- `wakeup_share_sim.py` 保存底层算法和请求构造。
- 原始 APK/HAR 可放在目录里，但不会纳入 git。
- 实测随机 `android_id` 即使完成 getdid 也会命中反作弊；传入一个曾经使用过 WakeUp 课程表的 `android_id` 可以通过。
- `Dp-Ticket` 来自 `libdpsdk.so` 的 native DProtect worker，目前脚本不离线生成它。

