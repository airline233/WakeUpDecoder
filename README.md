# WakeUp 课程表分享口令解析器

一个用于解析 WakeUp 课程表分享口令的 Python 脚本，无需抓包即可获取分享的课程表数据。

## 功能

从 WakeUp 课程表分享口令中提取课程表数据，脚本会：

1. 从 APK 中读取渠道、公钥和签名证书信息
2. 模拟客户端生成反作弊签名（signA/signB）
3. 构造并签名分享请求
4. 解密服务端返回的课程表数据

## 安装依赖

```powershell
python -m pip install -r requirements.txt
```

## 使用方法

### 基础用法

将 WakeUp 的 APK 文件放在脚本同目录下，然后运行：

```bash
python3 wakeup_share_import.py --code <分享口令> --android-id <android_id>
```

**参数说明：**
- `--code`: WakeUp 分享口令（必需）
- `--android-id`: 曾经登录过 WakeUp 的设备 Android ID（必需）
- `--apk`: APK 文件路径（可选，默认自动探测当前目录下的 APK）

### 自定义设备参数

可以根据需要自定义设备信息：

```bash
python3 wakeup_share_import.py\
  --code <分享口令> \
  --android-id <android_id> \
  --sdk 36 \
  --device 24129PN74C \
  --brand Xiaomi \
  --screensize 2670x1200
```

**可选参数：**
- `--sdk`: Android SDK 版本（默认 35）
- `--device`: 设备型号（默认 Pixel 7）
- `--brand`: 设备品牌（默认 google）
- `--screensize`: 屏幕分辨率（默认 1080x2400）
- `--abis`: CPU 架构（默认 arm64-v8a）

### 输出示例

成功解析后，脚本会输出 JSON 格式的课程表数据：

```json
{
  "schedule_name": "我的课程表",
  "courses": [
    {
      "name": "高等数学",
      "teacher": "张老师",
      "location": "教学楼A101",
      "time": "周一 8:00-10:00"
    }
  ]
}
```

如果解密失败，则输出原始响应体。

## 注意事项

- **必须使用真实的 Android ID**：需要提供一个曾经登录过 WakeUp 课程表的设备 Android ID，脚本不会生成或注册新设备
- **APK 文件**：需要从官方渠道获取 WakeUp APK 文件以提取签名信息
- **分享口令有效期**：WakeUp 分享口令可能有时效限制

## 文件说明

- `wakeup_share_import.py`: 主程序入口，处理命令行参数和请求流程
- `wakeup_share_sim.py`: 底层实现，包含签名算法、加密解密和请求构造
