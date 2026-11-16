# 更新日志

## 2026-11-16

代理核心层微小性能优化
修复桌面关闭窗口后重开doh/镜像列表展开问题
安卓设置页轮询读空时保留上次快照

首次安装提示：

- 安卓下载android.apk就行了，armv7.apk是留给老旧设备兼容的
- macOS：先把 hakimi.app 拖进「应用程序」，再在终端执行  
  `xattr -dr com.apple.quarantine /Applications/hakimi.app