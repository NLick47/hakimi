# 更新日志

## 2026-11-22

暂停加速时还原系统代理，恢复时重新接管
配置修改后PAC脚本即时重应用
下载分块按文件大小与线路自动分级
设置页合并下载与镜像配置
macOS 安装包改用 lzfse 压缩
内部资源压缩，缩小安装包体积
CA证书改用内置DER解析，缩小程序体积
桌面端日志改为固定级别
合并DoH缓存读取


首次安装提示：

- 安卓下载android.apk就行了，armv7.apk是留给老旧设备兼容的
- macOS：先把 hakimi.app 拖进「应用程序」，再在终端执行  
  `xattr -dr com.apple.quarantine /Applications/hakimi.app