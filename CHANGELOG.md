# 更新日志

## 2026-11-17

代理核心层修复及优化
桌面与安卓设置页新增分段下载和线程选择
下载分块默认改为512 KiB并自动迁移旧配置
安卓增加DoH端点设置
修复最小化窗口后通过任务栏关闭无法立即进行ui内存回收
减少桌面端构建体积



首次安装提示：

- 安卓下载android.apk就行了，armv7.apk是留给老旧设备兼容的
- macOS：先把 hakimi.app 拖进「应用程序」，再在终端执行  
  `xattr -dr com.apple.quarantine /Applications/hakimi.app