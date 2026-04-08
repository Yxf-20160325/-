package com.chatroom.app;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

/**
 * 聊天室 App 主 Activity
 * 
 * 功能：
 * - 配置 WebView 以支持 Socket.IO 长连接
 * - 允许混合内容（HTTP + HTTPS）
 * - 支持文件上传
 * - 优化内存管理
 */
public class MainActivity extends BridgeActivity {
    
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // 注册 Capacitor 插件
        this.registerPlugin(SplashScreenPlugin.class);
    }
}
