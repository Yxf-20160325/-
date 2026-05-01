package com.chatroom.app;

import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // 启用 WebView 调试
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.KITKAT) {
            WebView.setWebContentsDebuggingEnabled(true);
        }
    }
    
    @Override
    public void onStart() {
        super.onStart();
        // 在 Bridge 初始化完成后配置 WebView
        WebView webView = getBridge().getWebView();
        if (webView != null) {
            WebSettings settings = webView.getSettings();
            // 启用 JavaScript
            settings.setJavaScriptEnabled(true);
            // 启用 DOM storage
            settings.setDomStorageEnabled(true);
            // 启用数据库
            settings.setDatabaseEnabled(true);
            // 设置缓存模式
            settings.setCacheMode(WebSettings.LOAD_DEFAULT);
            // 启用混合内容（HTTP/HTTPS）
            settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
            // 启用触摸事件
            webView.setFocusable(true);
            webView.setFocusableInTouchMode(true);
            webView.requestFocus();
        }
    }
}
