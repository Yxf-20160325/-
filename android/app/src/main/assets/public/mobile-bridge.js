/**
 * 聊天室 - Capacitor 移动端适配层
 * 
 * 此脚本在 Capacitor App 环境中自动加载，
 * 提供以下功能：
 * 1. 检测并适配原生 App 环境
 * 2. 处理状态栏样式
 * 3. 处理安全区域（刘海屏等）
 * 4. 原生功能桥接（相机、文件选择、分享等）
 * 5. 优化触摸交互
 */

(function() {
    'use strict';
    
    // 检测是否在 Capacitor 原生环境中
    const isNative = window.Capacitor && window.Capacitor.isNativePlatform();
    
    if (!isNative) {
        console.log('[ChatRoom Mobile] 运行在浏览器环境，跳过移动端适配');
        return;
    }
    
    console.log('[ChatRoom Mobile] 检测到原生 App 环境，初始化移动端适配...');
    
    // ====== 全局状态 ======
    const ChatRoomMobile = {
        isNative: true,
        platform: null,      // 'android' | 'ios'
        safeArea: { top: 0, bottom: 0 },
        initialized: false
    };
    
    // 获取平台信息
    async function getPlatformInfo() {
        try {
            const { Device } = Capacitor.Plugins;
            if (Device) {
                const info = await Device.getInfo();
                ChatRoomMobile.platform = info.platform.toLowerCase();
                console.log(`[ChatRoom Mobile] 平台: ${info.platform}, 型号: ${info.model}`);
            }
        } catch (e) {
            console.warn('[ChatRoom Mobile] 无法获取设备信息:', e.message);
        }
    }
    
    // ====== 安全区域处理 ======
    function applySafeAreaInsets() {
        // 为容器添加 padding 以避免内容被状态栏/底部指示器遮挡
        document.documentElement.style.setProperty('--safe-area-top', `${ChatRoomMobile.safeArea.top}px`);
        document.documentElement.style.setProperty('safe-area-bottom', `${ChatRoomMobile.safeArea.bottom}px`);
        
        const container = document.querySelector('.container');
        if (container) {
            container.style.paddingTop = `max(20px, ${ChatRoomMobile.safeArea.top}px)`;
            container.style.paddingBottom = `max(20px, ${ChatRoomMobile.safeArea.bottom}px)`;
        }
        
        // header 区域需要额外处理
        const header = document.querySelector('.header');
        if (header) {
            header.style.paddingTop = `calc(20px + ${ChatRoomMobile.safeArea.top}px)`;
        }
        
        console.log(`[ChatRoom Mobile] 安全区域: top=${ChatRoomMobile.safeArea.top}px, bottom=${ChatRoomMobile.safeArea.bottom}px`);
    }
    
    async function getSafeAreaInsets() {
        try {
            const { SafeArea, StatusBar } = Capacitor.Plugins;
            
            if (SafeArea) {
                const insets = await SafeArea.getSafeAreaInsets();
                ChatRoomMobile.safeArea = {
                    top: insets.insets.top,
                    bottom: insets.insets.bottom
                };
            } else if (StatusBar) {
                const info = await StatusBar.getInfo();
                ChatRoomMobile.safeArea.top = info.height || 0;
            }
            
            applySafeAreaInsets();
        } catch (e) {
            console.warn('[ChatRoom Mobile] 安全区域检测失败:', e.message);
            // 使用默认值
            applySafeAreaInsets();
        }
    }
    
    // ====== 状态栏样式 ======
    function setupStatusBar() {
        const { StatusBar } = Capacitor.Plugins;
        if (!StatusBar) return;
        
        // 设置状态栏为浅色内容 + 渐变背景
        StatusBar.setStyle({ style: 'LIGHT' }).catch(e => 
            console.warn('[ChatRoom Mobile] 设置状态栏样式失败:', e.message)
        );
        
        // 设置背景色与 App 主题一致
        StatusBar.setBackgroundColor({
            color: '#667eea'
        }).catch(() => {});
    }
    
    // ====== 屏幕方向锁定（可选） ======
    function lockPortraitMode() {
        const { ScreenOrientation } = Capacitor.Plugins;
        if (!ScreenOrientation) return;
        
        ScreenOrientation.lock({ orientation: 'portrait' }).catch(() => {
            // 部分设备不支持，忽略错误
        });
    }
    
    // ====== 原生功能桥接 ======
    
    /**
     * 从相机或相册选择图片
     */
    async function pickImage(options = {}) {
        try {
            const { Camera, CameraResultType, CameraSource } = Capacitor.Plugins;
            if (!Camera) return null;
            
            const photo = await Camera.getPhotos({
                quality: options.quality || 90,
                allowEditing: options.allowEditing || false,
                resultType: CameraResultType.Base64,
                source: options.source === 'camera' ? CameraSource.Camera : 
                        options.source === 'photos' ? CameraSource.Photos :
                        CameraSource.Prompt,
                saveToGallery: options.saveToGallery || false,
                correctOrientation: true
            });
            
            return photo;
        } catch (e) {
            console.error('[ChatRoom Mobile] 选择图片失败:', e.message);
            throw e;
        }
    }
    
    /**
     * 分享内容到其他应用
     */
    async function shareContent(options) {
        try {
            const { Share } = Capacitor.Plugins;
            if (!Share) {
                // 回退到 Web Share API
                if (navigator.share) {
                    await navigator.share({
                        title: options.title || '聊天室',
                        text: options.text,
                        url: options.url
                    });
                    return true;
                }
                return false;
            }
            
            await Share.share({
                title: options.title || '聊天室',
                text: options.text,
                url: options.url || '',
                dialogTitle: options.title || '分享到...'
            });
            return true;
        } catch (e) {
            if (e.message?.includes('cancel')) return false;
            console.error('[ChatRoom Mobile] 分享失败:', e.message);
            return false;
        }
    }
    
    /**
     * 复制文本到剪贴板
     */
    async function copyToClipboard(text) {
        try {
            const { Clipboard } = Capacitor.Plugins;
            if (Clipboard) {
                await Clipboard.write({ string: text });
                return true;
            }
            // 回退到浏览器 API
            await navigator.clipboard.writeText(text);
            return true;
        } catch (e) {
            console.error('[ChatRoom Mobile] 复制失败:', e.message);
            return false;
        }
    }
    
    /**
     * 获取设备信息（用于调试）
     */
    async function getDeviceInfo() {
        try {
            const { Device } = Capacitor.Plugins;
            if (Device) return await Device.getInfo();
        } catch (e) {}
        return null;
    }
    
    /**
     * 震动反馈
     */
    function vibrate(duration = 50) {
        try {
            const { Haptics, ImpactStyle } = Capacitor.Plugins;
            if (Haptics) {
                Haptics.impact({ style: ImpactStyle.Light });
                return;
            }
            navigator.vibrate?.(duration);
        } catch (e) {}
    }
    
    // ====== 触摸优化 ======
    function optimizeTouchInteractions() {
        // 禁用双击缩放（移动端常见问题）
        const meta = document.querySelector('meta[name="viewport"]');
        if (meta) {
            meta.setAttribute('content', 
                'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover'
            );
        }
        
        // 为可点击元素添加 touch-action
        document.addEventListener('touchstart', function() {}, { passive: true });
        
        // 优化按钮点击响应
        document.addEventListener('click', function(e) {
            const target = e.target.closest('button, .btn, [onclick], .header-btn');
            if (target) {
                vibrate(10); // 轻微触觉反馈
            }
        }, { passive: true });
    }
    
    // ====== 网络状态监听 ======
    function setupNetworkListener() {
        const { Network } = Capacitor.Plugins;
        if (!Network) return;
        
        Network.addListener('networkStatusChange', (status) => {
            console.log(`[ChatRoom Mobile] 网络变化: ${status.connected ? '已连接' : '已断开'}, 类型: ${status.connectionType}`);
            
            if (!status.connected) {
                // 显示离线提示
                showNetworkAlert(false);
            } else if (status.connectionType !== 'none') {
                showNetworkAlert(true);
            }
        });
        
        // 启动时获取网络状态
        Network.getStatus().then(status => {
            console.log(`[ChatRoom Mobile] 当前网络: ${status.connected ? '在线' : '离线'}, ${status.connectionType}`);
        });
    }
    
    function showNetworkAlert(online) {
        const existing = document.getElementById('network-status-bar');
        if (existing) existing.remove();
        
        const bar = document.createElement('div');
        bar.id = 'network-status-bar';
        bar.style.cssText = `
            position: fixed; top: 0; left: 0; right: 0; z-index: 99999;
            padding: 8px 16px; text-align: center; font-size: 14px;
            color: white; font-weight: 500; transition: all 0.3s ease;
            background: ${online ? '#28a745' : '#dc3545'};
        `;
        bar.textContent = online ? '网络已恢复连接' : '当前无网络连接，部分功能不可用';
        document.body.appendChild(bar);
        
        setTimeout(() => {
            bar.style.opacity = '0';
            setTimeout(() => bar.remove(), 300);
        }, 3000);
    }
    
    // ====== App 生命周期 ======
    function setupAppLifecycle() {
        const { App } = Capacitor.Plugins;
        if (!App) return;
        
        App.addListener('appStateChange', ({ isActive }) => {
            if (isActive) {
                console.log('[ChatRoom Mobile] App 进入前台，检查连接...');
                // 通知前端 Socket.IO 可以尝试重连
                window.dispatchEvent(new CustomEvent('app-foreground'));
            } else {
                console.log('[ChatRoom Mobile] App 进入后台');
                window.dispatchEvent(new CustomEvent('app-background'));
            }
        });
        
        // 处理 URL 打开（用于深链接）
        App.addListener('appUrlOpen', (data) => {
            console.log('[ChatRoom Mobile] URL 打开:', data.url);
            window.dispatchEvent(new CustomEvent('app-url-open', { detail: { url: data.url } }));
        });
    }
    
    // ====== 初始化 ======
    async function init() {
        console.log('[ChatRoom Mobile] 开始初始化...');
        
        await getPlatformInfo();
        setupStatusBar();
        await getSafeAreaInsets();
        lockPortraitMode();
        optimizeTouchInteractions();
        setupNetworkListener();
        setupAppLifecycle();
        
        ChatRoomMobile.initialized = true;
        
        // 将 API 暴露给全局使用
        window.ChatRoomMobile = ChatRoomMobile;
        window.chatroomPickImage = pickImage;
        window.chatroomShare = shareContent;
        window.chatroomCopyText = copyToClipboard;
        window.chatroomVibrate = vibrate;
        window.chatroomDeviceInfo = getDeviceInfo;
        
        console.log('[ChatRoom Mobile] 初始化完成！API 已挂载到 window 对象');
        
        // 触发自定义事件，让主应用知道移动端适配已就绪
        window.dispatchEvent(new CustomEvent('chatroom-mobile-ready', { detail: ChatRoomMobile }));
    }
    
    // DOM 加载完成后初始化
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
})();
