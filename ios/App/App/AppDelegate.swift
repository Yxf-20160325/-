import UIKit
import Capacitor
import UserNotifications

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?
    
    // 后台任务标识符，用于向系统申请额外执行时间
    var backgroundTask: UIBackgroundTaskIdentifier = .invalid

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // 注册远程推送通知
        registerForPushNotifications(application)
        return true
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        // 回到前台时清除角标
        UIApplication.shared.applicationIconBadgeNumber = 0
    }
    
    // MARK: - 推送通知注册
    
    func registerForPushNotifications(_ application: UIApplication) {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error = error {
                print("[Push] 请求通知权限失败: \(error.localizedDescription)")
                return
            }
            if granted {
                DispatchQueue.main.async {
                    application.registerForRemoteNotifications()
                    print("[Push] 已向 APNs 注册远程通知")
                }
            } else {
                print("[Push] 用户拒绝了通知权限")
            }
        }
        // 确保通知中心设置正确
        UNUserNotificationCenter.current().delegate = self
    }

    // APNs 注册成功，收到设备 token
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let tokenString = deviceToken.map { String(format: "%02.2hhx", $0) }.joined()
        print("[Push] APNs Device Token: \(tokenString)")
        // 通知 Capacitor 插件（@capacitor/push-notifications 会自动处理）
        NotificationCenter.default.post(
            name: NSNotification.Name("CAPNotificationsRegistered"),
            object: nil,
            userInfo: ["token": tokenString]
        )
    }

    // APNs 注册失败
    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        print("[Push] APNs 注册失败: \(error.localizedDescription)")
    }

    // 收到远程推送（前台 & 后台唤醒）
    func application(_ application: UIApplication,
                     didReceiveRemoteNotification userInfo: [AnyHashable: Any],
                     fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        print("[Push] 收到远程通知: \(userInfo)")
        completionHandler(.newData)
    }

    // MARK: - 后台保活

    func applicationDidEnterBackground(_ application: UIApplication) {
        // 向系统申请后台执行时间（最长约 30 秒），防止 Socket 立即断开
        backgroundTask = application.beginBackgroundTask(withName: "ChatroomKeepAlive") { [weak self] in
            // 超时回调，必须结束任务
            self?.endBackgroundTask()
        }
        print("[Background] App 进入后台，已申请后台时间")
    }

    func applicationWillEnterForeground(_ application: UIApplication) {
        endBackgroundTask()
        print("[Background] App 回到前台")
    }

    func applicationWillTerminate(_ application: UIApplication) {
        endBackgroundTask()
    }

    private func endBackgroundTask() {
        if backgroundTask != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTask)
            backgroundTask = .invalid
        }
    }

    // MARK: - 其他 Delegate

    func applicationWillResignActive(_ application: UIApplication) {}

    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        return ApplicationDelegateProxy.shared.application(app, open: url, options: options)
    }

    func application(_ application: UIApplication,
                     continue userActivity: NSUserActivity,
                     restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
        return ApplicationDelegateProxy.shared.application(application,
                                                           continue: userActivity,
                                                           restorationHandler: restorationHandler)
    }
}

// MARK: - UNUserNotificationCenterDelegate

extension AppDelegate: UNUserNotificationCenterDelegate {
    
    // App 在前台时收到通知 → 仍然展示 banner
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                 willPresent notification: UNNotification,
                                 withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        // 前台也显示通知 banner + 声音 + 角标
        completionHandler([.banner, .sound, .badge])
    }

    // 用户点击通知
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                 didReceive response: UNNotificationResponse,
                                 withCompletionHandler completionHandler: @escaping () -> Void) {
        let userInfo = response.notification.request.content.userInfo
        print("[Push] 用户点击通知: \(userInfo)")
        completionHandler()
    }
}
