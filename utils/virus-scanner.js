const NodeClam = require('clamscan');
const fs = require('fs');
const path = require('path');

class VirusScanner {
    constructor() {
        this.clamscan = null;
        this.initialized = false;
        this.initialize();
    }

    // 初始化ClamAV扫描器
    async initialize() {
        try {
            console.log('正在初始化ClamAV病毒扫描器...');
            
            this.clamscan = await new NodeClam().init({
                removeInfected: false, // 发现病毒时不自动删除文件
                quarantineInfected: false, // 不隔离感染文件
                scanLog: path.join(__dirname, '../logs/scan.log'), // 扫描日志
                debugMode: false, // 调试模式
                fileList: false, // 不生成文件列表
                scanRecursively: false, // 不递归扫描
                clamdscan: {
                    socket: false, // 使用TCP端口而非Unix socket
                    host: 'localhost',
                    port: 3310,
                    timeout: 60000, // 60秒超时
                    localFallback: true // 如果无法连接到clamd，使用本地命令行
                },
                clamdscanbin: this.findClamScanBinary(), // 尝试自动查找可执行文件
                timeout: 60000 // 全局超时
            });

            this.initialized = true;
            console.log('ClamAV病毒扫描器初始化成功');
        } catch (error) {
            console.warn('ClamAV初始化失败，病毒扫描功能将不可用:', error.message);
            console.warn('请确保已安装ClamAV并启动服务，或使用npm run install-clamav命令安装');
            this.initialized = false;
        }
    }

    // 尝试查找ClamScan可执行文件
    findClamScanBinary() {
        const possiblePaths = [
            'C:\\Program Files\\ClamAV\\clamdscan.exe',
            'C:\\Program Files (x86)\\ClamAV\\clamdscan.exe',
            '/usr/bin/clamdscan',
            '/usr/local/bin/clamdscan'
        ];

        for (const path of possiblePaths) {
            if (fs.existsSync(path)) {
                return path;
            }
        }

        return 'clamdscan'; // 依赖系统PATH
    }

    // 扫描文件
    async scanFile(filePath) {
        try {
            // 确保扫描器已初始化
            if (!this.initialized) {
                await this.initialize();
                if (!this.initialized) {
                    // 初始化失败，默认允许文件上传
                    return {
                        safe: true,
                        scanned: false,
                        message: 'ClamAV未初始化，跳过病毒扫描'
                    };
                }
            }

            // 检查文件是否存在
            if (!fs.existsSync(filePath)) {
                throw new Error('文件不存在');
            }

            console.log('开始病毒扫描:', path.basename(filePath));
            
            // 执行扫描
            const result = await this.clamscan.scanFile(filePath);
            
            console.log('扫描结果:', result);

            if (result && result.isInfected) {
                return {
                    safe: false,
                    scanned: true,
                    viruses: result.viruses,
                    message: '文件被检测到病毒'
                };
            } else {
                return {
                    safe: true,
                    scanned: true,
                    message: '文件安全'
                };
            }
        } catch (error) {
            console.error('病毒扫描失败:', error.message);
            // 扫描失败时，默认允许文件上传（避免ClamAV问题导致正常文件无法上传）
            return {
                safe: true,
                scanned: false,
                error: error.message,
                message: '病毒扫描失败，默认允许上传'
            };
        }
    }

    // 扫描缓冲区数据（直接从内存扫描）
    async scanBuffer(buffer, filename) {
        try {
            // 创建临时文件
            const tempDir = path.join(__dirname, '../temp');
            if (!fs.existsSync(tempDir)) {
                fs.mkdirSync(tempDir, { recursive: true });
            }

            const tempFilePath = path.join(tempDir, filename || `temp-${Date.now()}`);
            fs.writeFileSync(tempFilePath, buffer);

            // 扫描临时文件
            const result = await this.scanFile(tempFilePath);

            // 清理临时文件
            try {
                fs.unlinkSync(tempFilePath);
            } catch (e) {
                console.warn('清理临时文件失败:', e.message);
            }

            return result;
        } catch (error) {
            console.error('缓冲区扫描失败:', error.message);
            return {
                safe: true,
                scanned: false,
                error: error.message,
                message: '病毒扫描失败，默认允许上传'
            };
        }
    }
}

// 导出单例实例
module.exports = new VirusScanner();
