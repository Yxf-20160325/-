// 插件系统测试脚本
// 使用方法: node test-plugins.js

const fs = require('fs');
const path = require('path');

const pluginDir = path.join(__dirname, 'plugins');

console.log('=== 插件系统测试 ===\n');

// 测试1：检查插件目录
console.log('测试1: 检查插件目录');
if (fs.existsSync(pluginDir)) {
    console.log('✓ 插件目录存在:', pluginDir);
} else {
    console.log('✗ 插件目录不存在');
    process.exit(1);
}

// 测试2：列出插件文件
console.log('\n测试2: 列出插件文件');
const pluginFiles = fs.readdirSync(pluginDir).filter(file => file.endsWith('.js'));
console.log(`找到 ${pluginFiles.length} 个插件文件:`);
pluginFiles.forEach(file => console.log('  -', file));

// 测试3：加载并验证插件
console.log('\n测试3: 加载并验证插件结构');
let validCount = 0;
let invalidCount = 0;

pluginFiles.forEach(file => {
    try {
        const pluginPath = path.join(pluginDir, file);
        const plugin = require(pluginPath);

        // 检查必需属性
        const hasName = plugin.name;
        const hasInit = typeof plugin.init === 'function';
        const hasDestroy = typeof plugin.destroy === 'function';

        if (hasName && hasInit) {
            console.log(`✓ ${plugin.name || file}: 结构正确`);
            console.log(`  描述: ${plugin.description || '无'}`);
            console.log(`  版本: ${plugin.version || '1.0.0'}`);
            console.log(`  作者: ${plugin.author || '未知'}`);
            validCount++;
        } else {
            console.log(`✗ ${file}: 结构不正确`);
            if (!hasName) console.log('  缺少 name 属性');
            if (!hasInit) console.log('  缺少 init 函数');
            invalidCount++;
        }
    } catch (error) {
        console.log(`✗ ${file}: 加载失败`);
        console.log(`  错误: ${error.message}`);
        invalidCount++;
    }
});

// 测试4：检查示例代码
console.log('\n测试4: 检查前端示例代码');
const indexHtmlPath = path.join(__dirname, 'public', 'index.html');
if (fs.existsSync(indexHtmlPath)) {
    const indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');
    const hasCorrectExample = indexHtml.includes("io.on('connection', (socket) =>");
    const hasWrongExample = !indexHtml.includes("io.on('user-joined', (data) =>");

    if (hasCorrectExample) {
        console.log('✓ 前端示例代码格式正确');
    } else {
        console.log('✗ 前端示例代码格式不正确');
    }

    if (hasWrongExample) {
        console.log('✓ 前端示例代码已修复（不包含错误的 io.on 用法）');
    } else {
        console.log('⚠ 前端示例代码可能仍包含错误的 io.on 用法');
    }
} else {
    console.log('✗ 找不到 index.html 文件');
}

// 总结
console.log('\n=== 测试结果 ===');
console.log(`有效插件: ${validCount}`);
console.log(`无效插件: ${invalidCount}`);
console.log(`总计: ${pluginFiles.length}`);

if (invalidCount === 0) {
    console.log('\n✓ 所有测试通过！');
} else {
    console.log('\n⚠ 发现问题，请检查插件文件');
}

console.log('\n提示: 启动服务器后，查看控制台输出以确认插件加载状态');
console.log('运行命令: npm start');
