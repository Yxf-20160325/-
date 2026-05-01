// 天气查询插件
module.exports = {
    name: "weather",
    description: "查询指定城市的天气信息",
    version: "1.0.0",
    init: function(app, io, context) {
        const { users, rooms } = context;
        
        // 注册天气查询命令
        io.on('connection', (socket) => {
            socket.on('weather-query', async (data) => {
                try {
                    const { city } = data;
                    if (!city) {
                        socket.emit('weather-response', {
                            success: false,
                            error: '请输入城市名称'
                        });
                        return;
                    }
                    
                    // 调用天气API
                    const weatherData = await getWeather(city);
                    
                    socket.emit('weather-response', {
                        success: true,
                        data: weatherData
                    });
                    
                } catch (error) {
                    console.error('天气查询失败:', error);
                    socket.emit('weather-response', {
                        success: false,
                        error: '天气查询失败，请稍后重试'
                    });
                }
            });
        });
        
        // 天气查询函数
        async function getWeather(city) {
            try {
                const https = require('https');
                const querystring = require('querystring');
                
                const WEATHER_API_KEY = 'cb9fc**********5e4e9248'; // 已打码
                const postData = querystring.stringify({
                    key: WEATHER_API_KEY,
                    city: city
                });
                
                const options = {
                    hostname: 'api-proxy-juhe.jenius.cn',
                    path: '/simpleWeather/query',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Content-Length': Buffer.byteLength(postData)
                    }
                };
                
                return new Promise((resolve, reject) => {
                    const req = https.request(options, (res) => {
                        let data = '';
                        res.on('data', (chunk) => {
                            data += chunk;
                        });
                        res.on('end', () => {
                            try {
                                const weatherData = JSON.parse(data);
                                
                                if (weatherData && weatherData.result) {
                                    const result = weatherData.result;
                                    const realtime = result.realtime || {};
                                    const forecast = result.future || result.forecast || [];
                                    
                                    resolve({
                                        city: result.city || result.cityName || city,
                                        temperature: realtime.temperature || result.temperature || result.temp || '未知',
                                        weather: realtime.info || result.weather || result.weatherDesc || '未知',
                                        wind: `${realtime.direct || ''} ${realtime.power || ''}`.trim() || result.wind || result.windDirection || result.windPower || '未知',
                                        humidity: realtime.humidity || result.humidity || '未知',
                                        updateTime: result.updateTime || result.date || new Date().toLocaleString(),
                                        forecast: forecast.slice(0, 5).map(day => ({
                                            date: day.date || day.datetime || '',
                                            weather: day.weather || day.info || '',
                                            temperature: `${day.temperature || day.temp || day.low || '0'}-${day.high || day.temp || '0'}°C`,
                                            wind: day.wind || day.direct || ''
                                        }))
                                    });
                                } else {
                                    resolve({
                                        city: city,
                                        temperature: '未知',
                                        weather: '未知',
                                        wind: '未知',
                                        humidity: '未知',
                                        updateTime: new Date().toLocaleString()
                                    });
                                }
                            } catch (error) {
                                console.error('解析天气数据失败:', error);
                                resolve({
                                    city: city,
                                    temperature: '未知',
                                    weather: '未知',
                                    wind: '未知',
                                    humidity: '未知',
                                    updateTime: new Date().toLocaleString()
                                });
                            }
                        });
                    });
                    
                    req.on('error', (error) => {
                        console.error('天气查询请求失败:', error);
                        resolve({
                            city: city,
                            temperature: '未知',
                            weather: '未知',
                            wind: '未知',
                            humidity: '未知',
                            updateTime: new Date().toLocaleString()
                        });
                    });
                    
                    req.write(postData);
                    req.end();
                });
            } catch (error) {
                console.error('天气查询失败:', error);
                return {
                    city: city,
                    temperature: '未知',
                    weather: '未知',
                    wind: '未知',
                    humidity: '未知',
                    updateTime: new Date().toLocaleString()
                };
            }
        }
    },
    destroy: function() {
        // 插件销毁代码
        console.log('天气插件已销毁');
    }
};
