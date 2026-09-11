const express = require('express');
const cors = require('cors');
const axios = require('axios');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(cors());
app.use(express.json());

// =============================================================
// 🔑 API 密钥验证（防止别人盗用你的后端）
// 
// =============================================================
const API_KEY = 'dongjdongj9494';  // ← 改成你自己的

app.use('/api/*', (req, res, next) => {
    const userKey = req.headers['x-api-key'];
    if (userKey !== API_KEY) {
        return res.status(403).json({ 
            error: '无效的 API 密钥，请检查配置' 
        });
    }
    next();
});

// =============================================================
// 1. 限流（15分钟最多100次请求）
// =============================================================
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: '请求过于频繁，请 15 分钟后重试' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// =============================================================
// 2. 更严格的限流：密码验证接口（5分钟最多10次）
// =============================================================
const passwordLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    message: { error: '密码尝试次数过多，请 5 分钟后重试' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/verify-password', passwordLimiter);

// =============================================================
// 3. 密码错误记录（防暴力破解）
// =============================================================
const wrongPasswordAttempts = new Map();
const VALID_PASSWORD = '78.95866253';  // ← 你可以改这个密码

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// =============================================================
// 4. 密码验证
// =============================================================
app.post('/api/verify-password', async (req, res) => {
    const { password } = req.body;
    const ip = req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 'unknown';

    if (wrongPasswordAttempts.has(ip)) {
        const data = wrongPasswordAttempts.get(ip);
        if (data.count >= 5) {
            const timeElapsed = (Date.now() - data.lastAttempt) / 60000;
            if (timeElapsed < 15) {
                return res.status(429).json({
                    error: `尝试次数过多，请 ${Math.ceil(15 - timeElapsed)} 分钟后重试`
                });
            } else {
                wrongPasswordAttempts.delete(ip);
            }
        }
    }

    if (password === VALID_PASSWORD) {
        wrongPasswordAttempts.delete(ip);
        console.log(`✅ 密码验证成功 - IP: ${ip}`);
        res.json({ valid: true });
    } else {
        if (wrongPasswordAttempts.has(ip)) {
            const data = wrongPasswordAttempts.get(ip);
            data.count += 1;
            data.lastAttempt = Date.now();
        } else {
            wrongPasswordAttempts.set(ip, { count: 1, lastAttempt: Date.now() });
        }

        const attemptCount = wrongPasswordAttempts.get(ip).count;
        console.log(`❌ 密码验证失败 - IP: ${ip}，尝试次数: ${attemptCount}`);
        await sleep(2000);
        res.status(401).json({ valid: false });
    }
});

// =============================================================
// 5. 健康检查
// =============================================================
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok' });
});

// =============================================================
// 6. 换取 Bearer Token
// =============================================================
app.post('/api/exchange-token', async (req, res) => {
    const { ssoToken } = req.body;
    if (!ssoToken) {
        return res.status(400).json({ error: '缺少 SSO Token' });
    }

    try {
        const response = await axios.post(
            'https://oauth.battle.net/oauth/sso',
            new URLSearchParams({
                client_id: 'baedda12fe054e4abdfc3ad7bdea970a',
                grant_type: 'client_sso',
                scope: 'auth.authenticator',
                token: ssoToken
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8'
                }
            }
        );

        const { access_token } = response.data;
        res.json({ bearerToken: access_token });
    } catch (error) {
        console.error('换取 Token 失败:', error.response?.data || error.message);
        res.status(500).json({
            error: '换取 Token 失败',
            detail: error.response?.data || error.message
        });
    }
});

// =============================================================
// 7. 绑定安全令
// =============================================================
app.post('/api/bind-authenticator', async (req, res) => {
    const { bearerToken } = req.body;
    if (!bearerToken) {
        return res.status(400).json({ error: '缺少 Bearer Token' });
    }

    try {
        const response = await axios.post(
            'https://authenticator-rest-api.bnet-identity.blizzard.net/v1/authenticator',
            {},
            {
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${bearerToken}`
                }
            }
        );

        const { serial, restoreCode, deviceSecret } = response.data;
        res.json({ serial, restoreCode, deviceSecret });
    } catch (error) {
        console.error('绑定安全令失败:', error.response?.data || error.message);
        res.status(500).json({
            error: '绑定安全令失败',
            detail: error.response?.data || error.message
        });
    }
});

// =============================================================
// 8. 根路径提示
// =============================================================
app.get('/', (req, res) => {
    res.json({
        message: '✅ 后端服务运行正常',
        endpoints: {
            health: '/api/health',
            verifyPassword: '/api/verify-password (POST)',
            exchangeToken: '/api/exchange-token (POST)',
            bindAuthenticator: '/api/bind-authenticator (POST)'
        }
    });
});

// =============================================================
// 9. 启动服务
// =============================================================
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`✅ 后端服务已启动，端口: ${PORT}`);
});
