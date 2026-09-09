const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());

// ===== 健康检查 =====
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// ===== 步骤1：用 SSO Token 换取 Bearer Token =====
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

// ===== 步骤2：用 Bearer Token 绑定安全令 =====
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

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`✅ 后端服务已启动，端口: ${PORT}`);
});