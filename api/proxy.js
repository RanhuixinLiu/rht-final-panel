// 檔案路徑: /api/proxy.js
const fetch = require('node-fetch');
const crypto = require('crypto'); // 引入 Node.js 內建的加密模組

// 在函數外部宣告一個變數，用來在 Vercel 環境中快取 Token
// 這樣可以讓 Token 在多次請求之間共享，直到它過期
let cachedToken = {
  value: null,
  expiresAt: 0,
};

// --- 這是獲取 Token 的核心函數 ---
async function getValidToken() {
  // 檢查快取的 Token 是否仍然有效 (我們預留了 60 秒的緩衝時間)
  if (cachedToken.value && Date.now() < cachedToken.expiresAt - 60000) {
    console.log("Using cached token.");
    return cachedToken.value;
  }

  console.log("Fetching a new token...");
  // 從 Vercel 環境變數中讀取【使用者憑證】
  const username = process.env.LOGIN_USERNAME;
  const password = process.env.LOGIN_PASSWORD;

  if (!username || !password) {
    throw new Error('Username or Password is not set in Vercel Environment Variables.');
  }

  // 1. 對【使用者密碼】進行標準 MD5 加密
  const standardHash = crypto.createHash('md5').update(password).digest('hex');

  // 2. 應用我们逆向工程發現的【獨特重排演算法】
  const finalPassword = standardHash.slice(-6) + standardHash.slice(6, 26) + standardHash.slice(0, 6);

  const AUTH_ENDPOINT = '/api/v1/login/login';
  const targetApiHost = 'http://39.108.191.53:8089';
  const authUrl = `${targetApiHost}${AUTH_ENDPOINT}`;

  try {
    const response = await fetch(authUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // 使用【使用者名稱】和【重排後的密碼】進行登入
      body: JSON.stringify({
        username: username,
        password: finalPassword,
      }),
    });

    const data = await response.json();

    if (!response.ok || !data.data || !data.data.token) {
      // 如果登錄失敗，清除快取並拋出錯誤
      cachedToken = { value: null, expiresAt: 0 };
      throw new Error(`Failed to fetch token: ${data.msg || 'Unknown error'}`);
    }
    
    const accessToken = data.data.token; 
    // expiresIn 是 token 的有效期，单位是秒
    const expiresIn = data.data.expires_in || 3600; // 如果不存在，默認為1小時

    // 更新快取
    cachedToken.value = accessToken;
    // 计算出毫秒级的过期时间戳
    cachedToken.expiresAt = Date.now() + expiresIn * 1000; 

    console.log("Successfully fetched a new token.");
    return accessToken;

  } catch (error) {
    console.error('Error fetching token:', error);
    // 發生錯誤時，重置快取
    cachedToken = { value: null, expiresAt: 0 }; 
    throw error;
  }
}


// --- 這是我們主要的代理處理函數 (Serverless Function) ---
module.exports = async (req, res) => {
  try {
    // 1. 自動獲取一個有效的 X-Token
    const xToken = await getValidToken();
    const appKey = process.env.APP_KEY;

    if (!appKey) {
        throw new Error('APP_KEY is not set in Vercel Environment Variables.');
    }

    // 2. 準備轉發請求
    const targetApiHost = 'http://39.108.191.53:8089';
    // 從請求 URL 中移除代理路徑 /api/proxy，得到目標路徑
    const targetPath = req.url.replace('/api/proxy', '');
    const targetUrl = `${targetApiHost}${targetPath}`;

    // 3. 組合轉發請求的選項
    const fetchOptions = {
      method: req.method,
      headers: {
        // 保留原始請求的 Content-Type，如果沒有則默認為 json
        'Content-Type': req.headers['content-type'] || 'application/json',
        // 加上我們必要的認證標頭
        'App-Key': appKey,
        'X-Token': xToken,
      },
    };

    // 如果原始請求是 POST, PUT 等帶有 Body 的請求，我們需要將 Body 轉發過去
    // Vercel 的 body parser 会自动解析 JSON body，所以我们直接用 req.body
    if (req.method !== 'GET' && req.method !== 'HEAD' && req.body) {
      fetchOptions.body = JSON.stringify(req.body);
    }
    
    // 4. 發送請求到真正的 RHT 平台
    const targetResponse = await fetch(targetUrl, fetchOptions);
    
    // 5. 獲取 RHT 平台的響應
    // 我們需要先檢查 Content-Type 來決定如何處理響應
    const contentType = targetResponse.headers.get('content-type');
    let responseData;
    if (contentType && contentType.includes('application/json')) {
        responseData = await targetResponse.json();
    } else {
        responseData = await targetResponse.text();
    }
    
    // 6. 將 RHT 平台的響應原封不動地送回給前端
    res.status(targetResponse.status).json(responseData);

  } catch (error) {
    console.error('Proxy handler error:', error);
    // 如果過程中發生任何錯誤（例如獲取Token失敗），向前端返回 500 錯誤
    res.status(500).json({ 
        error: 'An error occurred in the proxy handler.', 
        details: error.message 
    });
  }
};