/**
 * NotifyHub - Cloudflare Worker
 * 包含了 前端Web UI、后端API、Webhook签名算法 和 Cron定时任务
 */

// ============================================================================
// 1. 数据库表结构初始化 (D1)
// ============================================================================
const INIT_SQL_CHANNELS = `CREATE TABLE IF NOT EXISTS channels (id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, webhook_url TEXT NOT NULL, security_type TEXT NOT NULL, security_key TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);`;

const INIT_SQL_TASKS = `CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, name TEXT NOT NULL, expire_date TEXT NOT NULL, remind_days TEXT NOT NULL, channel_id TEXT NOT NULL, remark TEXT, status TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);`;

const INIT_SQL_LOGS = `CREATE TABLE IF NOT EXISTS logs (id TEXT PRIMARY KEY, task_name TEXT, channel_name TEXT, status TEXT, error_msg TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);`;

// ============================================================================
// 2. 加密与安全辅助函数
// ============================================================================
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getAuthToken(secret) {
    return await sha256(secret + "notifyhub_salt");
}

function generateId() {
    return Math.random().toString(36).substring(2, 10) + Date.now().toString(36);
}

// 钉钉加签
async function signDingTalk(secret) {
    const timestamp = Date.now().toString();
    const cleanSecret = secret.trim(); // 强制去除首尾空格
    const stringToSign = timestamp + '\n' + cleanSecret;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", encoder.encode(cleanSecret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(stringToSign));
    const signBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
    return { timestamp, sign: encodeURIComponent(signBase64) };
}

// 飞书加签
async function signFeishu(secret) {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const cleanSecret = secret.trim(); // 强制去除首尾空格
    const stringToSign = timestamp + '\n' + cleanSecret;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", encoder.encode(stringToSign), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    
    // 飞书加签的规范：以 timestamp+secret 为 key，对空字符串进行 HMAC 运算
    const signature = await crypto.subtle.sign("HMAC", key, new Uint8Array(0)); 
    const signBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
    return { timestamp, sign: signBase64 };
}

// ============================================================================
// 3. 消息发送核心引擎
// ============================================================================
async function sendNotification(channel, task, isTest = false, db = null) {
    let url = channel.webhook_url.trim();

    // 【终极防御】无视数据库中的错误类型记录，强制根据 URL 特征判定真实平台
    let actualType = channel.type;
    if (url.includes('feishu.cn')) {
        actualType = 'feishu';
    } else if (url.includes('dingtalk.com')) {
        actualType = 'dingtalk';
    }

    const keyword = channel.security_type === 'keyword' ? (channel.security_key || '').trim() : '';
    
    // 强制将关键词注入标题最前方，确保 100% 命中官方校验规则
    let baseTitle = isTest ? "🔔 NotifyHub 测试通知" : `🔔 订阅到期提醒：${task ? task.name : '未知'}`;
    let title = keyword ? `【${keyword}】${baseTitle}` : baseTitle; 
    
    let daysText = "";
    if (!isTest && task) {
        // 计算剩余天数 (强制转换并对齐到北京时间 UTC+8 进行绝对天数计算)
        const beijingTime = new Date(Date.now() + 8 * 3600 * 1000);
        const todayUTC = Date.UTC(beijingTime.getUTCFullYear(), beijingTime.getUTCMonth(), beijingTime.getUTCDate());
        const [ey, em, ed] = task.expire_date.split('-').map(Number);
        const expireUTC = Date.UTC(ey, em - 1, ed);
        const diffDays = Math.round((expireUTC - todayUTC) / (1000 * 3600 * 24));
        
        if (diffDays > 0) daysText = `**剩余天数**：<font color="warning">${diffDays}天</font>\n`;
        else if (diffDays === 0) daysText = `**剩余天数**：<font color="warning">今天到期</font>\n`;
        else daysText = `**剩余天数**：<font color="comment">已超期 ${Math.abs(diffDays)}天</font>\n`;
    }

    let contentStr = `**任务名称**：${isTest ? '测试任务' : task.name}\n${daysText}`;
    if (!isTest && task) {
        contentStr += `**到期时间**：${task.expire_date}\n`;
        if (task.remark) contentStr += `**备注信息**：${task.remark}\n`;
    } else {
        contentStr += `**备注信息**：这是一条测试消息，您的 webhook 配置成功！\n`;
    }

    let payload = {};

    // 使用刚才强制覆盖的 actualType 进行判断，彻底避免因为历史脏数据导致发错格式
    if (actualType === 'dingtalk') {
        if (channel.security_type === 'sign') {
            const { timestamp, sign } = await signDingTalk(channel.security_key);
            url += (url.includes('?') ? '&' : '?') + `timestamp=${timestamp}&sign=${sign}`;
        }
        payload = {
            msgtype: "markdown",
            markdown: { title: title, text: `### ${title}\n\n` + contentStr }
        };
    } else if (actualType === 'feishu') {
        payload = {
            msg_type: "interactive",
            card: {
                config: { wide_screen_mode: true },
                header: { title: { tag: "plain_text", content: title }, template: isTest ? "blue" : "red" },
                elements: [{ tag: "markdown", content: contentStr }]
            }
        };
        if (channel.security_type === 'sign') {
            const { timestamp, sign } = await signFeishu(channel.security_key);
            payload.timestamp = timestamp;
            payload.sign = sign;
        }
    }

    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    
    // 解析返回结果，判断是否发送成功
    const resultText = await response.text();
    let isError = !response.ok;
    try {
        const rObj = JSON.parse(resultText);
        if ((rObj.errcode !== undefined && rObj.errcode !== 0) || (rObj.code !== undefined && rObj.code !== 0)) {
            isError = true;
        }
    } catch(e) {}

    // 写入日志到数据库
    if (db) {
        try {
            const taskName = isTest ? "测试任务" : (task ? task.name : '未知');
            const status = isError ? 'failed' : 'success';
            const errMsg = isError ? resultText : '';
            await db.prepare("INSERT INTO logs (id, task_name, channel_name, status, error_msg) VALUES (?, ?, ?, ?, ?)")
                .bind(generateId(), taskName, channel.name, status, errMsg).run();
        } catch(e) {
            console.error("写入日志失败:", e);
        }
    }
    
    // 改造为返回完整的对象，以供外层做更详细的 Debug
    return { response, payload, url, actualType, isError, resultText }; 
}

// ============================================================================
// 4. 定时任务逻辑 (Cron Triggers)
// ============================================================================
async function handleScheduled(env) {
    const { results: tasks } = await env.DB.prepare("SELECT * FROM tasks WHERE status = 'active'").all();
    const { results: channels } = await env.DB.prepare("SELECT * FROM channels").all();
    const channelsMap = channels.reduce((acc, c) => ({ ...acc, [c.id]: c }), {});

    // 强制锁定到北京时间的当天 0 点，防止云函数所在时区导致的推算偏移
    const beijingTime = new Date(Date.now() + 8 * 3600 * 1000);
    const todayUTC = Date.UTC(beijingTime.getUTCFullYear(), beijingTime.getUTCMonth(), beijingTime.getUTCDate());

    for (const task of tasks) {
        const [ey, em, ed] = task.expire_date.split('-').map(Number);
        const expireUTC = Date.UTC(ey, em - 1, ed);
        const diffDays = Math.round((expireUTC - todayUTC) / (1000 * 3600 * 24));
        
        const remindDays = JSON.parse(task.remind_days);
        if (remindDays.includes(diffDays)) {
            const channel = channelsMap[task.channel_id];
            if (channel) {
                try {
                    // 传入 env.DB 以便在发送后记录日志
                    await sendNotification(channel, task, false, env.DB);
                } catch (e) {
                    console.error("发送异常", task.name, e);
                    // 如果由于网络或代码错误直接崩溃，也要记录失败日志
                    try {
                        await env.DB.prepare("INSERT INTO logs (id, task_name, channel_name, status, error_msg) VALUES (?, ?, ?, ?, ?)")
                            .bind(generateId(), task.name, channel.name, 'failed', e.message).run();
                    } catch(err){}
                }
            }
        }
    }
}

// ============================================================================
// 5. 路由与 HTTP 处理
// ============================================================================
export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        
        // 配置缺失检查，返回规范的 JSON 错误
        if (!env.DB) {
            return Response.json({ error: "未绑定 D1 数据库，请检查 Cloudflare 设置 (变量名必须为 DB)" }, { status: 500 });
        }
        if (!env.ADMIN_SECRET) {
            return Response.json({ error: "未配置 ADMIN_SECRET，请在 Cloudflare 环境变量中添加" }, { status: 500 });
        }

        // 自动初始化数据库表 (分开执行，避免 D1 批量执行语句的兼容性问题)
        try {
            await env.DB.exec(INIT_SQL_CHANNELS);
            await env.DB.exec(INIT_SQL_TASKS);
            await env.DB.exec(INIT_SQL_LOGS);
        } catch (e) {
            console.error("DB Init Error:", e);
            // 如果建表失败，直接抛出，不要静默失败
            return Response.json({ error: "数据库初始化失败，请重试或检查 D1 状态: " + e.message }, { status: 500 });
        }

        const adminSecret = env.ADMIN_SECRET;
        
        const expectedToken = await getAuthToken(adminSecret);

        // API: 登录
        if (request.method === 'POST' && url.pathname === '/api/login') {
            const body = await request.json();
            if (body.password === adminSecret) {
                return new Response(JSON.stringify({ success: true }), {
                    headers: {
                        'Content-Type': 'application/json',
                        'Set-Cookie': `auth_token=${expectedToken}; Path=/; HttpOnly; Max-Age=2592000; SameSite=Strict`
                    }
                });
            }
            return new Response(JSON.stringify({ success: false, msg: "密码错误" }), { status: 401 });
        }

        // 鉴权拦截
        if (url.pathname.startsWith('/api/') || url.pathname === '/dashboard') {
            const cookie = request.headers.get('Cookie') || '';
            if (!cookie.includes(`auth_token=${expectedToken}`)) {
                return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
            }
        }

        // API 路由分配
        if (url.pathname.startsWith('/api/')) {
            return await handleApi(request, env, url.pathname);
        }

        // 页面入口 (HTML直出)
        return new Response(htmlTemplate, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    },

    async scheduled(event, env, ctx) {
        ctx.waitUntil(handleScheduled(env));
    }
};

// 后端 API 实现
async function handleApi(request, env, path) {
    const method = request.method;
    const db = env.DB;
    
    try {
        if (path === '/api/stats' && method === 'GET') {
            const tasksCount = await db.prepare("SELECT count(*) as c FROM tasks").first('c');
            const channelsCount = await db.prepare("SELECT count(*) as c FROM channels").first('c');
            const logsCount = await db.prepare("SELECT count(*) as c FROM logs").first('c');
            return Response.json({ tasks: tasksCount, channels: channelsCount, logs: logsCount });
        }
        
        // Logs API
        if (path === '/api/logs' && method === 'GET') {
            const { results } = await db.prepare("SELECT * FROM logs ORDER BY created_at DESC LIMIT 100").all();
            return Response.json(results);
        }

        // Channels API
        if (path === '/api/channels' && method === 'GET') {
            const { results } = await db.prepare("SELECT * FROM channels ORDER BY created_at DESC").all();
            return Response.json(results);
        }
        if (path === '/api/channels' && method === 'POST') {
            const b = await request.json();
            const id = generateId();
            await db.prepare("INSERT INTO channels (id, name, type, webhook_url, security_type, security_key) VALUES (?, ?, ?, ?, ?, ?)")
                .bind(id, b.name.trim(), b.type, b.webhook_url.trim(), b.security_type, (b.security_key||'').trim()).run();
            return Response.json({ success: true, id });
        }
        if (path.startsWith('/api/channels/') && method === 'PUT') {
            const id = path.split('/').pop();
            const b = await request.json();
            await db.prepare("UPDATE channels SET name = ?, type = ?, webhook_url = ?, security_type = ?, security_key = ? WHERE id = ?")
                .bind(b.name.trim(), b.type, b.webhook_url.trim(), b.security_type, (b.security_key||'').trim(), id).run();
            return Response.json({ success: true });
        }
        if (path.startsWith('/api/channels/') && method === 'DELETE') {
            const id = path.split('/').pop();
            await db.prepare("DELETE FROM channels WHERE id = ?").bind(id).run();
            return Response.json({ success: true });
        }
        
        // 核心测试接口优化，加入了详细报错捕获和日志记录
        if (path.startsWith('/api/channels/') && path.endsWith('/test') && method === 'POST') {
            const id = path.split('/')[3];
            const channel = await db.prepare("SELECT * FROM channels WHERE id = ?").bind(id).first();
            if(!channel) return Response.json({ success: false, msg: "渠道不存在" });
            
            try {
                // 传入 db 实例以记录测试日志
                const { response, payload, url, actualType, isError, resultText } = await sendNotification(channel, { name: "测试任务", expire_date: "2099-12-31" }, true, db);
                
                return Response.json({ 
                    success: !isError, 
                    result: resultText,
                    debug: { url, payload, actualType } // 回传发送的具体数据供调试
                });
            } catch (err) {
                // 如果发生内部崩溃，补记一条失败日志
                try {
                    await db.prepare("INSERT INTO logs (id, task_name, channel_name, status, error_msg) VALUES (?, ?, ?, ?, ?)")
                        .bind(generateId(), "测试任务", channel.name, 'failed', err.message).run();
                } catch(e){}
                return Response.json({ success: false, msg: "内部错误: " + err.message });
            }
        }

        // Tasks API
        if (path === '/api/tasks' && method === 'GET') {
            const { results } = await db.prepare("SELECT * FROM tasks ORDER BY expire_date ASC").all();
            return Response.json(results);
        }
        if (path === '/api/tasks' && method === 'POST') {
            const b = await request.json();
            const id = generateId();
            await db.prepare("INSERT INTO tasks (id, name, expire_date, remind_days, channel_id, remark, status) VALUES (?, ?, ?, ?, ?, ?, ?)")
                .bind(id, b.name, b.expire_date, JSON.stringify(b.remind_days), b.channel_id, b.remark || '', b.status || 'active').run();
            return Response.json({ success: true, id });
        }
        if (path.startsWith('/api/tasks/') && method === 'PUT' && !path.endsWith('/renew')) {
            const id = path.split('/').pop();
            const b = await request.json();
            await db.prepare("UPDATE tasks SET name = ?, expire_date = ?, remind_days = ?, channel_id = ?, remark = ? WHERE id = ?")
                .bind(b.name, b.expire_date, JSON.stringify(b.remind_days), b.channel_id, b.remark || '', id).run();
            return Response.json({ success: true });
        }
        if (path.startsWith('/api/tasks/') && method === 'DELETE') {
            const id = path.split('/').pop();
            await db.prepare("DELETE FROM tasks WHERE id = ?").bind(id).run();
            return Response.json({ success: true });
        }
        if (path.startsWith('/api/tasks/') && path.endsWith('/renew') && method === 'POST') {
            const id = path.split('/')[3];
            const body = await request.json().catch(() => ({}));
            const monthsToAdd = parseInt(body.months) || 12; // 默认增加12个月

            const task = await db.prepare("SELECT * FROM tasks WHERE id = ?").bind(id).first();
            if (!task) return Response.json({ success: false, msg: "任务不存在" });

            // 解析原日期，并增加指定月份
            const [y, m, d] = task.expire_date.split('-').map(Number);
            const dateObj = new Date(y, m - 1, d);
            dateObj.setMonth(dateObj.getMonth() + monthsToAdd);

            // 格式化回 YYYY-MM-DD
            const newY = dateObj.getFullYear();
            const newM = String(dateObj.getMonth() + 1).padStart(2, '0');
            const newD = String(dateObj.getDate()).padStart(2, '0');
            const newDate = `${newY}-${newM}-${newD}`;

            await db.prepare("UPDATE tasks SET expire_date = ? WHERE id = ?").bind(newDate, id).run();
            return Response.json({ success: true, newDate });
        }

    } catch (e) {
        return Response.json({ success: false, error: e.message }, { status: 500 });
    }
    return new Response("Not Found", { status: 404 });
}

// ============================================================================
// 6. 前端 UI 页面代码 (Vue 3 + TailwindCSS)
// ============================================================================
const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NotifyHub - 订阅提醒</title>
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-50 text-gray-800">
    <div id="app" v-cloak>
        
        <!-- 登录页 -->
        <div v-if="!isLoggedIn" class="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
            <div class="bg-white p-8 rounded-2xl shadow-xl w-96 text-center">
                <h1 class="text-3xl font-bold text-gray-800 mb-2"><i class="fas fa-bell text-blue-500"></i> NotifyHub</h1>
                <p class="text-gray-500 mb-8 text-sm">轻量级订阅与到期提醒系统</p>
                <input v-model="loginPwd" type="password" placeholder="请输入 ADMIN_SECRET" @keyup.enter="login"
                    class="w-full px-4 py-3 rounded-lg border focus:outline-none focus:ring-2 focus:ring-blue-500 mb-4 transition">
                <button @click="login" :disabled="loading" 
                    class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 rounded-lg transition shadow-md">
                    {{ loading ? '验证中...' : '登 录' }}
                </button>
            </div>
        </div>

        <!-- 主界面 -->
        <div v-else class="flex h-screen overflow-hidden">
            <!-- 侧边栏 -->
            <div class="w-64 bg-gray-900 text-white flex flex-col">
                <div class="p-6 text-2xl font-bold border-b border-gray-800 flex items-center">
                    <i class="fas fa-bell text-blue-400 mr-3"></i> NotifyHub
                </div>
                <nav class="flex-1 px-4 py-6 space-y-2">
                    <a @click="currentTab='dashboard'" :class="currentTab==='dashboard'?'bg-gray-800 text-blue-400':'text-gray-400 hover:bg-gray-800 hover:text-white'" class="flex items-center px-4 py-3 rounded-lg cursor-pointer transition">
                        <i class="fas fa-chart-pie w-6"></i> <span>总览看板</span>
                    </a>
                    <a @click="currentTab='tasks'" :class="currentTab==='tasks'?'bg-gray-800 text-blue-400':'text-gray-400 hover:bg-gray-800 hover:text-white'" class="flex items-center px-4 py-3 rounded-lg cursor-pointer transition">
                        <i class="fas fa-tasks w-6"></i> <span>提醒任务</span>
                    </a>
                    <a @click="currentTab='channels'" :class="currentTab==='channels'?'bg-gray-800 text-blue-400':'text-gray-400 hover:bg-gray-800 hover:text-white'" class="flex items-center px-4 py-3 rounded-lg cursor-pointer transition">
                        <i class="fas fa-paper-plane w-6"></i> <span>通知渠道</span>
                    </a>
                    <a @click="currentTab='logs'" :class="currentTab==='logs'?'bg-gray-800 text-blue-400':'text-gray-400 hover:bg-gray-800 hover:text-white'" class="flex items-center px-4 py-3 rounded-lg cursor-pointer transition">
                        <i class="fas fa-list-alt w-6"></i> <span>推送日志</span>
                    </a>
                </nav>
            </div>

            <!-- 右侧内容 -->
            <div class="flex-1 flex flex-col bg-gray-50 h-screen overflow-y-auto">
                <div class="p-8 max-w-7xl mx-auto w-full">
                    
                    <!-- Dashboard -->
                    <div v-if="currentTab === 'dashboard'">
                        <h2 class="text-2xl font-bold mb-6">总览看板</h2>
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex items-center justify-between cursor-pointer hover:shadow-md transition" @click="currentTab='tasks'">
                                <div>
                                    <p class="text-gray-500 text-sm font-medium">监控中任务</p>
                                    <p class="text-4xl font-bold text-gray-800 mt-2">{{stats.tasks}}</p>
                                </div>
                                <div class="bg-blue-100 p-4 rounded-full text-blue-600"><i class="fas fa-tasks text-2xl"></i></div>
                            </div>
                            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex items-center justify-between cursor-pointer hover:shadow-md transition" @click="currentTab='channels'">
                                <div>
                                    <p class="text-gray-500 text-sm font-medium">已配置渠道</p>
                                    <p class="text-4xl font-bold text-gray-800 mt-2">{{stats.channels}}</p>
                                </div>
                                <div class="bg-green-100 p-4 rounded-full text-green-600"><i class="fas fa-paper-plane text-2xl"></i></div>
                            </div>
                            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex items-center justify-between cursor-pointer hover:shadow-md transition" @click="currentTab='logs'">
                                <div>
                                    <p class="text-gray-500 text-sm font-medium">累计推送日志</p>
                                    <p class="text-4xl font-bold text-gray-800 mt-2">{{stats.logs || 0}}</p>
                                </div>
                                <div class="bg-purple-100 p-4 rounded-full text-purple-600"><i class="fas fa-list-alt text-2xl"></i></div>
                            </div>
                        </div>
                    </div>

                    <!-- Channels -->
                    <div v-if="currentTab === 'channels'">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-2xl font-bold">通知渠道管理</h2>
                            <button @click="openCreateChannel" class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 shadow-sm"><i class="fas fa-plus mr-2"></i>添加渠道</button>
                        </div>
                        <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                            <table class="w-full text-left border-collapse">
                                <thead>
                                    <tr class="bg-gray-50 border-b">
                                        <th class="p-4 font-semibold text-gray-600">名称</th>
                                        <th class="p-4 font-semibold text-gray-600">平台</th>
                                        <th class="p-4 font-semibold text-gray-600">安全验证</th>
                                        <th class="p-4 font-semibold text-gray-600 text-right">操作</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="ch in channels" :key="ch.id" class="border-b hover:bg-gray-50">
                                        <td class="p-4">{{ch.name}}</td>
                                        <td class="p-4">
                                            <span :class="ch.type==='dingtalk'?'bg-blue-100 text-blue-700':'bg-teal-100 text-teal-700'" class="px-2 py-1 rounded text-xs font-bold uppercase">{{ch.type}}</span>
                                        </td>
                                        <td class="p-4">
                                            <span class="text-sm text-gray-500">{{ch.security_type==='none'?'无':(ch.security_type==='sign'?'签名':'关键词')}}</span>
                                        </td>
                                        <td class="p-4 text-right space-x-2">
                                            <button @click="testChannel(ch.id)" class="text-green-600 hover:text-green-800 text-sm font-medium px-2 py-1 bg-green-50 rounded">测试</button>
                                            <button @click="editChannel(ch)" class="text-blue-600 hover:text-blue-800 text-sm font-medium px-2 py-1 bg-blue-50 rounded">编辑</button>
                                            <button @click="deleteChannel(ch.id)" class="text-red-600 hover:text-red-800 text-sm font-medium px-2 py-1 bg-red-50 rounded">删除</button>
                                        </td>
                                    </tr>
                                    <tr v-if="channels.length===0"><td colspan="4" class="p-8 text-center text-gray-500">暂无配置渠道，请先添加</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Tasks -->
                    <div v-if="currentTab === 'tasks'">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-2xl font-bold">提醒任务管理</h2>
                            <button @click="openCreateTask" class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 shadow-sm"><i class="fas fa-plus mr-2"></i>添加任务</button>
                        </div>
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            <div v-for="t in tasks" :key="t.id" class="bg-white rounded-xl shadow-sm border p-5 relative overflow-hidden transition hover:shadow-md" :class="getTaskBorderClass(t.expire_date)">
                                <div class="flex justify-between items-start mb-3">
                                    <h3 class="font-bold text-lg text-gray-800 truncate" :title="t.name">{{t.name}}</h3>
                                    <span class="text-xs px-2 py-1 rounded bg-gray-100 text-gray-600">{{t.status==='active'?'监控中':'已停用'}}</span>
                                </div>
                                <div class="text-sm text-gray-500 space-y-1 mb-4">
                                    <p><i class="far fa-calendar-alt w-5 text-center"></i> 到期：{{t.expire_date}}</p>
                                    <p><i class="fas fa-history w-5 text-center"></i> 剩余：<span class="font-bold" :class="getDaysColorClass(t.expire_date)">{{calculateDays(t.expire_date)}} 天</span></p>
                                    <p class="truncate" :title="t.remark"><i class="far fa-comment-dots w-5 text-center"></i> {{t.remark || '无备注'}}</p>
                                </div>
                                <div class="flex justify-between border-t pt-4">
                                    <button @click="openRenewModal(t.id)" class="text-blue-600 hover:bg-blue-50 px-3 py-1 rounded text-sm font-medium transition"><i class="fas fa-sync-alt mr-1"></i> 续期</button>
                                    <div>
                                        <button @click="editTask(t)" class="text-gray-500 hover:text-blue-600 hover:bg-gray-100 px-3 py-1 rounded text-sm font-medium transition mr-1"><i class="fas fa-edit"></i></button>
                                        <button @click="deleteTask(t.id)" class="text-red-500 hover:bg-red-50 px-3 py-1 rounded text-sm font-medium transition"><i class="fas fa-trash-alt"></i></button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div v-if="tasks.length===0" class="text-center py-20 text-gray-500 bg-white rounded-xl shadow-sm border">
                            <i class="fas fa-box-open text-4xl mb-3 text-gray-300"></i><br>暂无提醒任务
                        </div>
                    </div>

                    <!-- Logs -->
                    <div v-if="currentTab === 'logs'">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-2xl font-bold">推送日志 <span class="text-sm font-normal text-gray-500 ml-2">(仅展示最近 100 条)</span></h2>
                            <button @click="loadData" class="bg-white border text-gray-600 px-4 py-2 rounded-lg hover:bg-gray-50 shadow-sm"><i class="fas fa-sync-alt mr-2"></i>刷新日志</button>
                        </div>
                        <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                            <table class="w-full text-left border-collapse">
                                <thead>
                                    <tr class="bg-gray-50 border-b">
                                        <th class="p-4 font-semibold text-gray-600 w-48">发送时间</th>
                                        <th class="p-4 font-semibold text-gray-600 w-48">触发任务</th>
                                        <th class="p-4 font-semibold text-gray-600 w-40">接收渠道</th>
                                        <th class="p-4 font-semibold text-gray-600 w-24">状态</th>
                                        <th class="p-4 font-semibold text-gray-600">错误详情</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="log in logs" :key="log.id" class="border-b hover:bg-gray-50">
                                        <td class="p-4 text-sm text-gray-500 whitespace-nowrap">{{formatDate(log.created_at)}}</td>
                                        <td class="p-4 text-sm font-medium">{{log.task_name}}</td>
                                        <td class="p-4 text-sm text-gray-600">{{log.channel_name}}</td>
                                        <td class="p-4">
                                            <span v-if="log.status==='success'" class="bg-green-100 text-green-700 px-2 py-1 rounded text-xs font-bold"><i class="fas fa-check mr-1"></i>成功</span>
                                            <span v-else class="bg-red-100 text-red-700 px-2 py-1 rounded text-xs font-bold"><i class="fas fa-times mr-1"></i>失败</span>
                                        </td>
                                        <td class="p-4 text-sm text-red-500 truncate max-w-xs" :title="log.error_msg">
                                            {{log.error_msg || '-'}}
                                        </td>
                                    </tr>
                                    <tr v-if="logs.length===0"><td colspan="5" class="p-8 text-center text-gray-500">暂无任何推送日志</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                </div>
            </div>
        </div>

        <!-- 渠道添加/编辑 Modal -->
        <div v-if="showChannelModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div class="bg-white rounded-xl shadow-2xl w-[500px] overflow-hidden">
                <div class="px-6 py-4 border-b flex justify-between items-center bg-gray-50">
                    <h3 class="font-bold text-lg">{{ editingChannelId ? '编辑通知渠道' : '添加通知渠道' }}</h3>
                    <button @click="showChannelModal=false" class="text-gray-400 hover:text-gray-700"><i class="fas fa-times"></i></button>
                </div>
                <div class="p-6 space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">渠道名称</label>
                        <input v-model="formCh.name" class="w-full border rounded p-2 text-sm focus:ring-2 focus:ring-blue-500" placeholder="如：域名续费群">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">平台类型</label>
                        <select v-model="formCh.type" class="w-full border rounded p-2 text-sm focus:ring-2 focus:ring-blue-500">
                            <option value="dingtalk">钉钉群机器人</option>
                            <option value="feishu">飞书群机器人</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Webhook URL</label>
                        <input v-model="formCh.webhook_url" class="w-full border rounded p-2 text-sm focus:ring-2 focus:ring-blue-500" placeholder="https://oapi.dingtalk.com/robot/send?access_token=...">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">安全设置</label>
                        <select v-model="formCh.security_type" class="w-full border rounded p-2 text-sm focus:ring-2 focus:ring-blue-500">
                            <option value="none">无验证</option>
                            <option value="keyword">自定义关键词</option>
                            <option value="sign">加签校验 (Secret)</option>
                        </select>
                    </div>
                    <div v-if="formCh.security_type !== 'none'">
                        <label class="block text-sm font-medium text-gray-700 mb-1">{{formCh.security_type==='sign'?'密钥 Secret':'关键词'}}</label>
                        <input v-model="formCh.security_key" class="w-full border rounded p-2 text-sm focus:ring-2 focus:ring-blue-500" :placeholder="formCh.security_type==='sign'?'SECxxxx':'如：【提醒】'">
                    </div>
                </div>
                <div class="px-6 py-4 border-t bg-gray-50 flex justify-end space-x-3">
                    <button @click="showChannelModal=false" class="px-4 py-2 border rounded text-gray-600 hover:bg-gray-100">取消</button>
                    <button @click="saveChannel" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">保存</button>
                </div>
            </div>
        </div>

        <!-- 任务添加/编辑 Modal -->
        <div v-if="showTaskModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div class="bg-white rounded-xl shadow-2xl w-[500px] overflow-hidden">
                <div class="px-6 py-4 border-b flex justify-between items-center bg-gray-50">
                    <h3 class="font-bold text-lg">{{ editingTaskId ? '编辑提醒任务' : '添加提醒任务' }}</h3>
                    <button @click="showTaskModal=false" class="text-gray-400 hover:text-gray-700"><i class="fas fa-times"></i></button>
                </div>
                <div class="p-6 space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">任务名称</label>
                        <input v-model="formTask.name" class="w-full border rounded p-2 text-sm" placeholder="如：阿里云 example.com">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">到期日期</label>
                        <input v-model="formTask.expire_date" type="date" class="w-full border rounded p-2 text-sm">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">通知渠道</label>
                        <select v-model="formTask.channel_id" class="w-full border rounded p-2 text-sm">
                            <option v-for="c in channels" :value="c.id" :key="c.id">{{c.name}} ({{c.type}})</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">提前提醒策略 (天)</label>
                        <div class="flex space-x-3 text-sm">
                            <label class="flex items-center"><input type="checkbox" v-model="formTask.remind_days" :value="30" class="mr-1">30天</label>
                            <label class="flex items-center"><input type="checkbox" v-model="formTask.remind_days" :value="7" class="mr-1">7天</label>
                            <label class="flex items-center"><input type="checkbox" v-model="formTask.remind_days" :value="3" class="mr-1">3天</label>
                            <label class="flex items-center"><input type="checkbox" v-model="formTask.remind_days" :value="1" class="mr-1">1天</label>
                            <label class="flex items-center"><input type="checkbox" v-model="formTask.remind_days" :value="0" class="mr-1">当天</label>
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">备注说明 (选填)</label>
                        <textarea v-model="formTask.remark" class="w-full border rounded p-2 text-sm" rows="2" placeholder="可填写账号信息、续费链接等，将附带在通知中"></textarea>
                    </div>
                </div>
                <div class="px-6 py-4 border-t bg-gray-50 flex justify-end space-x-3">
                    <button @click="showTaskModal=false" class="px-4 py-2 border rounded text-gray-600 hover:bg-gray-100">取消</button>
                    <button @click="saveTask" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">保存</button>
                </div>
            </div>
        </div>

        <!-- 续期 Modal -->
        <div v-if="showRenewModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div class="bg-white rounded-xl shadow-2xl w-[400px] overflow-hidden">
                <div class="px-6 py-4 border-b flex justify-between items-center bg-gray-50">
                    <h3 class="font-bold text-lg">选择续期时长</h3>
                    <button @click="showRenewModal=false" class="text-gray-400 hover:text-gray-700"><i class="fas fa-times"></i></button>
                </div>
                <div class="p-6 space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">延长到期时间</label>
                        <select v-model="renewDuration" class="w-full border rounded p-2 text-sm focus:ring-2 focus:ring-blue-500">
                            <option :value="1">1个月</option>
                            <option :value="2">2个月</option>
                            <option :value="3">3个月</option>
                            <option :value="6">半年</option>
                            <option :value="12">1年</option>
                            <option :value="24">2年</option>
                            <option :value="36">3年</option>
                        </select>
                    </div>
                </div>
                <div class="px-6 py-4 border-t bg-gray-50 flex justify-end space-x-3">
                    <button @click="showRenewModal=false" class="px-4 py-2 border rounded text-gray-600 hover:bg-gray-100">取消</button>
                    <button @click="confirmRenew" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">确认续期</button>
                </div>
            </div>
        </div>

    </div>

    <script>
        const { createApp, ref, onMounted, watch } = Vue;

        createApp({
            setup() {
                const isLoggedIn = ref(false);
                const loading = ref(false);
                const loginPwd = ref('');
                const currentTab = ref('dashboard');
                
                const stats = ref({ tasks: 0, channels: 0, logs: 0 });
                const channels = ref([]);
                const tasks = ref([]);
                const logs = ref([]);
                const showChannelModal = ref(false);
                const showTaskModal = ref(false);
                const showRenewModal = ref(false);
                
                const editingChannelId = ref(null);
                const editingTaskId = ref(null); // 用于判断是否为编辑任务
                const renewingTaskId = ref(null); // 正在续期的任务ID
                const renewDuration = ref(12); // 默认选中 1 年

                const formCh = ref({ name: '', type: 'dingtalk', webhook_url: '', security_type: 'none', security_key: '' });
                const formTask = ref({ name: '', expire_date: '', channel_id: '', remind_days: [30, 7, 3, 1, 0], remark: '' });

                const request = async (url, options = {}) => {
                    const res = await fetch(url, options);
                    if (res.status === 401) { isLoggedIn.value = false; throw new Error("未登录"); }
                    
                    let data;
                    const text = await res.text();
                    try { data = JSON.parse(text); } catch(e) { data = { error: text }; }
                    
                    if (!res.ok) {
                        if (data.error) alert("系统提示: " + data.error);
                        throw new Error(data.error || "请求异常");
                    }
                    return data;
                };

                const login = async () => {
                    if(!loginPwd.value) return;
                    loading.value = true;
                    try {
                        const res = await fetch('/api/login', {
                            method: 'POST', body: JSON.stringify({ password: loginPwd.value })
                        });
                        if (res.ok) {
                            isLoggedIn.value = true;
                            loadData();
                        } else {
                            alert("密码错误");
                        }
                    } finally {
                        loading.value = false;
                    }
                };

                const loadData = async () => {
                    try {
                        stats.value = await request('/api/stats');
                        channels.value = await request('/api/channels');
                        tasks.value = await request('/api/tasks');
                        if (currentTab.value === 'logs') {
                            logs.value = await request('/api/logs');
                        }
                    } catch(e) {}
                };

                // 监听当前标签页的变化，当切换到“推送日志”时自动拉取数据
                watch(currentTab, async (newTab) => {
                    if (newTab === 'logs') {
                        try {
                            logs.value = await request('/api/logs');
                        } catch (e) {}
                    }
                });

                // 【核心修复】改为显式对每个属性进行赋值，绝对避免 ref 的根代理对象被覆盖
                const openCreateChannel = () => {
                    editingChannelId.value = null;
                    formCh.value.name = '';
                    formCh.value.type = 'dingtalk';
                    formCh.value.webhook_url = '';
                    formCh.value.security_type = 'none';
                    formCh.value.security_key = '';
                    showChannelModal.value = true;
                };

                const editChannel = (ch) => {
                    editingChannelId.value = ch.id;
                    formCh.value.name = ch.name;
                    formCh.value.type = ch.type;
                    formCh.value.webhook_url = ch.webhook_url;
                    formCh.value.security_type = ch.security_type;
                    formCh.value.security_key = ch.security_key || '';
                    showChannelModal.value = true;
                };

                const saveChannel = async () => {
                    if(!formCh.value.name || !formCh.value.webhook_url) return alert('必填项为空');
                    if(formCh.value.security_key) formCh.value.security_key = formCh.value.security_key.trim();
                    formCh.value.webhook_url = formCh.value.webhook_url.trim();

                    // 智能纠错，防止用户选错下拉框
                    if (formCh.value.webhook_url.includes('feishu.cn')) {
                        formCh.value.type = 'feishu';
                    } else if (formCh.value.webhook_url.includes('dingtalk.com')) {
                        formCh.value.type = 'dingtalk';
                    }

                    if (editingChannelId.value) {
                        await request('/api/channels/' + editingChannelId.value, { method: 'PUT', body: JSON.stringify(formCh.value) });
                    } else {
                        await request('/api/channels', { method: 'POST', body: JSON.stringify(formCh.value) });
                    }
                    showChannelModal.value = false;
                    loadData();
                };

                const deleteChannel = async (id) => {
                    if(!confirm('确定删除该渠道？相关的任务可能会失效。')) return;
                    await request('/api/channels/'+id, { method: 'DELETE' });
                    loadData();
                };

                const testChannel = async (id) => {
                    alert('正在发送测试消息，请稍候...');
                    try {
                        const res = await request('/api/channels/'+id+'/test', { method: 'POST' });
                        if(res.success) {
                            alert('发送成功！平台返回结果: \\n' + res.result);
                        } else {
                            console.error("====== 详细调试信息 ======");
                            console.error("目标URL:", res.debug?.url);
                            console.error("判定发送类型:", res.debug?.actualType); 
                            console.error("发出Payload:", JSON.stringify(res.debug?.payload, null, 2));
                            console.error("平台返回报错:", res.result);
                            
                            alert('推送被拒绝！\\n平台报错: ' + (res.msg || res.result) + '\\n\\n已自动写入错误日志。');
                        }
                        if (currentTab.value === 'logs') loadData(); // 如果当前就在日志页，测试完刷新一下
                    } catch(e) {
                        alert('测试出现网络异常: ' + e.message);
                    }
                };

                const openCreateTask = () => {
                    editingTaskId.value = null;
                    formTask.value.name = '';
                    formTask.value.expire_date = '';
                    formTask.value.channel_id = channels.value.length > 0 ? channels.value[0].id : '';
                    formTask.value.remind_days = [30, 7, 3, 1, 0];
                    formTask.value.remark = '';
                    showTaskModal.value = true;
                };

                const editTask = (t) => {
                    editingTaskId.value = t.id;
                    // 解析存放在数据库里的提醒天数 JSON
                    let parsedDays = [30, 7, 3, 1, 0];
                    try { parsedDays = JSON.parse(t.remind_days); } catch(e) {}
                    
                    formTask.value.name = t.name;
                    formTask.value.expire_date = t.expire_date;
                    formTask.value.channel_id = t.channel_id;
                    formTask.value.remind_days = parsedDays;
                    formTask.value.remark = t.remark || '';
                    showTaskModal.value = true;
                };

                const saveTask = async () => {
                    if(!formTask.value.name || !formTask.value.expire_date || !formTask.value.channel_id) return alert('必填项为空');
                    
                    if (editingTaskId.value) {
                        await request('/api/tasks/' + editingTaskId.value, { method: 'PUT', body: JSON.stringify(formTask.value) });
                    } else {
                        await request('/api/tasks', { method: 'POST', body: JSON.stringify(formTask.value) });
                    }
                    showTaskModal.value = false;
                    loadData();
                };

                const deleteTask = async (id) => {
                    if(!confirm('确定删除该任务？')) return;
                    await request('/api/tasks/'+id, { method: 'DELETE' });
                    loadData();
                };

                const openRenewModal = (id) => {
                    renewingTaskId.value = id;
                    renewDuration.value = 12; // 打开时默认重置为1年
                    showRenewModal.value = true;
                };

                const confirmRenew = async () => {
                    if(!renewingTaskId.value) return;
                    await request('/api/tasks/'+renewingTaskId.value+'/renew', { 
                        method: 'POST',
                        body: JSON.stringify({ months: renewDuration.value })
                    });
                    showRenewModal.value = false;
                    loadData();
                };

                // UI 辅助计算: 强制锁定为北京时区计算，抵消用户电脑的本地时区偏差
                const calculateDays = (dateStr) => {
                    const now = new Date();
                    const beijingMs = now.getTime() + (now.getTimezoneOffset() * 60000) + 8 * 3600000;
                    const bTime = new Date(beijingMs);
                    const currentUTC = Date.UTC(bTime.getFullYear(), bTime.getMonth(), bTime.getDate());
                    
                    const [y, m, d] = dateStr.split('-').map(Number);
                    const targetUTC = Date.UTC(y, m - 1, d);
                    
                    return Math.round((targetUTC - currentUTC) / (1000 * 3600 * 24));
                };

                const getDaysColorClass = (dateStr) => {
                    const d = calculateDays(dateStr);
                    if(d < 0) return 'text-red-600';
                    if(d <= 7) return 'text-orange-500';
                    return 'text-green-600';
                };

                const getTaskBorderClass = (dateStr) => {
                    const d = calculateDays(dateStr);
                    if(d < 0) return 'border-red-200 bg-red-50/30';
                    if(d <= 7) return 'border-orange-200 bg-orange-50/30';
                    return 'border-gray-200';
                };

                // 格式化数据库中的 UTC 时间为标准的北京时间显示
                const formatDate = (dateStr) => {
                    if(!dateStr) return '';
                    try {
                        const isoStr = dateStr.replace(' ', 'T') + 'Z';
                        const d = new Date(isoStr);
                        return d.toLocaleString('zh-CN', { hour12: false, timeZone: 'Asia/Shanghai' });
                    } catch (e) {
                        return dateStr;
                    }
                };

                onMounted(() => {
                    request('/api/stats').then(res => {
                        isLoggedIn.value = true;
                        stats.value = res;
                        loadData();
                    }).catch(e => {
                        isLoggedIn.value = false;
                    });
                });

                return {
                    isLoggedIn, loading, loginPwd, login, currentTab,
                    stats, channels, tasks, logs,
                    showChannelModal, showTaskModal, showRenewModal, formCh, formTask,
                    editingChannelId, editingTaskId, renewDuration,
                    openCreateChannel, editChannel, saveChannel, deleteChannel, testChannel,
                    openCreateTask, editTask, saveTask, deleteTask, openRenewModal, confirmRenew,
                    calculateDays, getDaysColorClass, getTaskBorderClass, formatDate, loadData
                };
            }
        }).mount('#app');
    </script>
</body>
</html>
`;
// EOF - 如果你能看到这行注释，说明你已经完整复制了代码！