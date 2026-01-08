# -*- coding: utf-8 -*-
"""
WAF (Web Application Firewall) - Web 应用防火墙
功能：拦截常见的 Web 攻击（SQL注入、XSS、命令注入等）
"""


import requests
from flask import Flask, request, Response
import json
import re
import logging
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime
import os
import html  # 用于 HTML 转义，防止日志中的 XSS 代码执行

# ==================== 配置区域 ====================
BACKEND = "http://dvwa:2222"  # 后端 DVWA 服务器地址
LISTEN_PORT = 9998  # WAF 监听端口
LOG_FILE = "waf_log.txt"  # 日志文件路径
# ================================================

app = Flask(__name__)
req_session = requests.Session()
app.secret_key = 'your_secret_key'

# 配置控制台日志记录格式
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(message)s',
    handlers=[logging.StreamHandler()]
)


# ==================== 日志功能 ====================

def init_log_file():
    """
    初始化日志文件
    如果文件不存在，创建新文件并写入头部信息
    如果文件存在，不做任何操作（保留历史日志）
    """
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("                    WAF 攻击拦截日志\n")
            f.write("=" * 80 + "\n")
            f.write(f"日志创建时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")


def reset_log_file():
    """
    重置日志文件（清空并重新初始化）
    删除旧文件，创建新的空日志文件
    """
    # 如果文件存在，先删除
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    # 创建新的日志文件并写入头部
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("                    WAF 攻击拦截日志\n")
        f.write("=" * 80 + "\n")
        f.write(f"日志创建时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")


def sanitize_for_log(text):
    """
    清理日志内容，防止恶意代码在查看日志时执行

    : param text: 原始文本
    :return: 清理后的安全文本
    """
    if text is None:
        return "None"

    # 转换为字符串
    text = str(text)

    # 移除或替换危险字符，但保留可读性
    # 替换 < 和 > 为全角字符，防止 HTML 解析
    text = text.replace('<', '＜').replace('>', '＞')

    # 替换可能导致问题的字符
    text = text.replace('\x00', '[NULL]')  # 空字节
    text = text.replace('\r', '[CR]')  # 回车
    text = text.replace('\n', '[LF]')  # 换行

    return text


def sanitize_for_html_display(text):
    """
    将文本转义为安全的 HTML 显示格式
    用于在网页上显示日志时防止 XSS 攻击

    :param text: 原始文本
    :return: HTML 转义后的安全文本
    """
    if text is None:
        return "None"

    # 使用 html.escape 进行 HTML 实体转义
    # 这会将 < > & " ' 等字符转换为 HTML 实体
    return html.escape(str(text))


def write_log(log_type, message, details=None):
    """
    写入日志到文件

    :param log_type: 日志类型 (ATTACK, INFO, WARNING, ERROR)
    :param message: 日志消息
    :param details: 详细信息字典（可选）
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        # 写入时间戳和日志类型
        f.write(f"[{timestamp}] [{log_type}] {sanitize_for_log(message)}\n")

        # 如果有详细信息，逐行写入
        if details:
            for key, value in details.items():
                # 对所有值进行清理，防止恶意内容
                safe_value = sanitize_for_log(value)
                f.write(f"    {key}: {safe_value}\n")

        # 写入分隔线
        f.write("-" * 80 + "\n")

    # 同时打印到控制台（控制台不需要转义）
    print(f"[{timestamp}] [{log_type}] {message}")


# 初始化日志文件
init_log_file()


# ==================== 规则加载 ====================

def load_rules():
    """
    从 rules.json 文件加载 WAF 检测规则

    :return: 规则字典
    """
    with open("rules.json", "r", encoding="utf-8") as f:
        rules = json.load(f)
        print(f"Loaded rules: {json.dumps(rules, indent=2)}")
        # 记录规则加载日志
        write_log("INFO", "WAF 规则加载成功", {
            "规则数量": sum(len(v) for v in rules["fatal"].values())
        })
        return rules


# 加载规则
rules = load_rules()


# ==================== 攻击检测 ====================

def detect_attack(data):
    """
    检测请求数据中是否包含攻击特征

    :param data: 待检测的数据字符串
    :return: 元组 (是否攻击, 攻击类型, 匹配的规则)
    """
    print(f"Data being checked: {data}")

    # 遍历所有攻击类型和对应的规则
    for attack_type, patterns in rules["fatal"].items():
        for pattern in patterns:
            try:
                # 使用正则表达式匹配，忽略大小写
                if re.search(pattern, data, re.IGNORECASE):
                    print(f"[! ] Attack detected!  Type: {attack_type}, Pattern: {pattern}")
                    return True, attack_type, pattern
            except re.error as e:
                # 正则表达式错误，记录并跳过
                print(f"Regex error with pattern '{pattern}': {e}")
                continue

    # 未检测到攻击
    return False, None, None


# ==================== 白名单配置 ====================

# ==================== 白名单配置 ====================

# 白名单路径 - 这些路径不进行攻击检测（如登录页面）
# 注意：路径中不要有多余空格
WHITELIST_PATHS = [
    "/login.php",      # 登录页面
    "/logout.php",     # 注销页面
]

# 白名单参数 - 这些参数名不进行检测（如用户名、密码字段）
WHITELIST_PARAMS = [
    "username",       # 登录用户名
    "password",       # 登录密码
    "Login",          # 登录按钮
    "user_token",     # CSRF 令牌
    "PHPSESSID",      # 会话 ID
    "security",       # 安全级别切换
    "seclev_submit",  # 提交安全级别调整
    "Change",         # 提交表单按钮
    "password_new",   # 更改密码 - 新密码
    "password_conf",  # 更改密码 - 确认密码
    "password_current",  # 更改密码 - 当前密码
]


# ==================== 攻击日志记录 ====================

def log_attack(req, attack_type, matched_pattern, payload):
    """
    记录攻击日志到文件

    :param req: Flask 请求对象
    : param attack_type: 攻击类型
    :param matched_pattern: 匹配的规则
    :param payload:  攻击载荷
    """
    details = {
        "攻击类型": attack_type,
        "匹配规则": matched_pattern,
        "客户端IP": req.remote_addr,
        "请求方法": req.method,
        "请求路径": req.path,
        "完整URL": req.url,
        "攻击载荷": payload,
        "User-Agent": req.headers.get('User-Agent', 'Unknown'),
        "Referer": req.headers.get('Referer', 'None'),
    }

    write_log("ATTACK", f"拦截到 {attack_type} 攻击", details)


# ==================== 主代理路由 ====================

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(path):
    """
    主代理函数 - 处理所有进入的 HTTP 请求
    1. 检查是在白名单中
    2. 收集并检测请求参数
    3. 如果检测到攻，返回拦截页面
    4. 如果正常，转发请求到后端服务器

    :param path: 请求路径
    :return: Response 对象
    """
    try:
        # 获取当前请求路径
        current_path = "/" + path

        # 检查是否在白名单路径中
        is_whitelisted = any(wp in current_path for wp in WHITELIST_PATHS)

        if is_whitelisted:
            # 白名单路径，跳过检测
            print(f"[白名单] 跳过检测: {current_path}")
        else:
            # 非白名单路径，进行攻击检测
            data_to_check = []  # 待检测的数据列表
            raw_payloads = []  # 原始载荷（用于日志记录）

            # 收集 GET 参数
            for key, value in request.args.items():
                # 排除白名单参数
                if key.lower() not in [p.lower() for p in WHITELIST_PARAMS]:
                    decoded_value = urllib.parse.unquote(value)
                    data_to_check.append(decoded_value)
                    raw_payloads.append(f"{key}={decoded_value}")
                    print(f"GET param [{key}]: {decoded_value}")

            # 收集 POST 参数
            for key, value in request.form.items():
                # 排除白名单参数
                if key.lower() not in [p.lower() for p in WHITELIST_PARAMS]:
                    decoded_value = urllib.parse.unquote(value)
                    data_to_check.append(decoded_value)
                    raw_payloads.append(f"{key}={decoded_value}")
                    print(f"POST param [{key}]: {decoded_value}")

            # 检查 URL 路径本身
            data_to_check.append(urllib.parse.unquote(path))

            # 合并所有数据，转小写进行检测
            combined_data = " ".join(data_to_check).lower().strip()
            print(f"Combined data to check: {combined_data}")

            # 进行攻击检测
            if combined_data:
                is_attack, attack_type, matched_pattern = detect_attack(combined_data)

                if is_attack:
                    # 检测到攻击，记录日志并返回拦截页面
                    print(f"[!] Attack blocked!")

                    # 记录攻击日志
                    payload_str = " | ".join(raw_payloads) if raw_payloads else combined_data
                    log_attack(request, attack_type, matched_pattern, payload_str)

                    # 返回拦截页面（对攻击类型进行 HTML 转义）
                    safe_attack_type = sanitize_for_html_display(attack_type)
                    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    return Response(
                        f'''
                        <! DOCTYPE html>
                        <html>
                        <head>
                            <title>WAF - 请求被拦截</title>
                            <meta charset="utf-8">
                            <style>
                                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; background:  #f5f5f5; }}
                                .container {{ background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 500px; margin: 0 auto; }}
                                h1 {{ color: #e74c3c; }}
                                p {{ color: #666; }}
                                .icon {{ font-size: 60px; }}
                                .attack-type {{ background: #fee; padding: 10px; border-radius: 5px; margin: 15px 0; color: #c0392b; }}
                                .time {{ font-size: 12px; color: #999; }}
                                a {{ color: #3498db; text-decoration: none; }}
                                a:hover {{ text-decoration: underline; }}
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                <div class="icon">🛡️</div>
                                <h1>请求被拦截</h1>
                                <div class="attack-type">
                                    <strong>检测到攻击类型: </strong> {safe_attack_type}
                                </div>
                                <p>WAF 检测到恶意请求，已阻止访问。</p>
                                <p>您的 IP 地址和请求已被记录。</p>
                                <p class="time">拦截时间: {current_time}</p>
                                <br>
                                <a href="javascript:history.back()">← 返回上一页</a>
                            </div>
                        </body>
                        </html>
                        ''',
                        status=403,
                        content_type="text/html; charset=utf-8"
                    )

        # ========== 正常请求转发 ==========
        print(f"Request allowed: {request.method} /{path}")
        url = f"{BACKEND}/{path}"

        # 复制请求头（排除 host 头）
        headers = {k: v for k, v in request.headers if k.lower() != "host"}

        # 转发请求到后端服务器
        resp = req_session.request(
            method=request.method,
            url=url,
            headers=headers,
            params=request.args,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=True
        )

        # 过滤响应头（排除某些头以避免问题）
        excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
        out_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]

        # 返回后端响应
        return Response(resp.content, resp.status_code, out_headers)

    except Exception as e:
        # 发生错误，记录日志并返回错误页面
        error_msg = str(e)
        print(f"Error: {error_msg}")
        import traceback
        traceback.print_exc()

        # 记录错误日志
        write_log("ERROR", "服务器内部错误", {
            "错误信息": error_msg,
            "请求路径": request.path,
        })

        return Response(f"Internal Server Error: {error_msg}", status=500)


# ==================== 频率限制 ====================

request_times = defaultdict(list)  # 存储每个 IP 的请求时间列表
TIME_WINDOW = 60  # 时间窗口（秒）
MAX_REQUESTS = 30  # 时间窗口内最大请求数


def check_rate_limit(ip):
    """
    检查请求频率是否超过限制

    :param ip: 客户端 IP 地址
    :return: True 如果超过限制，False 如果未超过
    """
    current_time = time.time()

    # 清理过期的请求记录（超过时间窗口的记录）
    request_times[ip] = [t for t in request_times[ip] if current_time - t < TIME_WINDOW]

    # 添加当前请求时间
    request_times[ip].append(current_time)

    # 检查是否超过限制
    if len(request_times[ip]) > MAX_REQUESTS:
        write_log("WARNING", "触发请求频率限制", {
            "IP地址": ip,
            "请求次数": len(request_times[ip]),
            "时间窗口": f"{TIME_WINDOW}秒",
        })
        return True

    return False


# ==================== WAF 管理页面 ====================

@app.route("/waf/logs", methods=["GET"])
def view_logs():
    """
    查看 WAF 日志页面
    仅限本地访问（127.0.0.1）
    日志内容会进行 HTML 转义，防止 XSS 攻击
    """
    # 安全检查：仅允许本地访问
    if request.remote_addr not in ["127.0.0.1", "localhost"]:
        return Response("Access Denied", status=403)

    try:
        # 读取日志文件
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            raw_logs = f.read()

        # 关键：对日志内容进行 HTML 转义，防止 XSS 攻击
        # 这样即使日志中包含 <script> 等代码也不会执行
        safe_logs = sanitize_for_html_display(raw_logs)

        return Response(
            f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>WAF 日志查看</title>
                <meta charset="utf-8">
                <meta http-equiv="refresh" content="30">  <!-- 每30秒自动刷新 -->
                <style>
                    body {{ font-family: 'Consolas', 'Monaco', monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; margin: 0; }}
                    h1 {{ color: #569cd6; margin-bottom: 10px; }}
                    . toolbar {{ background: #2d2d2d; padding: 10px 15px; border-radius: 5px; margin-bottom: 15px; }}
                    .toolbar a {{ color: #4ec9b0; text-decoration:  none; margin-right: 20px; padding: 5px 10px; border-radius: 3px; }}
                    .toolbar a:hover {{ background: #3d3d3d; }}
                    .log-container {{ background: #2d2d2d; padding: 20px; border-radius: 5px; overflow-x: auto; }}
                    pre {{ margin: 0; white-space: pre-wrap; word-wrap: break-word; line-height: 1.5; }}
                    .info {{ color: #888; font-size: 12px; margin-bottom: 10px; }}
                    /* 语法高亮 */
                    .log-attack {{ color: #f44336; }}
                    .log-info {{ color: #4caf50; }}
                    .log-warning {{ color: #ff9800; }}
                    .log-error {{ color: #e91e63; }}
                </style>
            </head>
            <body>
                <h1>🛡️ WAF 攻击拦截日志</h1>
                <div class="toolbar">
                    <a href="/waf/logs">🔄 刷新日志</a>
                    <a href="/waf/stats">📊 统计信息</a>
                    <a href="/waf/clear" onclick="return confirm('确定要清空所有日志吗？');">🗑️ 清空日志</a>
                </div>
                <p class="info">📁 日志文件:  {LOG_FILE} | ⏱️ 页面每30秒自动刷新</p>
                <div class="log-container">
                    <pre>{safe_logs}</pre>
                </div>
            </body>
            </html>
            ''',
            content_type="text/html; charset=utf-8"
        )
    except FileNotFoundError:
        return Response("日志文件不存在", status=404)


@app.route("/waf/clear", methods=["GET"])
def clear_logs():
    """
    清空 WAF 日志
    仅限本地访问（127.0.0.1）
    会删除旧日志文件并创建新的空日志文件
    """
    # 安全检查：仅允许本地访问
    if request.remote_addr not in ["127.0.0.1", "localhost"]:
        return Response("Access Denied", status=403)

    # 重置日志文件（删除并重新创建）
    reset_log_file()

    # 记录清空操作
    write_log("INFO", "日志已被手动清空", {
        "操作者IP": request.remote_addr,
        "操作时间": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

    return Response(
        '''
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta http-equiv="refresh" content="2;url=/waf/logs">
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
                .container { background: white; padding: 40px; border-radius: 10px; max-width: 400px; margin: 0 auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color:  #27ae60; }
                p { color: #666; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>✅ 日志已清空</h1>
                <p>2秒后自动跳转到日志页面...</p>
            </div>
        </body>
        </html>
        ''',
        content_type="text/html; charset=utf-8"
    )


@app.route("/waf/stats", methods=["GET"])
def waf_stats():
    """
    显示 WAF 统计信息页面
    统计各类攻击的拦截次数
    仅限本地访问（127.0.0.1）
    """
    # 安全检查：仅允许本地访问
    if request.remote_addr not in ["127.0.0.1", "localhost"]:
        return Response("Access Denied", status=403)

    # 统计变量
    attack_count = 0
    attack_types = defaultdict(int)
    recent_attacks = []  # 最近的攻击记录

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            current_attack = {}

            for line in lines:
                # 统计攻击次数
                if "[ATTACK]" in line:
                    attack_count += 1
                    # 提取时间
                    if line.startswith("["):
                        time_str = line.split("]")[0][1:]
                        current_attack = {"time": time_str}

                # 统计攻击类型
                if "攻击类型:" in line:
                    attack_type = line.split("攻击类型:")[1].strip()
                    attack_types[attack_type] += 1
                    current_attack["type"] = attack_type

                # 提取 IP
                if "客户端IP:" in line:
                    ip = line.split("客户端IP:")[1].strip()
                    current_attack["ip"] = ip

                # 分隔线表示一条记录结束
                if line.startswith("-" * 10) and current_attack.get("type"):
                    recent_attacks.append(current_attack.copy())
                    current_attack = {}

    except FileNotFoundError:
        pass

    # 生成攻击类型统计 HTML（进行转义）
    if attack_types:
        stats_items = []
        for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
            safe_type = sanitize_for_html_display(attack_type)
            stats_items.append(
                f'<div class="stat-item"><span class="type">{safe_type}</span><span class="count">{count}次</span></div>')
        stats_html = "\n".join(stats_items)
    else:
        stats_html = '<p class="no-data">暂无攻击记录</p>'

    # 生成最近攻击记录 HTML（最多显示10条，进行转义）
    recent_html = ""
    for attack in recent_attacks[-10:][::-1]:  # 最近10条，倒序显示
        safe_type = sanitize_for_html_display(attack.get('type', 'Unknown'))
        safe_ip = sanitize_for_html_display(attack.get('ip', 'Unknown'))
        safe_time = sanitize_for_html_display(attack.get('time', 'Unknown'))
        recent_html += f'<tr><td>{safe_time}</td><td>{safe_type}</td><td>{safe_ip}</td></tr>'

    return Response(
        f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>WAF 统计信息</title>
            <meta charset="utf-8">
            <meta http-equiv="refresh" content="30">
            <style>
                body {{ font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; margin: 0; }}
                .container {{ max-width: 800px; margin: 0 auto; }}
                h1 {{ color: #333; text-align: center; }}
                .card {{ background: white; padding: 25px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .total {{ background: linear-gradient(135deg, #e74c3c, #c0392b); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 20px; }}
                .total h2 {{ margin: 0; font-size: 48px; }}
                .total p {{ margin: 10px 0 0 0; opacity: 0.9; }}
                .stat-item {{ display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }}
                .stat-item:last-child {{ border-bottom: none; }}
                .stat-item .type {{ color: #333; }}
                .stat-item .count {{ color: #e74c3c; font-weight: bold; }}
                .no-data {{ color: #999; text-align: center; }}
                table {{ width: 100%; border-collapse:  collapse; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #eee; }}
                th {{ background: #f9f9f9; color: #666; }}
                .toolbar {{ text-align: center; margin-bottom: 20px; }}
                .toolbar a {{ color: #3498db; text-decoration: none; margin: 0 15px; }}
                .toolbar a:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ WAF 统计信息</h1>

                <div class="toolbar">
                    <a href="/waf/logs">📋 查看日志</a>
                    <a href="/waf/stats">🔄 刷新统计</a>
                    <a href="/waf/clear" onclick="return confirm('确定要清空所有日志吗？');">🗑️ 清空日志</a>
                </div>

                <div class="total">
                    <h2>{attack_count}</h2>
                    <p>拦截攻击总数</p>
                </div>

                <div class="card">
                    <h3>📊 攻击类型分布</h3>
                    {stats_html}
                </div>

                <div class="card">
                    <h3>🕐 最近攻击记录</h3>
                    <table>
                        <tr><th>时间</th><th>攻击类型</th><th>IP地址</th></tr>
                        {recent_html if recent_html else '<tr><td colspan="3" style="text-align: center;color:#999;">暂无记录</td></tr>'}
                    </table>
                </div>
            </div>
        </body>
        </html>
        ''',
        content_type="text/html; charset=utf-8"
    )


# ==================== 程序入口 ====================

if __name__ == "__main__":
    # 打印启动信息
    print("=" * 50)
    print("       WAF 防火墙已启动")
    print("=" * 50)
    print(f"监听端口: {LISTEN_PORT}")
    print(f"后端地址: {BACKEND}")
    print(f"日志文件: {LOG_FILE}")
    print("-" * 50)
    print(f"查看日志: http://localhost:{LISTEN_PORT}/waf/logs")
    print(f"统计信息: http://localhost:{LISTEN_PORT}/waf/stats")
    print(f"清空日志: http://localhost:{LISTEN_PORT}/waf/clear")
    print("=" * 50)

    # 记录启动日志
    write_log("INFO", "WAF 防火墙启动", {
        "监听端口": LISTEN_PORT,
        "后端地址": BACKEND,
    })

    # 启动 Flask 应用
    app.config['PROPAGATE_EXCEPTIONS'] = False
    app.config['DEBUG'] = True
    app.run(host="localhost", port=LISTEN_PORT, debug=True)