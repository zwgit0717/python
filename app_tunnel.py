#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eooce/Sing-box 项目的 SSH 反向隧道模板 (基于 python/app.py 修改)
================================================================
用途: 在容器平台没有公网端口时, 用自己的 VPS 作反向隧道代替 Cloudflare Argo,
      避免依赖 CF 优选 IP。

用法: 直接用本文件替换 eooce 项目中的 python/app.py, 填写下方环境变量即可。
      不启用隧道时 (SSH_TUNNEL=false), 行为与原版 app.py 完全一致。

新增环境变量:
    SSH_TUNNEL  是否启用 VPS 反向隧道, "true" 启用, 默认 "false"
    SSH_HOST    VPS 公网 IP, 例如 3.114.183.128
    SSH_PORT    VPS SSH 端口, 例如 61522
    SSH_USER    VPS 上的隧道用户名, 例如 ctunnel (无 shell, 仅允许端口转发)
    SSH_KEY     隧道私钥内容 (多行, 直接粘贴; 若平台把换行转成 \n 也会自动处理)
    SSH_RPORT   VPS 上暴露的公网端口, 例如 10100 (每次部署用不同端口, 范围见文档)
    SSH_LPORT   容器内 sing-box 的端口, 留空则自动跟随 ARGO_PORT (默认 8001)
    WS_PATH     vmess-ws 的路径, 默认 /vmess-argo (一般不用改)

原理:
    容器内: sing-box(vmess+ws) 监听 SSH_LPORT
             -> ssh -R 0.0.0.0:SSH_RPORT:localhost:SSH_LPORT 到 VPS
    用户侧:  客户端连接 VPS_IP:SSH_RPORT, 流量经隧道进容器, 从容器出口上网
    注意: SSH 只转发 TCP, 所以只支持 vmess-ws 这类 TCP 协议 (默认即是)。
"""

import os
import sys
import signal
import time
import stat
import json
import base64
import shutil
import subprocess
import urllib.request
import urllib.error
import http.server
import socketserver
import threading
import platform
from pathlib import Path

# ---------------- 原版环境变量配置 ----------------
PORT = int(os.environ.get('PORT', 3000))       # http服务端口
SUB_PATH = os.environ.get('SUB_PATH', 'sub')   # 订阅token
config = {
    'UUID': os.environ.get('UUID', ''),
    'NEZHA_SERVER': os.environ.get('NEZHA_SERVER', ''),
    'NEZHA_PORT': os.environ.get('NEZHA_PORT', ''),
    'NEZHA_KEY': os.environ.get('NEZHA_KEY', ''),
    'ARGO_DOMAIN': os.environ.get('ARGO_DOMAIN', ''),
    'ARGO_AUTH': os.environ.get('ARGO_AUTH', ''),
    'ARGO_PORT': os.environ.get('ARGO_PORT', '8001'),
    'CFIP': os.environ.get('CFIP', 'saas.sin.fan'),
    'CFPORT': os.environ.get('CFPORT', '443'),
    'NAME': os.environ.get('NAME', ''),
    'S5_PORT': os.environ.get('S5_PORT', ''),
    'HY2_PORT': os.environ.get('HY2_PORT', ''),
    'TUIC_PORT': os.environ.get('TUIC_PORT', ''),
    'ANYTLS_PORT': os.environ.get('ANYTLS_PORT', ''),
    'REALITY_PORT': os.environ.get('REALITY_PORT', ''),
    'ANYREALITY_PORT': os.environ.get('ANYREALITY_PORT', ''),
    'CHAT_ID': os.environ.get('CHAT_ID', ''),
    'BOT_TOKEN': os.environ.get('BOT_TOKEN', ''),
    'UPLOAD_URL': os.environ.get('UPLOAD_URL', ''),
    'FILE_PATH': os.environ.get('FILE_PATH', '.cache'),
    'DISABLE_ARGO': os.environ.get('DISABLE_ARGO', 'false'),
    'SHOW_LOG': os.environ.get('SHOW_LOG', 'true'),
    # ---------------- 隧道模式新增 ----------------
    'SSH_TUNNEL': os.environ.get('SSH_TUNNEL', ''),  # true=启用VPS隧道代替argo
    'SSH_HOST': os.environ.get('SSH_HOST', ''),
    'SSH_PORT': os.environ.get('SSH_PORT', ''),
    'SSH_USER': os.environ.get('SSH_USER', ''),
    'SSH_KEY': os.environ.get('SSH_KEY', ''),
    'SSH_RPORT': os.environ.get('SSH_RPORT', ''),
    'SSH_LPORT': os.environ.get('SSH_LPORT', ''),        # 留空=跟随ARGO_PORT
    'WS_PATH': os.environ.get('WS_PATH', '/vmess-argo'),
}

TUNNEL_ON = config['SSH_TUNNEL'].lower() == 'true'
if TUNNEL_ON:
    # 隧道模式下强制禁用 argo, sing-box 以直连端口模式运行
    config['DISABLE_ARGO'] = 'true'
    if not config['SSH_LPORT']:
        config['SSH_LPORT'] = config['ARGO_PORT']


# ================= 隧道相关函数 =================

def ensure_ssh_client():
    """确保容器内有 ssh 客户端, 没有则尝试 apt 安装"""
    if shutil.which('ssh'):
        return True
    print('ssh 客户端不存在, 尝试 apt-get 安装 openssh-client ...')
    try:
        subprocess.run(['apt-get', 'update', '-qq'], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        r = subprocess.run(['apt-get', 'install', '-y', '-qq', 'openssh-client'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
        if r.returncode == 0 and shutil.which('ssh'):
            print('openssh-client 安装成功')
            return True
    except Exception as e:
        print(f'安装 openssh-client 失败: {e}')
    return False


def write_ssh_key():
    """把环境变量中的私钥写入文件"""
    key_text = config['SSH_KEY']
    if not key_text:
        raise Exception('SSH_TUNNEL=true 但 SSH_KEY 为空, 请填写隧道私钥')
    # 兼容平台把换行转义成 \n 的情况
    if '\n' not in key_text and '\\n' in key_text:
        key_text = key_text.replace('\\n', '\n')
    key_text = key_text.strip() + '\n'
    ssh_dir = os.path.expanduser('~/.ssh')
    os.makedirs(ssh_dir, exist_ok=True)
    key_path = os.path.join(ssh_dir, 'tunnel_key')
    with open(key_path, 'w') as f:
        f.write(key_text)
    os.chmod(key_path, 0o600)
    return key_path


def check_tunnel_alive():
    """从容器内验证隧道是否真的通了: 连 VPS 公网端口, 能握手即转发链路正常"""
    import socket
    try:
        s = socket.create_connection((config['SSH_HOST'], int(config['SSH_RPORT'])), timeout=8)
        s.close()
        return True
    except Exception:
        return False


def tunnel_loop(key_path):
    """隧道保活循环: ssh 断线自动重连"""
    host = config['SSH_HOST']
    port = config['SSH_PORT']
    user = config['SSH_USER']
    rport = config['SSH_RPORT']
    lport = config['SSH_LPORT']
    if not all([host, user, rport, lport]):
        print('❌ 隧道参数不全, 请检查 SSH_HOST/SSH_USER/SSH_RPORT/SSH_LPORT')
        return
    cmd = [
        'ssh', '-N',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3',
        '-o', 'ExitOnForwardFailure=yes',
        '-o', 'BatchMode=yes',
        '-R', f'0.0.0.0:{rport}:localhost:{lport}',
        '-i', key_path,
        '-p', str(port),
        f'{user}@{host}',
    ]
    fail_count = 0
    while True:
        print(f'🔗 正在建立隧道 {host}:{rport} -> 容器:{lport} ...')
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            # 等几秒看是否立刻退出 (端口被占/认证失败会立刻退出)
            time.sleep(6)
            if p.poll() is not None:
                out = p.stdout.read().decode(errors='ignore')[-500:]
                fail_count += 1
                wait = min(10 * fail_count, 60)
                print(f'❌ 隧道启动失败 (第{fail_count}次), {wait}s 后重试. 输出: {out.strip()[-200:]}')
                time.sleep(wait)
                continue
            fail_count = 0
            # 存活检查: 每 30s 验证一次转发链路
            while p.poll() is None:
                time.sleep(30)
                if not check_tunnel_alive():
                    print('⚠️  转发链路不通, 重建隧道')
                    p.terminate()
                    break
            print('⚠️  隧道进程退出, 5s 后重连')
            time.sleep(5)
        except Exception as e:
            print(f'隧道异常: {e}, 10s 后重试')
            time.sleep(10)


def generate_vmess_link():
    """按 sbsh 的默认配置 (vmess+ws) 生成节点链接, 地址指向 VPS"""
    vmess_info = {
        'v': '2',
        'ps': f"{config['NAME'] or 'tunnel'}-{config['SSH_RPORT']}",
        'add': config['SSH_HOST'],
        'port': config['SSH_RPORT'],
        'id': config['UUID'],
        'aid': '0',
        'scy': 'auto',
        'net': 'ws',
        'type': 'none',
        'host': '',
        'path': config['WS_PATH'],
        'tls': '',
    }
    link = 'vmess://' + base64.b64encode(
        json.dumps(vmess_info, separators=(',', ':')).encode()).decode()
    return link


def write_tunnel_sub(link):
    """把隧道节点链接写入订阅文件 (覆盖 sbsh 生成的空文件)"""
    sub_file = os.path.join(config['FILE_PATH'], 'sub.txt')
    os.makedirs(config['FILE_PATH'], exist_ok=True)
    with open(sub_file, 'w') as f:
        f.write(link + '\n')
    print(f'📝 订阅文件已写入: {sub_file}')


# ================= 原版函数 (未改动) =================

def sleep(ms):
    time.sleep(ms / 1000)

def get_architecture():
    arch = platform.machine().lower()
    system = platform.system().lower()
    if system in ['linux', 'darwin']:
        if arch in ['x86_64', 'amd64']:
            return 'amd64'
        elif arch in ['aarch64', 'arm64']:
            return 'arm64'
    raise Exception(f"Unsupported architecture: {system} {arch}")

def download_file(url, dest_path):
    opener = urllib.request.build_opener()
    opener.addheaders = [
        ('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'),
        ('Accept', '*/*'),
        ('Connection', 'keep-alive')
    ]
    urllib.request.install_opener(opener)
    try:
        urllib.request.urlretrieve(url, dest_path)
    except urllib.error.HTTPError as e:
        if os.path.exists(dest_path):
            os.unlink(dest_path)
        raise Exception(f"Download failed (HTTP {e.code}): {e.reason}")
    except urllib.error.URLError as e:
        if os.path.exists(dest_path):
            os.unlink(dest_path)
        raise Exception(f"Download failed: {str(e)}")
    except Exception as e:
        if os.path.exists(dest_path):
            os.unlink(dest_path)
        raise Exception(f"Download failed: {str(e)}")

def set_executable(file_path):
    try:
        current_permissions = os.stat(file_path).st_mode
        os.chmod(file_path, current_permissions | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception as e:
        raise Exception(f"Failed to set executable permission: {str(e)}")

def delete_file(file_path):
    try:
        if os.path.exists(file_path):
            os.unlink(file_path)
    except Exception as e:
        print(f"Failed to delete file {file_path}: {str(e)}")

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.handle_root()
        elif self.path == f'/{SUB_PATH}':
            self.handle_sub()
        elif self.path == '/ps':
            self.handle_ps()
        else:
            self.send_error(404, '404 Not Found')

    def handle_root(self):
        try:
            html_path = os.path.join(os.path.dirname(__file__), 'index.html')
            if os.path.exists(html_path):
                with open(html_path, 'r', encoding='utf-8') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(data.encode('utf-8'))
            else:
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write("Hello world!<br><br>You can access /{SUB_PATH}(Default: /sub) to get your nodes!".encode('utf-8'))
        except Exception as e:
            self.send_error(500, str(e))

    def handle_sub(self):
        sub_file_path = os.path.join(config['FILE_PATH'], 'sub.txt')
        try:
            if os.path.exists(sub_file_path):
                with open(sub_file_path, 'r', encoding='utf-8') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(data.encode('utf-8'))
            else:
                self.send_error(404, f'Sub file not found at: {sub_file_path}')
        except Exception as e:
            self.send_error(500, str(e))

    def handle_ps(self):
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, check=True)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(result.stdout.encode('utf-8'))
        except subprocess.CalledProcessError as e:
            self.send_error(500, f'Error executing ps command: {str(e)}')

    def log_message(self, format, *args):
        pass

def start_http_server():
    handler = CustomHTTPRequestHandler
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(('0.0.0.0', PORT), handler)
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return httpd

def cleanup(binary_path):
    delete_file(binary_path)

def main():
    binary_path = None
    httpd = None
    process = None

    try:
        httpd = start_http_server()

        # ---------- 隧道模式: 准备 ssh ----------
        key_path = None
        if TUNNEL_ON:
            print('🚇 SSH 隧道模式已启用 (代替 argo)')
            if not ensure_ssh_client():
                raise Exception('容器内无 ssh 客户端且无法安装, 隧道模式不可用')
            key_path = write_ssh_key()
            t = threading.Thread(target=tunnel_loop, args=(key_path,), daemon=True)
            t.start()

        arch = get_architecture()
        download_url = 'https://amd64.eooce.com/sbsh' if arch == 'amd64' else 'https://arm64.eooce.com/sbsh'

        binary_path = os.path.join(os.getcwd(), 'sbsh')
        download_file(download_url, binary_path)
        if not os.path.exists(binary_path):
            raise Exception('Download failed, file does not exist at the specified path')
        set_executable(binary_path)

        env = os.environ.copy()
        env.update({k: str(v) for k, v in config.items()})

        process = subprocess.Popen(
            [binary_path],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )

        def log_output():
            for line in process.stdout:
                print(line, end='')

        log_thread = threading.Thread(target=log_output)
        log_thread.daemon = True
        log_thread.start()

        sleep(18000)

        # ---------- 隧道模式: 生成指向 VPS 的节点链接 ----------
        if TUNNEL_ON:
            # 等 sing-box 就绪
            time.sleep(10)
            link = generate_vmess_link()
            write_tunnel_sub(link)
            print('')
            print('✅ 隧道节点链接 (导入客户端即可用):')
            print(link)
            print('')

        sleep(90000)
        cleanup(binary_path)
        os.system('clear' if os.name == 'posix' else 'cls')
        print('✅  App is running')
        print(f'🌐  HTTP server is running on {PORT}')
        if TUNNEL_ON:
            print(f"🚇 隧道: {config['SSH_HOST']}:{config['SSH_RPORT']} -> 容器:{config['SSH_LPORT']}")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")

    except Exception as e:
        print(f"\n❌ An error occurred: {str(e)}")
        if binary_path:
            cleanup(binary_path)
        sys.exit(1)
    finally:
        if process and process.poll() is None:
            process.terminate()
        if httpd:
            httpd.shutdown()

def signal_handler(signum, frame):
    print("\nReceived signal to terminate")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()
