#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
校园网自动登录脚本 - 增强版
支持配置文件、日志记录、自动重试等功能
"""

import requests
import json
import re
import time
import socket
import os
import sys
import getpass
import questionary
import netifaces
from datetime import datetime
from typing import Dict, Optional, List
from loguru import logger
from config import ConfigManager

class EnhancedCampusLogin:
    def __init__(self):
        """
        初始化校园网登录类
        """
        # 初始化配置管理器
        self.config_manager = ConfigManager()
        self.config = self.config_manager.get_config()
        
        server_config = self.config_manager.get_server_config()
        self.base_url = server_config['base_url']
        self.timeout = server_config['timeout']
        self.session = requests.Session()
        
        # 设置日志格式
        fmt = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
        
        # 清除默认处理程序
        logger.remove()
        
        # 添加控制台处理程序
        logger.add(sys.stderr, format=fmt, level="INFO")
        
        # 添加文件处理程序
        log_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
        os.makedirs(log_path, exist_ok=True)
        logger.add(
            os.path.join(log_path, "main_{time}.log"),
            rotation="10 MB",
            format=fmt,
            level="DEBUG",
            encoding="utf-8"
        )
        
        # 设置请求头
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0',
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh-TW;q=0.9,zh;q=0.8,en;q=0.7,zh-HK;q=0.6,en-US;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'DNT': '1',
            'Connection': 'keep-alive'
        })
        
        logger.info("校园网登录客户端初始化完成")
    

    
    def get_user_credentials(self, force_config=False) -> Dict[str, str]:
        """
        获取用户凭据，优先使用配置文件，如果没有则提示用户输入
        """
        # 如果不是强制配置，先尝试从配置文件读取凭据
        if not force_config:
            user_config = self.config_manager.get_user_config()
            
            # 检查配置文件中是否有有效的用户名和密码
            if (user_config.get('username') and 
                user_config.get('password') and 
                user_config['username'].strip() != ''):
                
                logger.info(f"使用已保存的用户名: {user_config['username']}")
                return {
                    'username': user_config['username'],
                    'password': user_config['password']
                }
        
        # 提示用户输入新的凭据
        logger.info("请输入校园网登录凭据")
  
        base_username = questionary.text(
            "用户名（学号/工号）:",
            style=questionary.Style([
                ('question', 'fg:#ff9d00 bold'),
                ('answer', 'fg:#ff9d00')
            ])
        ).ask()
        
        if base_username is None:
            logger.info("用户取消输入")
            sys.exit(0)
        
        base_username = base_username.strip()

        password = questionary.text(
            "密码:",
            style=questionary.Style([
                ('question', 'fg:#ff9d00 bold'),
                ('answer', 'fg:#ff9d00')
            ])
        ).ask()
        
        if password is None:
            logger.info("用户取消输入")
            sys.exit(0)
        
        password = password.strip()
        
        # 获取运营商配置
        isp_config = self.config_manager.get_isp_config()
        available_isps = isp_config.get('available_isps', {
            '1': {'name': '校园网', 'suffix': ''},
            '2': {'name': '中国移动', 'suffix': '@cmcc'},
            '3': {'name': '中国联通', 'suffix': '@unicom'},
            '4': {'name': '中国电信', 'suffix': '@telecom'}
        })
        default_isp = isp_config.get('default_isp', '1')
        
        isp_choices = [f"{isp_info['name']}" for isp_info in available_isps.values()]
        default_isp_name = available_isps[default_isp]['name']
        
        selected_isp_name = questionary.select(
            "📡 请选择运营商:",
            choices=isp_choices,
            default=default_isp_name,
            style=questionary.Style([
                ('question', 'fg:#ff9d00 bold'),
                ('pointer', 'fg:#ff9d00 bold'),
                ('highlighted', 'fg:#ff9d00 bold'),
                ('selected', 'fg:#cc5454'),
                ('instruction', 'fg:#858585')
            ])
        ).ask()
        
        if selected_isp_name is None:
            logger.info("用户取消输入")
            sys.exit(0)
        
        # 根据选择的运营商名称找到对应的配置
        isp_choice = None
        for key, isp_info in available_isps.items():
            if isp_info['name'] == selected_isp_name:
                isp_choice = key
                break
        
        # 验证选择并设置默认值
        if isp_choice not in available_isps:
            isp_choice = default_isp
            
        selected_isp = available_isps[isp_choice]
        suffix = selected_isp['suffix']
        username = base_username + suffix
        
        logger.info(f"已选择运营商: {selected_isp['name']}")
        logger.info(f"完整用户名: {username}")
        
        # 自动保存凭据到配置文件
        self.config_manager.save_credentials(username, password)
        logger.info("凭据已保存到配置文件")
        
        return {
            'username': username,
            'password': password
        }
    


    def get_local_ip(self) -> str:
        """
        智能获取本机IP地址，优先选择校园网段IP，避免VPN等虚拟网络
        """
        try:
            # 获取所有网络接口
            interfaces = netifaces.interfaces()
            campus_ips = []
            other_ips = []
            
            for interface in interfaces:
                # 跳过回环接口和虚拟接口
                if 'loopback' in interface.lower() or 'radmin' in interface.lower():
                    continue
                    
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            ip = addr_info.get('addr')
                            if ip and not ip.startswith('127.'):
                                # 优先选择校园网段IP (172.19.x.x)
                                if ip.startswith('172.19.'):
                                    campus_ips.append(ip)
                                    logger.debug(f"发现校园网IP: {ip} (接口: {interface})")
                                # 其他私有网段IP作为备选
                                elif (ip.startswith('192.168.') or 
                                      ip.startswith('10.') or 
                                      ip.startswith('172.')):
                                    other_ips.append(ip)
                                    logger.debug(f"发现其他IP: {ip} (接口: {interface})")
                except Exception as e:
                    logger.debug(f"读取接口 {interface} 失败: {e}")
                    continue
            
            # 优先返回校园网段IP
            if campus_ips:
                selected_ip = campus_ips[0]
                logger.info(f"选择校园网IP: {selected_ip}")
                return selected_ip
            
            # 如果没有校园网IP，使用其他私有IP
            if other_ips:
                selected_ip = other_ips[0]
                logger.info(f"选择备用IP: {selected_ip}")
                return selected_ip
            
            # 如果都没有，尝试传统方法
            logger.warning("未找到合适的网络接口，尝试传统方法获取IP")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                fallback_ip = s.getsockname()[0]
                # 检查是否为校园网段
                if fallback_ip.startswith('172.19.'):
                    logger.info(f"传统方法获取到校园网IP: {fallback_ip}")
                    return fallback_ip
                else:
                    logger.warning(f"传统方法获取的IP不在校园网段: {fallback_ip}")
                    
        except Exception as e:
            logger.warning(f"无法自动获取IP地址: {e}")
        
        # 最后使用配置文件中的默认IP
        user_config = self.config_manager.get_user_config()
        default_ip = user_config.get('user_ip', '172.19.202.90')
        logger.info(f"使用配置文件中的默认IP: {default_ip}")
        return default_ip
    
    def check_network_status(self) -> bool:
        """
        检查网络连接状态
        """
        logger.info("正在检查网络连接状态...")
        
        network_config = self.config_manager.get_network_check_config()
        
        for url in network_config['test_urls']:
            try:
                response = self.session.get(
                    url, 
                    timeout=network_config['check_timeout'],
                    allow_redirects=False
                )
                
                # 如果返回200且没有重定向，说明网络正常
                if response.status_code == 200:
                    logger.info(f"网络连接正常，测试URL: {url}")
                    return True
                    
            except requests.exceptions.RequestException as e:
                logger.debug(f"测试URL {url} 连接失败: {e}")
                continue
        
        logger.info("网络需要认证")
        return False
    
    def login_with_retry(self, username: Optional[str] = None, 
                        password: Optional[str] = None, 
                        user_ip: Optional[str] = None) -> Dict:
        """
        带重试机制的登录
        """
        # 使用配置文件中的默认值
        user_config = self.config_manager.get_user_config()
        retry_config = self.config_manager.get_retry_config()
        
        username = username or user_config['username']
        password = password or user_config['password']
        user_ip = user_ip or self.get_local_ip()
        
        max_retries = retry_config['max_retries']
        retry_delay = retry_config['retry_delay']
        
        for attempt in range(max_retries + 1):
            if attempt > 0:
                logger.info(f"第 {attempt} 次重试登录...")
                time.sleep(retry_delay)
            
            result = self._do_login(username, password, user_ip)
            
            if result['success']:
                logger.info(f"登录成功: {result['message']}")
                return result
            else:
                logger.warning(f"登录失败: {result['message']}")
                if attempt < max_retries:
                    logger.info(f"将在 {retry_delay} 秒后重试...")
        
        logger.error(f"经过 {max_retries} 次重试后仍然登录失败")
        return result
    
    def _do_login(self, username: str, password: str, user_ip: str) -> Dict:
        """
        执行单次登录尝试
        """
        # 构建登录参数
        login_params = {
            'callback': 'dr1003',
            'login_method': '1',
            'user_account': username,
            'user_password': password,
            'wlan_user_ip': user_ip,
            'wlan_user_ipv6': '',
            'wlan_user_mac': '000000000000',
            'wlan_ac_ip': '',
            'wlan_ac_name': '',
            'jsVersion': '4.2.1',
            'terminal_type': '1',
            'lang': 'zh-cn',
            'v': '5911'
        }
        
        # 构建登录URL
        server_config = self.config_manager.get_server_config()
        login_path = server_config.get('login_path', '/eportal/portal/login')
        login_url = f"{self.base_url}{login_path}"
        
        try:
            # 设置referer
            self.session.headers['Referer'] = f"{self.base_url}/"
            
            logger.debug(f"发送登录请求到: {login_url}")
            logger.debug(f"登录参数: {login_params}")
            
            # 发送登录请求
            response = self.session.get(
                login_url, 
                params=login_params, 
                timeout=self.timeout
            )
            
            # 检查响应状态
            if response.status_code != 200:
                error_msg = f'HTTP请求失败，状态码: {response.status_code}'
                logger.error(error_msg)
                return {
                    'success': False,
                    'message': error_msg,
                    'raw_response': response.text
                }
            
            # 解析响应内容
            return self._parse_response(response.text)
            
        except requests.exceptions.RequestException as e:
            error_msg = f'网络请求异常: {str(e)}'
            logger.error(error_msg)
            return {
                'success': False,
                'message': error_msg,
                'raw_response': ''
            }
    
    def _parse_response(self, response_text: str) -> Dict:
        """
        解析登录响应
        """
        try:
            logger.debug(f"原始响应: {response_text}")
            
            # 使用正则表达式提取JSONP回调中的JSON数据
            match = re.search(r'dr1003\((.+)\);?', response_text)
            
            if not match:
                error_msg = '无法解析响应格式'
                logger.error(f"{error_msg}: {response_text}")
                return {
                    'success': False,
                    'message': error_msg,
                    'raw_response': response_text
                }
            
            # 解析JSON数据
            json_data = json.loads(match.group(1))
            logger.debug(f"解析后的JSON: {json_data}")
            
            # 判断登录是否成功
            if json_data.get('result') == 1:
                return {
                    'success': True,
                    'message': json_data.get('msg', '登录成功'),
                    'raw_response': response_text
                }
            else:
                return {
                    'success': False,
                    'message': json_data.get('msg', '登录失败'),
                    'raw_response': response_text
                }
                
        except json.JSONDecodeError as e:
            error_msg = f'JSON解析错误: {str(e)}'
            logger.error(error_msg)
            return {
                'success': False,
                'message': error_msg,
                'raw_response': response_text
            }
        except Exception as e:
            error_msg = f'响应解析异常: {str(e)}'
            logger.error(error_msg)
            return {
                'success': False,
                'message': error_msg,
                'raw_response': response_text
            }
    
    def auto_login(self, force_config=False) -> bool:
        """
        自动登录流程
        """
        logger.info("开始自动登录流程")
        
        # 检查网络状态
        if not force_config and self.check_network_status():
            logger.info("网络连接正常，无需登录")
            return True
        
        # 获取用户凭据
        credentials = self.get_user_credentials(force_config)
        
        # 执行登录
        logger.info("开始校园网登录")
        result = self.login_with_retry(
            username=credentials['username'],
            password=credentials['password']
        )
        
        if result['success']:
            logger.info(f"登录成功: {result['message']}")
            
            # 再次检查网络状态
            if self.check_network_status():
                logger.info("网络连接验证成功")
                return True
            else:
                logger.warning("登录成功但网络仍无法访问")
                return False
        else:
            logger.error(f"登录失败: {result['message']}")
            return False

def main():
    """
    主函数
    """
    print("=" * 50)
    print("常州工学院(CZU)校园网自动登录工具")
    print(f"启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("项目地址: https://github.com/Hanzzkj652/CZU-Network")
    print("=" * 50)
    try:
        # 创建登录实例
        campus_login = EnhancedCampusLogin()
        
        # 检查是否需要重新配置凭据
        if len(sys.argv) > 1 and sys.argv[1] in ['--config', '-c']:
            logger.info("重新配置用户凭据")
            # 强制重新获取用户凭据并执行登录
            success = campus_login.auto_login(force_config=True)
            if success:
                logger.info("凭据配置完成并登录成功！")
                logger.info("程序将在3秒后退出...")
                time.sleep(3)
            else:
                logger.error("凭据配置完成但登录失败")
                logger.info("程序将在3秒后退出...")
                time.sleep(3)
            return
        
        # 执行自动登录
        success = campus_login.auto_login()
        
        if success:
            logger.info("校园网登录完成，网络连接正常！")
            logger.info("程序将在3秒后退出...")
            time.sleep(3)
        else:
            logger.error("校园网登录失败，请检查配置或网络状态")
            logger.info("程序将在3秒后退出...")
            time.sleep(3)
            
    except KeyboardInterrupt:
        logger.info("用户中断操作")
    except Exception as e:
        logger.error(f"程序运行异常: {e}")
        logger.exception("程序运行异常")

if __name__ == "__main__":
    main()