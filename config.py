#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理模块
负责应用配置的加载、保存和管理
"""

import json
import os
from typing import Dict
from loguru import logger


class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_file: str = 'app_config.json'):
        """
        初始化配置管理器
        """
        self.config_file = config_file
        self.config = self.load_config()
    
    def get_default_config(self) -> Dict:
        """
        获取默认配置
        """
        return {
            "server_config": {
                "base_url": "http://172.19.0.1:801",
                "login_path": "/eportal/portal/login",
                "timeout": 10
            },
            "user_config": {
                "username": "",
                "password": "",
                "user_ip": "172.19.202.90"
            },
            "isp_config": {
                "available_isps": {
                    "1": {"name": "校园网", "suffix": ""},
                    "2": {"name": "中国移动", "suffix": "@cmcc"},
                    "3": {"name": "中国联通", "suffix": "@unicom"},
                    "4": {"name": "中国电信", "suffix": "@telecom"}
                },
                "default_isp": "1"
            },
            "network_check": {
                "test_urls": [
                    "http://www.baidu.com",
                    "http://www.qq.com",
                    "http://www.163.com"
                ],
                "check_timeout": 5
            },
            "log_config": {
                "enable_logging": True,
                "log_file": "campus_login.log",
                "log_level": "INFO"
            },
            "retry_config": {
                "max_retries": 3,
                "retry_delay": 2
            }
        }
    
    def load_config(self) -> Dict:
        """
        加载配置文件
        """
        default_config = self.get_default_config()
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 合并默认配置，确保所有必要的键都存在
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                    elif isinstance(value, dict):
                        for sub_key, sub_value in value.items():
                            if sub_key not in config[key]:
                                config[key][sub_key] = sub_value
                return config
            else:
                # 创建默认配置文件
                self.save_config(default_config)
                return default_config
        except Exception as e:
            logger.warning(f"读取配置文件失败，使用默认配置: {e}")
            return default_config
    
    def save_config(self, config: Dict = None):
        """
        保存配置到文件
        """
        try:
            config_to_save = config if config is not None else self.config
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_to_save, f, ensure_ascii=False, indent=4)
            logger.debug(f"配置已保存到: {self.config_file}")
        except Exception as e:
            logger.error(f"保存配置文件失败: {e}")
    
    def get_config(self, section: str = None) -> Dict:
        """
        获取配置
        """
        if section is None:
            return self.config
        return self.config.get(section, {})
    
    def update_config(self, section: str, key: str, value):
        """
        更新配置项
        """
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][key] = value
        self.save_config()
        logger.debug(f"配置已更新: {section}.{key} = {value}")
    
    def save_credentials(self, username: str, password: str):
        """
        保存用户凭据
        """
        try:
            self.config['user_config']['username'] = username
            self.config['user_config']['password'] = password
            self.save_config()
            logger.info(f"用户凭据已保存到配置文件: {username}")
        except Exception as e:
            logger.error(f"保存用户凭据失败: {e}")
    
    def get_user_config(self) -> Dict:
        """
        获取用户配置
        """
        return self.config.get('user_config', {})
    
    def get_server_config(self) -> Dict:
        """
        获取服务器配置
        """
        return self.config.get('server_config', {})
    
    def get_isp_config(self) -> Dict:
        """
        获取ISP配置
        """
        return self.config.get('isp_config', {})
    
    def get_network_check_config(self) -> Dict:
        """
        获取网络检查配置
        """
        return self.config.get('network_check', {})
    
    def get_retry_config(self) -> Dict:
        """
        获取重试配置
        """
        return self.config.get('retry_config', {})