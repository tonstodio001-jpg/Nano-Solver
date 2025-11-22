# -*- coding: utf-8 -*-
import kivy
kivy.require("2.3.1")

from kivy.app import App
from kivy.lang import Builder
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.widget import Widget
from kivy.uix.image import Image
from kivy.properties import StringProperty, BooleanProperty, ListProperty, NumericProperty
from kivy.animation import Animation
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.graphics import Color, RoundedRectangle, Rectangle, Line
from kivy.metrics import dp

import platform
import os
import random
import re
import webbrowser
import requests
import base64
import textwrap
import datetime
import ast
import ssl
import socket
import hashlib
import secrets
import string
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socketserver
from urllib.parse import urlparse, parse_qs
from io import BytesIO
import html
from collections import defaultdict
import stat
import importlib.util
import traceback
from pathlib import Path

# ==================== PLUGIN SYSTEM ====================

class PluginManager:
    def __init__(self, app_instance):
        self.app = app_instance
        self.plugins_dir = "plugins"
        self.loaded_plugins = {}
        self.create_plugins_directory()
        
    def create_plugins_directory(self):
        """Create plugins directory if it doesn't exist"""
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir)
            print("📁 Created plugins directory")
            
            # Create example plugin
            self.create_example_plugin()
    
    def create_example_plugin(self):
        """Create an example plugin for users"""
        example_plugin = '''# Example Plugin for Nano Solver
# This plugin demonstrates how to create custom commands

def hello_world_command(app, args):
    """Hello world example command
    Usage: hello [name]
    """
    name = args[0] if args else "World"
    return f"👋 Hello {name}! This is a plugin command!"

def calculator_advanced(app, args):
    """Advanced calculator with more operations
    Usage: calc_adv <expression>
    """
    if not args:
        return "Usage: calc_adv <expression>"
    
    try:
        # Safe evaluation with more operations
        result = eval(''.join(args), {"__builtins__": {}}, 
                     {"sin": __import__("math").sin, "cos": __import__("math").cos,
                      "sqrt": __import__("math").sqrt, "pi": __import__("math").pi})
        return f"🧮 Result: {result}"
    except Exception as e:
        return f"❌ Calculation error: {str(e)}"

def system_info_advanced(app, args):
    """Advanced system information
    Usage: sysinfo_adv
    """
    try:
        import psutil
        
        info = []
        info.append("🖥️ ADVANCED SYSTEM INFORMATION")
        info.append("=" * 40)
        
        # CPU information
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        info.append(f"CPU: {cpu_percent}% used ({cpu_count} cores)")
        
        # Memory information
        memory = psutil.virtual_memory()
        info.append(f"RAM: {memory.percent}% used ({memory.used//(1024**3)}GB/{memory.total//(1024**3)}GB)")
        
        # Disk information
        disk = psutil.disk_usage('/')
        info.append(f"Disk: {disk.percent}% used ({disk.used//(1024**3)}GB/{disk.total//(1024**3)}GB)")
        
        # Network information
        net_io = psutil.net_io_counters()
        info.append(f"Network: Sent: {net_io.bytes_sent//(1024**2)}MB, Recv: {net_io.bytes_recv//(1024**2)}MB")
        
        # Boot time
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        info.append(f"Boot Time: {boot_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        return "\\n".join(info)
        
    except ImportError:
        return "❌ This plugin requires 'psutil' library. Install with: pip install psutil"

# Plugin metadata
PLUGIN_INFO = {
    "name": "Example Plugin",
    "version": "1.0.0",
    "author": "Nano Solver",
    "description": "Example plugin demonstrating plugin system capabilities",
    "commands": {
        "hello": hello_world_command,
        "calc_adv": calculator_advanced,
        "sysinfo_adv": system_info_advanced
    }
}
'''
        with open(os.path.join(self.plugins_dir, "example_plugin.py"), "w", encoding="utf-8") as f:
            f.write(example_plugin)
        print("📝 Created example plugin")
    
    def load_plugins(self):
        """Load all plugins from the plugins directory"""
        self.loaded_plugins = {}
        
        if not os.path.exists(self.plugins_dir):
            print("❌ Plugins directory not found")
            return
        
        for file_name in os.listdir(self.plugins_dir):
            if file_name.endswith(".py") and not file_name.startswith("_"):
                plugin_path = os.path.join(self.plugins_dir, file_name)
                success, result = self.load_plugin(plugin_path)
                
                if success:
                    print(f"✅ Loaded plugin: {file_name}")
                else:
                    print(f"❌ Failed to load plugin {file_name}: {result}")
    
    def load_plugin(self, plugin_path):
        """Load a single plugin file"""
        try:
            # Read the plugin file
            with open(plugin_path, 'r', encoding='utf-8') as f:
                plugin_code = f.read()
            
            # Check for dangerous patterns
            dangerous_patterns = [
                r'__import__\s*\(\s*["\']os["\']\s*\)',
                r'__import__\s*\(\s*["\']sys["\']\s*\)',
                r'exec\s*\(',
                r'eval\s*\(',
                r'compile\s*\(',
                r'open\s*\(\s*["\'][^"\']*["\']\s*,\s*["\']w["\']',
                r'__builtins__',
                r'__import__\s*\(\s*["\']subprocess["\']\s*\)',
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, plugin_code):
                    return False, f"Dangerous pattern detected: {pattern}"
            
            # Create a module specification
            spec = importlib.util.spec_from_file_location(Path(plugin_path).stem, plugin_path)
            plugin_module = importlib.util.module_from_spec(spec)
            
            # Execute the module in a restricted environment
            restricted_globals = {
                '__builtins__': {
                    'print': print,
                    'len': len,
                    'str': str,
                    'int': int,
                    'float': float,
                    'list': list,
                    'dict': dict,
                    'tuple': tuple,
                    'set': set,
                    'range': range,
                    'enumerate': enumerate,
                    'zip': zip,
                    'Exception': Exception,
                    'datetime': datetime,
                    're': re,
                    'math': __import__('math'),
                    'json': __import__('json'),
                    'time': time,
                    'random': random,
                },
                'PLUGIN_INFO': None
            }
            
            # Execute the module
            exec(plugin_code, restricted_globals)
            
            # Get plugin info
            plugin_info = restricted_globals.get('PLUGIN_INFO')
            if not plugin_info:
                return False, "No PLUGIN_INFO found"
            
            plugin_name = plugin_info.get('name', Path(plugin_path).stem)
            self.loaded_plugins[plugin_name] = {
                'info': plugin_info,
                'commands': plugin_info.get('commands', {}),
                'module': plugin_module
            }
            
            return True, f"Successfully loaded {plugin_name}"
            
        except Exception as e:
            error_msg = self.get_helpful_error(e)
            return False, error_msg
    
    def get_helpful_error(self, error):
        """Generate helpful error messages with solutions"""
        error_type = type(error).__name__
        error_msg = str(error)
        
        error_help = {
            'ImportError': {
                'message': "Module import error",
                'solution': "Check if required modules are installed. Use 'pip install <module-name>'",
                'common_causes': ["Missing dependency", "Incorrect module name"]
            },
            'SyntaxError': {
                'message': "Syntax error in plugin code",
                'solution': "Check Python syntax in your plugin file",
                'common_causes': ["Missing colon", "Incorrect indentation", "Invalid characters"]
            },
            'NameError': {
                'message': "Undefined variable or function",
                'solution': "Check if all variables and functions are properly defined",
                'common_causes': ["Typo in variable name", "Missing function definition"]
            },
            'TypeError': {
                'message': "Incorrect data type operation",
                'solution': "Check variable types and function parameters",
                'common_causes': ["String instead of number", "Missing function arguments"]
            },
            'AttributeError': {
                'message': "Invalid attribute access",
                'solution': "Check if the object has the attribute you're trying to access",
                'common_causes': ["Wrong object type", "Misspelled attribute name"]
            },
            'IndexError': {
                'message': "List index out of range",
                'solution': "Check list length before accessing by index",
                'common_causes': ["Empty list", "Index too large"]
            }
        }
        
        help_info = error_help.get(error_type, {
            'message': f"Unexpected error: {error_type}",
            'solution': "Check the plugin code for errors",
            'common_causes': ["General coding error"]
        })
        
        return f"{help_info['message']}: {error_msg}\n💡 Solution: {help_info['solution']}\n🔍 Common causes: {', '.join(help_info['common_causes'])}"
    
    def execute_plugin_command(self, command, args):
        """Execute a plugin command"""
        for plugin_name, plugin_data in self.loaded_plugins.items():
            commands = plugin_data['commands']
            if command in commands:
                try:
                    result = commands[command](self.app, args)
                    return result
                except Exception as e:
                    error_msg = self.get_helpful_error(e)
                    return f"❌ Plugin '{plugin_name}' error: {error_msg}"
        
        return None
    
    def get_plugin_commands(self):
        """Get list of all available plugin commands"""
        commands_info = []
        for plugin_name, plugin_data in self.loaded_plugins.items():
            plugin_info = plugin_data['info']
            for cmd_name, cmd_func in plugin_data['commands'].items():
                commands_info.append({
                    'command': cmd_name,
                    'plugin': plugin_name,
                    'description': cmd_func.__doc__ or "No description available"
                })
        return commands_info
    
    def reload_plugins(self):
        """Reload all plugins"""
        self.load_plugins()
        return f"🔄 Reloaded {len(self.loaded_plugins)} plugins"

# ==================== AUDIO AND SYSTEM IMPORTS ====================

try:
    from kivy.core.audio import SoundLoader
except ImportError:
    SoundLoader = None
    print("⚠️ SoundLoader not available - audio features disabled")

try:
    import psutil
except ImportError:
    psutil = None
    print("⚠️ psutil not available - some system features disabled")

try:
    import yara
except ImportError:
    yara = None
    print("⚠️ yara not available - pattern scanning disabled")

# Optional extra modules
try:
    import dns.resolver as dns_resolver
except Exception:
    dns_resolver = None
    print("⚠️ dns.resolver not available - limited DNS queries")

try:
    import whois as pywhois
except Exception:
    pywhois = None
    print("⚠️ whois not available - WHOIS queries disabled")

# Optional token via environment variable
import os as _os
GITHUB_TOKEN = _os.environ.get("GITHUB_TOKEN")

# ==================== ADVANCED WEBSITE SCANNER ====================

class AdvancedWebsiteScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerability_patterns = {
            'sql_injection': [
                r"('|\")(\s)*(union|select|insert|update|delete|drop|create)(\s)+",
                r"(\b)(exec|execute|sp_executesql)(\b)",
                r"(\b)(waitfor|delay)(\b)",
                r"(\b)(char|concat)(\s)*\(",
                r"(\b)(version|user|database)(\s)*\(",
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"onload\s*=",
                r"onerror\s*=",
                r"onclick\s*=",
                r"onmouseover\s*=",
                r"alert\s*\(",
                r"document\.cookie",
                r"window\.location",
            ],
            'path_traversal': [
                r"(\.\./){2,}",
                r"(\b)(etc/passwd|etc/shadow|boot\.ini|win\.ini)(\b)",
                r"(%2e%2e%2f){2,}",
            ],
            'command_injection': [
                r"(\b)(rm\s+-rf|del\s+.*|format\s+.*|shutdown)(\b)",
                r"(\|\||&&)(\s*)(ls|cat|id|whoami|pwd)",
                r"(`)(.*)(`)",
            ]
        }
        
    def deep_scan_website(self, url):
        """Perform deep website security scan"""
        scan_results = {
            'url': url,
            'timestamp': datetime.datetime.now().isoformat(),
            'security_headers': {},
            'vulnerabilities': [],
            'misconfigurations': [],
            'crawl_results': [],
            'risk_score': 0,
            'recommendations': []
        }
        
        try:
            # Scan main page first
            main_page_scan = self.scan_single_page(url)
            scan_results['security_headers'] = main_page_scan['security_headers']
            scan_results['vulnerabilities'].extend(main_page_scan['vulnerabilities'])
            scan_results['misconfigurations'].extend(main_page_scan['misconfigurations'])
            
            # Simple crawl to discover other pages
            discovered_urls = self.simple_crawl(url)
            scan_results['crawl_results'] = discovered_urls
            
            # Scan discovered pages
            for page_url in discovered_urls[:3]:  # Limit to 3 pages for performance
                try:
                    page_scan = self.scan_single_page(page_url)
                    scan_results['vulnerabilities'].extend(page_scan['vulnerabilities'])
                    scan_results['misconfigurations'].extend(page_scan['misconfigurations'])
                except:
                    continue
            
            # Calculate risk score
            scan_results['risk_score'] = self.calculate_risk_score(scan_results)
            
            # Generate security recommendations
            scan_results['recommendations'] = self.generate_security_recommendations(scan_results)
            
            return scan_results
            
        except Exception as e:
            scan_results['error'] = f"Scan failed: {str(e)}"
            return scan_results
    
    def scan_single_page(self, url):
        """Scan single page in detail"""
        results = {
            'url': url,
            'security_headers': {},
            'vulnerabilities': [],
            'misconfigurations': [],
            'forms_found': 0,
            'inputs_analyzed': 0
        }
        
        try:
            # Add URL validation
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            response = self.session.get(url, timeout=10, verify=False)
            content = response.text
            
            # Scan security headers
            results['security_headers'] = self.analyze_security_headers(response.headers)
            
            # Scan for vulnerabilities in content
            results['vulnerabilities'] = self.scan_for_vulnerabilities(content, url)
            
            # Check server misconfigurations
            results['misconfigurations'] = self.check_server_misconfigurations(response)
            
            # Analyze forms
            forms_analysis = self.analyze_forms(content, url)
            results['forms_found'] = forms_analysis['forms_count']
            results['inputs_analyzed'] = forms_analysis['inputs_analyzed']
            results['vulnerabilities'].extend(forms_analysis['form_vulnerabilities'])
            
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def analyze_security_headers(self, headers):
        """Analyze security headers in detail"""
        security_headers = {
            'Content-Security-Policy': {'present': False, 'value': '', 'score': 0},
            'X-Content-Type-Options': {'present': False, 'value': '', 'score': 0},
            'X-Frame-Options': {'present': False, 'value': '', 'score': 0},
            'Strict-Transport-Security': {'present': False, 'value': '', 'score': 0},
            'X-XSS-Protection': {'present': False, 'value': '', 'score': 0},
            'Referrer-Policy': {'present': False, 'value': '', 'score': 0},
            'Permissions-Policy': {'present': False, 'value': '', 'score': 0},
        }
        
        for header_name, header_info in security_headers.items():
            if header_name in headers:
                header_info['present'] = True
                header_info['value'] = headers[header_name]
                header_info['score'] = self.evaluate_header_strength(header_name, headers[header_name])
        
        return security_headers
    
    def evaluate_header_strength(self, header_name, header_value):
        """Evaluate security header strength"""
        score = 0
        
        if header_name == 'Content-Security-Policy':
            if 'default-src' in header_value and "'self'" in header_value:
                score = 8
            elif 'default-src' in header_value:
                score = 5
            else:
                score = 2
                
        elif header_name == 'Strict-Transport-Security':
            if 'max-age=31536000' in header_value and 'includeSubDomains' in header_value:
                score = 10
            elif 'max-age=31536000' in header_value:
                score = 7
            else:
                score = 3
                
        elif header_name == 'X-Frame-Options':
            if header_value.upper() == 'DENY':
                score = 10
            elif header_value.upper() == 'SAMEORIGIN':
                score = 7
            else:
                score = 3
                
        return score
    
    def scan_for_vulnerabilities(self, content, url):
        """Scan for vulnerabilities in content"""
        vulnerabilities = []
        
        # Scan SQL Injection patterns
        for pattern_name, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': pattern_name.upper(),
                        'description': f'Potential {pattern_name} vulnerability detected',
                        'risk': 'Medium',
                        'evidence': 'Pattern match in page content'
                    })
        
        # Scan sensitive comments
        sensitive_comments = self.find_sensitive_comments(content)
        vulnerabilities.extend(sensitive_comments)
        
        # Scan information leaks
        information_leaks = self.find_information_leaks(content)
        vulnerabilities.extend(information_leaks)
        
        return vulnerabilities
    
    def find_sensitive_comments(self, content):
        """Find sensitive comments in code"""
        sensitive_patterns = [
            (r'<!--\s*(TODO|FIXME|HACK).*?-->', 'Development comment found', 'Low'),
            (r'<!--\s*(password|secret|key|api).*?-->', 'Sensitive information in comment', 'High'),
            (r'//\s*(TODO|FIXME|HACK).*', 'Development comment found', 'Low'),
            (r'//\s*(password|secret|key|api).*', 'Sensitive information in comment', 'High'),
        ]
        
        findings = []
        for pattern, description, risk in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    'type': 'SENSITIVE_COMMENT',
                    'description': description,
                    'risk': risk,
                    'evidence': 'Found in page source'
                })
        
        return findings
    
    def find_information_leaks(self, content):
        """Find information leaks"""
        leaks_patterns = [
            (r'stack trace:', 'Stack trace exposed', 'Medium'),
            (r'database error', 'Database error exposed', 'High'),
            (r'syntax error', 'Syntax error exposed', 'Medium'),
            (r'api key', 'API key potentially exposed', 'Critical'),
            (r'password.*=', 'Password in source code', 'Critical'),
        ]
        
        findings = []
        for pattern, description, risk in leaks_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    'type': 'INFORMATION_LEAK',
                    'description': description,
                    'risk': risk,
                    'evidence': 'Found in page source'
                })
        
        return findings
    
    def check_server_misconfigurations(self, response):
        """Check server misconfigurations"""
        misconfigurations = []
        
        # Check Server header
        server_header = response.headers.get('Server', '')
        if server_header:
            misconfigurations.append({
                'type': 'SERVER_INFO',
                'description': f'Server information exposed: {server_header}',
                'risk': 'Low',
                'recommendation': 'Remove or obscure server header'
            })
        
        # Check directory listing
        if 'Index of /' in response.text:
            misconfigurations.append({
                'type': 'DIRECTORY_LISTING',
                'description': 'Directory listing enabled',
                'risk': 'Medium',
                'recommendation': 'Disable directory listing'
            })
        
        return misconfigurations
    
    def analyze_forms(self, content, url):
        """Analyze forms on page"""
        forms_analysis = {
            'forms_count': 0,
            'inputs_analyzed': 0,
            'form_vulnerabilities': []
        }
        
        # Find forms
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, content, re.IGNORECASE | re.DOTALL)
        forms_analysis['forms_count'] = len(forms)
        
        for form in forms:
            # Analyze input fields
            input_pattern = r'<input[^>]*>'
            inputs = re.findall(input_pattern, form, re.IGNORECASE)
            forms_analysis['inputs_analyzed'] += len(inputs)
            
            # Check password fields without SSL
            if url.startswith('http:'):
                for input_field in inputs:
                    if 'type="password"' in input_field.lower():
                        forms_analysis['form_vulnerabilities'].append({
                            'type': 'INSECURE_FORM',
                            'description': 'Password field without SSL',
                            'risk': 'High',
                            'evidence': 'Form contains password field on HTTP page'
                        })
                        break
        
        return forms_analysis
    
    def simple_crawl(self, base_url):
        """Simple crawl to discover pages"""
        discovered_urls = [base_url]
        
        try:
            response = self.session.get(base_url, timeout=10, verify=False)
            content = response.text
            
            # Find links in page
            link_pattern = r'href="([^"]*)"'
            links = re.findall(link_pattern, content, re.IGNORECASE)
            
            for link in links:
                # Convert relative links to absolute
                if link.startswith('/'):
                    full_url = base_url.rstrip('/') + link
                    discovered_urls.append(full_url)
                elif link.startswith('http') and base_url in link:
                    discovered_urls.append(link)
                    
        except Exception:
            pass
        
        return list(set(discovered_urls))  # Remove duplicates
    
    def calculate_risk_score(self, scan_results):
        """Calculate risk score"""
        score = 0
        
        # Points based on vulnerabilities
        risk_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1
        }
        
        for vulnerability in scan_results['vulnerabilities']:
            score += risk_weights.get(vulnerability['risk'], 0)
        
        # Points based on missing security headers
        security_headers = scan_results['security_headers']
        for header_info in security_headers.values():
            if not header_info['present']:
                score += 2
        
        return min(score, 100)  # Max 100
    
    def generate_security_recommendations(self, scan_results):
        """Generate security recommendations"""
        recommendations = []
        
        # Security header recommendations
        security_headers = scan_results['security_headers']
        
        if not security_headers['Content-Security-Policy']['present']:
            recommendations.append("Implement Content Security Policy (CSP) to prevent XSS attacks")
        
        if not security_headers['Strict-Transport-Security']['present']:
            recommendations.append("Enable HSTS to enforce HTTPS connections")
        
        if not security_headers['X-Frame-Options']['present']:
            recommendations.append("Set X-Frame-Options to prevent clickjacking")
        
        # Recommendations based on vulnerabilities
        vulnerabilities = scan_results['vulnerabilities']
        
        if any('SQL' in vuln['type'] for vuln in vulnerabilities):
            recommendations.append("Implement input validation and parameterized queries to prevent SQL injection")
        
        if any('XSS' in vuln['type'] for vuln in vulnerabilities):
            recommendations.append("Implement output encoding and input sanitization to prevent XSS")
        
        # General recommendations
        recommendations.extend([
            "Use strong Content Security Policy",
            "Disable directory listing",
            "Remove sensitive information from source code comments",
            "Implement proper error handling",
            "Use HTTPS exclusively",
            "Regularly update and patch software"
        ])
        
        return recommendations[:10]  # Return top 10 recommendations

# ==================== LOG ANALYZER ====================

class LogAnalyzer:
    def __init__(self):
        self.attack_patterns = {
            'sql_injection': [
                r"union.*select",
                r"select.*from",
                r"insert.*into",
                r"drop.*table",
                r"exec.*sp_",
                r"waitfor.*delay",
                r"';.*--",
            ],
            'xss': [
                r"<script>",
                r"javascript:",
                r"onload=",
                r"alert\(",
                r"document\.cookie",
            ],
            'brute_force': [
                r"Failed password",
                r"Authentication failure",
                r"Invalid user",
                r"Bad credentials",
            ],
            'directory_traversal': [
                r"\.\./",
                r"etc/passwd",
                r"win\.ini",
                r"boot\.ini",
            ],
            'command_injection': [
                r"\|\||&&",
                r";.*\w+",
                r"`.*`",
            ],
            'scanner_bots': [
                r"nmap",
                r"nikto",
                r"sqlmap",
                r"wpscan",
                r"burp",
                r"acunetix",
            ]
        }
    
    def analyze_logs(self, log_data):
        """Analyze system logs"""
        analysis_results = {
            'total_entries': 0,
            'attacks_detected': 0,
            'attack_types': {},
            'suspicious_ips': {},
            'timeline': [],
            'recommendations': []
        }
        
        lines = log_data.split('\n')
        analysis_results['total_entries'] = len(lines)
        
        for line in lines:
            if not line.strip():
                continue
                
            detected_attacks = self.analyze_single_line(line)
            
            for attack_type in detected_attacks:
                analysis_results['attacks_detected'] += 1
                analysis_results['attack_types'][attack_type] = analysis_results['attack_types'].get(attack_type, 0) + 1
                
                # Extract IP
                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                if ip_match:
                    ip = ip_match.group()
                    if ip not in analysis_results['suspicious_ips']:
                        analysis_results['suspicious_ips'][ip] = []
                    analysis_results['suspicious_ips'][ip].append(attack_type)
        
        # Generate recommendations
        analysis_results['recommendations'] = self.generate_log_recommendations(analysis_results)
        
        return analysis_results
    
    def analyze_single_line(self, log_line):
        """Analyze single log line"""
        detected_attacks = []
        
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, log_line, re.IGNORECASE):
                    detected_attacks.append(attack_type)
                    break
        
        return detected_attacks
    
    def generate_log_recommendations(self, analysis_results):
        """Generate recommendations based on log analysis"""
        recommendations = []
        
        if analysis_results['attack_types'].get('sql_injection', 0) > 0:
            recommendations.append("Implement WAF (Web Application Firewall) to block SQL injection attempts")
        
        if analysis_results['attack_types'].get('brute_force', 0) > 0:
            recommendations.append("Implement rate limiting and account lockout policies")
        
        if analysis_results['attack_types'].get('scanner_bots', 0) > 0:
            recommendations.append("Block known scanner IPs and user agents")
        
        if analysis_results['attacks_detected'] > 100:
            recommendations.append("Consider implementing IPS (Intrusion Prevention System)")
        
        # General recommendations
        recommendations.extend([
            "Monitor logs regularly for suspicious activities",
            "Implement automated alerting for critical events",
            "Use SIEM (Security Information and Event Management) system",
            "Regularly update firewall rules",
            "Implement fail2ban for automated IP blocking"
        ])
        
        return recommendations[:8]

# ==================== PDF REPORT GENERATOR ====================

class PDFReportGenerator:
    def __init__(self):
        self.report_data = {}
    
    def generate_website_security_report(self, scan_results, output_path="security_report.pdf"):
        """Generate website security report in PDF format"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Report title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=30,
                textColor=colors.darkblue,
                alignment=1
            )
            
            story.append(Paragraph("Website Security Assessment Report", title_style))
            story.append(Spacer(1, 20))
            
            # Basic information
            story.append(Paragraph(f"<b>Scanned URL:</b> {scan_results['url']}", styles['Normal']))
            story.append(Paragraph(f"<b>Scan Date:</b> {scan_results['timestamp']}", styles['Normal']))
            story.append(Paragraph(f"<b>Risk Score:</b> {scan_results['risk_score']}/100", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Security summary
            story.append(Paragraph("<b>Security Summary</b>", styles['Heading2']))
            
            # Security headers table
            headers_data = [['Security Header', 'Status', 'Score']]
            for header_name, header_info in scan_results['security_headers'].items():
                status = "Present" if header_info['present'] else "Missing"
                color = colors.green if header_info['present'] else colors.red
                headers_data.append([header_name, status, str(header_info['score'])])
            
            headers_table = Table(headers_data, colWidths=[2*inch, 1.5*inch, 1*inch])
            headers_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(headers_table)
            story.append(Spacer(1, 20))
            
            # Detected vulnerabilities
            if scan_results['vulnerabilities']:
                story.append(Paragraph("<b>Detected Vulnerabilities</b>", styles['Heading2']))
                
                vuln_data = [['Type', 'Description', 'Risk']]
                for vuln in scan_results['vulnerabilities'][:10]:
                    vuln_data.append([vuln['type'], vuln['description'], vuln['risk']])
                
                vuln_table = Table(vuln_data, colWidths=[1.5*inch, 3*inch, 1*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('WORDWRAP', (1, 1), (1, -1), True)
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 20))
            
            # Recommendations
            story.append(Paragraph("<b>Security Recommendations</b>", styles['Heading2']))
            for i, recommendation in enumerate(scan_results['recommendations'][:8], 1):
                story.append(Paragraph(f"{i}. {recommendation}", styles['Normal']))
            
            # Report footer
            story.append(Spacer(1, 30))
            story.append(Paragraph("<i>Generated by Nano Solver v2 - Advanced Security Toolkit</i>", styles['Italic']))
            
            doc.build(story)
            return f"PDF report generated: {output_path}"
            
        except ImportError:
            return "PDF generation requires reportlab library: pip install reportlab"
        except Exception as e:
            return f"PDF generation failed: {str(e)}"
    
    def generate_log_analysis_report(self, log_analysis, output_path="log_analysis_report.pdf"):
        """Generate log analysis report in PDF format"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Report title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=30,
                textColor=colors.darkred,
                alignment=1
            )
            
            story.append(Paragraph("Log Analysis Security Report", title_style))
            story.append(Spacer(1, 20))
            
            # Analysis summary
            story.append(Paragraph("<b>Analysis Summary</b>", styles['Heading2']))
            story.append(Paragraph(f"<b>Total Log Entries:</b> {log_analysis['total_entries']}", styles['Normal']))
            story.append(Paragraph(f"<b>Attacks Detected:</b> {log_analysis['attacks_detected']}", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Attack types
            if log_analysis['attack_types']:
                story.append(Paragraph("<b>Attack Types Detected</b>", styles['Heading2']))
                
                attack_data = [['Attack Type', 'Count']]
                for attack_type, count in log_analysis['attack_types'].items():
                    attack_data.append([attack_type.upper(), str(count)])
                
                attack_table = Table(attack_data, colWidths=[3*inch, 1*inch])
                attack_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(attack_table)
                story.append(Spacer(1, 20))
            
            # Recommendations
            story.append(Paragraph("<b>Security Recommendations</b>", styles['Heading2']))
            for i, recommendation in enumerate(log_analysis['recommendations'], 1):
                story.append(Paragraph(f"{i}. {recommendation}", styles['Normal']))
            
            doc.build(story)
            return f"Log analysis PDF report generated: {output_path}"
            
        except ImportError:
            return "PDF generation requires reportlab library"
        except Exception as e:
            return f"PDF generation failed: {str(e)}"

# ==================== AUTO SCANNER ====================

class AutoScanner:
    def __init__(self):
        self.website_scanner = AdvancedWebsiteScanner()
        self.log_analyzer = LogAnalyzer()
        self.pdf_generator = PDFReportGenerator()
    
    def auto_scan_website(self, url):
        """Comprehensive automatic website scan"""
        # Step 1: Deep website scan
        scan_results = self.website_scanner.deep_scan_website(url)
        
        # Step 2: Generate PDF report
        pdf_result = self.pdf_generator.generate_website_security_report(scan_results)
        
        # Step 3: Generate hardening recommendations
        hardening_tips = self.generate_auto_hardening_tips(scan_results)
        
        return {
            'scan_results': scan_results,
            'pdf_report': pdf_result,
            'hardening_tips': hardening_tips,
            'risk_level': self.get_risk_level(scan_results['risk_score'])
        }
    
    def generate_auto_hardening_tips(self, scan_results):
        """Generate automatic security hardening tips"""
        tips = []
        
        # Tips based on missing security headers
        security_headers = scan_results['security_headers']
        
        if not security_headers['Content-Security-Policy']['present']:
            tips.append("🔒 Use strong Content Security Policy to prevent XSS attacks")
        
        if not security_headers['Strict-Transport-Security']['present']:
            tips.append("🔒 Enable HSTS to force HTTPS connections")
        
        if not security_headers['X-Frame-Options']['present']:
            tips.append("🔒 Set X-Frame-Options to DENY or SAMEORIGIN")
        
        # Tips based on vulnerabilities
        vulnerabilities = scan_results['vulnerabilities']
        
        if any('SQL' in vuln['type'] for vuln in vulnerabilities):
            tips.append("🛡️ Implement parameterized queries and input validation")
        
        if any('XSS' in vuln['type'] for vuln in vulnerabilities):
            tips.append("🛡️ Enable output encoding and input sanitization")
        
        # General tips
        tips.extend([
            "🚫 Disable directory listing in server configuration",
            "📝 Remove sensitive information from source code comments",
            "🔑 Implement proper authentication and session management",
            "📊 Regular security audits and penetration testing",
            "🔄 Keep all software and dependencies updated",
            "📋 Implement proper logging and monitoring",
            "🌐 Use Web Application Firewall (WAF)",
            "🔍 Regular vulnerability scanning"
        ])
        
        return tips
    
    def get_risk_level(self, risk_score):
        """Determine risk level"""
        if risk_score >= 80:
            return "🔴 CRITICAL"
        elif risk_score >= 60:
            return "🟠 HIGH"
        elif risk_score >= 40:
            return "🟡 MEDIUM"
        elif risk_score >= 20:
            return "🔵 LOW"
        else:
            return "🟢 INFO"

# ==================== BEHAVIOR ANALYZER ====================

class BehaviorAnalyzer:
    def __init__(self):
        self.process_monitor = ProcessMonitor()
        self.file_activity_monitor = FileActivityMonitor()
        self.network_activity_monitor = NetworkActivityMonitor()
        self.system_activity_monitor = SystemActivityMonitor()
        self.suspicious_behaviors = []
        self.behavior_log = []
        self.analysis_start_time = time.time()
        
    def start_continuous_monitoring(self):
        """Start continuous behavior monitoring"""
        # Monitor processes every 10 seconds
        Clock.schedule_interval(lambda dt: self.monitor_process_behavior(), 10)
        # Monitor file activity every 15 seconds
        Clock.schedule_interval(lambda dt: self.monitor_file_activity(), 15)
        # Monitor network activity every 20 seconds
        Clock.schedule_interval(lambda dt: self.monitor_network_activity(), 20)
        # Monitor system activity every 30 seconds
        Clock.schedule_interval(lambda dt: self.monitor_system_activity(), 30)
        
    def monitor_process_behavior(self):
        """Monitor process behavior"""
        try:
            current_processes = self.process_monitor.get_running_processes()
            suspicious_processes = self.process_monitor.detect_suspicious_processes(current_processes)
            
            for process_info in suspicious_processes:
                behavior = {
                    'timestamp': time.time(),
                    'type': 'suspicious_process',
                    'process_name': process_info['name'],
                    'pid': process_info['pid'],
                    'behavior': process_info['suspicious_reason'],
                    'risk_level': process_info['risk_level']
                }
                self.log_behavior(behavior)
                
        except Exception as e:
            print(f"Process monitoring error: {e}")
    
    def monitor_file_activity(self):
        """Monitor file activity"""
        try:
            suspicious_files = self.file_activity_monitor.detect_suspicious_file_activity()
            
            for file_activity in suspicious_files:
                behavior = {
                    'timestamp': time.time(),
                    'type': 'suspicious_file_activity',
                    'file_path': file_activity['file_path'],
                    'activity_type': file_activity['activity_type'],
                    'behavior': file_activity['suspicious_reason'],
                    'risk_level': file_activity['risk_level']
                }
                self.log_behavior(behavior)
                
        except Exception as e:
            print(f"File activity monitoring error: {e}")
    
    def monitor_network_activity(self):
        """Monitor network activity"""
        try:
            suspicious_connections = self.network_activity_monitor.detect_suspicious_connections()
            
            for connection in suspicious_connections:
                behavior = {
                    'timestamp': time.time(),
                    'type': 'suspicious_network',
                    'remote_address': connection['remote_address'],
                    'port': connection['port'],
                    'behavior': connection['suspicious_reason'],
                    'risk_level': connection['risk_level']
                }
                self.log_behavior(behavior)
                
        except Exception as e:
            print(f"Network monitoring error: {e}")
    
    def monitor_system_activity(self):
        """Monitor system activity"""
        try:
            system_anomalies = self.system_activity_monitor.detect_system_anomalies()
            
            for anomaly in system_anomalies:
                behavior = {
                    'timestamp': time.time(),
                    'type': 'system_anomaly',
                    'anomaly_type': anomaly['anomaly_type'],
                    'behavior': anomaly['description'],
                    'risk_level': anomaly['risk_level']
                }
                self.log_behavior(behavior)
                
        except Exception as e:
            print(f"System monitoring error: {e}")
    
    def log_behavior(self, behavior_info):
        """Log suspicious behavior"""
        self.behavior_log.append(behavior_info)
        
        # If risk level is high, add to main list
        if behavior_info['risk_level'] in ['high', 'critical']:
            self.suspicious_behaviors.append(behavior_info)
            print(f"[BEHAVIOR ALERT] {behavior_info['behavior']} - Risk: {behavior_info['risk_level']}")
    
    def analyze_behavior_patterns(self):
        """Analyze behavior patterns for advanced attack detection"""
        patterns = self.detect_behavior_patterns()
        return patterns
    
    def detect_behavior_patterns(self):
        """Detect suspicious behavior patterns"""
        patterns = []
        
        # Pattern: Rapid process creation
        rapid_process_creation = self.detect_rapid_process_creation()
        if rapid_process_creation:
            patterns.append(rapid_process_creation)
        
        # Pattern: Access to sensitive system files
        system_file_access = self.detect_system_file_access()
        if system_file_access:
            patterns.append(system_file_access)
        
        # Pattern: Unusual network patterns
        unusual_network_patterns = self.detect_unusual_network_patterns()
        if unusual_network_patterns:
            patterns.append(unusual_network_patterns)
        
        return patterns
    
    def detect_rapid_process_creation(self):
        """Detect rapid and repeated process creation"""
        recent_processes = [b for b in self.behavior_log 
                          if b['type'] == 'suspicious_process' 
                          and time.time() - b['timestamp'] < 60]
        
        if len(recent_processes) > 5:
            return {
                'pattern': 'rapid_process_creation',
                'description': f'{len(recent_processes)} suspicious processes created in the last minute',
                'risk_level': 'high',
                'processes': recent_processes
            }
        return None
    
    def detect_system_file_access(self):
        """Detect access to sensitive system files"""
        system_files_accessed = [b for b in self.behavior_log 
                               if b['type'] == 'suspicious_file_activity'
                               and any(keyword in b.get('file_path', '').lower() 
                                      for keyword in ['/etc/', '/system/', '/windows/system32', 'passwd', 'shadow'])]
        
        if system_files_accessed:
            return {
                'pattern': 'system_file_access',
                'description': f'Accessed {len(system_files_accessed)} sensitive system files',
                'risk_level': 'high',
                'accessed_files': system_files_accessed
            }
        return None
    
    def detect_unusual_network_patterns(self):
        """Detect unusual network patterns"""
        unusual_connections = [b for b in self.behavior_log 
                             if b['type'] == 'suspicious_network'
                             and b['risk_level'] in ['high', 'critical']]
        
        if len(unusual_connections) > 3:
            return {
                'pattern': 'unusual_network_activity',
                'description': f'Detected {len(unusual_connections)} unusual network connections',
                'risk_level': 'medium',
                'connections': unusual_connections
            }
        return None
    
    def get_behavior_report(self):
        """Comprehensive behavior analysis report"""
        report = []
        report.append("=== BEHAVIOR ANALYSIS REPORT ===")
        report.append(f"Monitoring duration: {int(time.time() - self.analysis_start_time)} seconds")
        report.append(f"Total behaviors logged: {len(self.behavior_log)}")
        report.append(f"Suspicious behaviors: {len(self.suspicious_behaviors)}")
        
        # Detected patterns
        patterns = self.analyze_behavior_patterns()
        if patterns:
            report.append("\nDetected Behavior Patterns:")
            for pattern in patterns:
                report.append(f"- {pattern['pattern']}: {pattern['description']} (Risk: {pattern['risk_level']})")
        
        # Recent suspicious behaviors
        recent_suspicious = [b for b in self.suspicious_behaviors 
                           if time.time() - b['timestamp'] < 300]
        
        if recent_suspicious:
            report.append("\nRecent Suspicious Activities (last 5 minutes):")
            for activity in recent_suspicious[-10:]:
                timestamp = datetime.datetime.fromtimestamp(activity['timestamp']).strftime('%H:%M:%S')
                report.append(f"- {timestamp} [{activity['type']}] {activity['behavior']} (Risk: {activity['risk_level']})")
        
        return "\n".join(report)

class ProcessMonitor:
    def __init__(self):
        self.process_history = []
        self.known_malicious_patterns = [
            'cryptominer', 'miner', 'coin', 'bitcoin', 'monero', 'xmrig', 'ccminer',
            'keylogger', 'spy', 'trojan', 'backdoor', 'rootkit', 'ransomware'
        ]
    
    def get_running_processes(self):
        """Get list of running processes"""
        processes = []
        try:
            if psutil:
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cpu_percent': proc.info['cpu_percent'],
                            'memory_percent': proc.info['memory_percent']
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            else:
                # Fallback without psutil
                if platform.system() == "Windows":
                    try:
                        output = subprocess.check_output(["tasklist", "/fo", "csv"], text=True, timeout=5)
                        for line in output.splitlines()[1:]:
                            parts = line.split(',')
                            if len(parts) >= 2:
                                processes.append({
                                    'pid': int(parts[1].strip('"')),
                                    'name': parts[0].strip('"'),
                                    'cpu_percent': 0,
                                    'memory_percent': 0
                                })
                    except:
                        pass
        except Exception as e:
            print(f"Process monitoring error: {e}")
        
        self.process_history.append({
            'timestamp': time.time(),
            'processes': processes
        })
        
        # Keep history for last 10 minutes only
        self.process_history = [h for h in self.process_history 
                              if time.time() - h['timestamp'] < 600]
        
        return processes
    
    def detect_suspicious_processes(self, processes):
        """Detect suspicious processes"""
        suspicious = []
        
        for process in processes:
            process_name = process['name'].lower()
            
            # Detect known malware patterns
            for pattern in self.known_malicious_patterns:
                if pattern in process_name:
                    suspicious.append({
                        **process,
                        'suspicious_reason': f'Process name matches malware pattern: {pattern}',
                        'risk_level': 'high'
                    })
                    break
            
            # Detect abnormal resource consumption
            if process.get('cpu_percent', 0) > 80.0:
                suspicious.append({
                    **process,
                    'suspicious_reason': f'High CPU usage: {process["cpu_percent"]}%',
                    'risk_level': 'medium'
                })
            
            if process.get('memory_percent', 0) > 50.0:
                suspicious.append({
                    **process,
                    'suspicious_reason': f'High memory usage: {process["memory_percent"]}%',
                    'risk_level': 'medium'
                })
        
        return suspicious

class FileActivityMonitor:
    def __init__(self):
        self.recent_file_activities = []
        self.suspicious_locations = [
            '/etc/passwd', '/etc/shadow', '/windows/system32', 
            '/etc/hosts', 'C:\\Windows\\System32'
        ]
    
    def detect_suspicious_file_activity(self):
        """Detect suspicious file activity"""
        suspicious_activities = []
        
        try:
            # Simulate file activity monitoring
            current_time = time.time()
            
            # Check recently created temporary files
            temp_dirs = ['/tmp', '/var/tmp', 'C:\\Windows\\Temp']
            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    try:
                        for file in os.listdir(temp_dir):
                            file_path = os.path.join(temp_dir, file)
                            if os.path.isfile(file_path):
                                file_time = os.path.getctime(file_path)
                                if current_time - file_time < 60:
                                    # Check if it's an executable file
                                    if self.is_executable_file(file_path):
                                        suspicious_activities.append({
                                            'file_path': file_path,
                                            'activity_type': 'recent_executable_in_temp',
                                            'suspicious_reason': 'Recent executable file in temp directory',
                                            'risk_level': 'high'
                                        })
                    except:
                        pass
            
            # Check changes to important system files
            for sys_file in self.suspicious_locations:
                if os.path.exists(sys_file):
                    try:
                        # Check if file was recently modified
                        mod_time = os.path.getmtime(sys_file)
                        if current_time - mod_time < 300:
                            suspicious_activities.append({
                                'file_path': sys_file,
                                'activity_type': 'system_file_modified',
                                'suspicious_reason': 'Sensitive system file recently modified',
                                'risk_level': 'critical'
                            })
                    except:
                        pass
        
        except Exception as e:
            print(f"File activity monitoring error: {e}")
        
        return suspicious_activities
    
    def is_executable_file(self, file_path):
        """Check if file is executable"""
        executable_extensions = ['.exe', '.bat', '.cmd', '.sh', '.bin', '.app', '.scr']
        file_ext = os.path.splitext(file_path)[1].lower()
        return file_ext in executable_extensions

class NetworkActivityMonitor:
    def __init__(self):
        self.known_suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337]
        self.known_c2_servers = []
    
    def detect_suspicious_connections(self):
        """Detect suspicious network connections"""
        suspicious_connections = []
        
        try:
            if psutil:
                connections = psutil.net_connections()
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        remote_ip, remote_port = conn.raddr
                        
                        # Check suspicious ports
                        if remote_port in self.known_suspicious_ports:
                            suspicious_connections.append({
                                'remote_address': remote_ip,
                                'port': remote_port,
                                'suspicious_reason': f'Connection to suspicious port: {remote_port}',
                                'risk_level': 'high'
                            })
                        
                        # Check external connections on unusual ports
                        if remote_port > 49152 and not self.is_private_ip(remote_ip):
                            suspicious_connections.append({
                                'remote_address': remote_ip,
                                'port': remote_port,
                                'suspicious_reason': f'External connection to random port: {remote_port}',
                                'risk_level': 'medium'
                            })
            
            else:
                # Fallback without psutil
                if platform.system() == "Windows":
                    try:
                        output = subprocess.check_output(["netstat", "-an"], text=True, timeout=5)
                        for line in output.splitlines():
                            if "ESTABLISHED" in line:
                                parts = line.split()
                                if len(parts) >= 3:
                                    remote_addr = parts[2]
                                    if ':' in remote_addr:
                                        ip, port = remote_addr.rsplit(':', 1)
                                        port = int(port)
                                        
                                        if port in self.known_suspicious_ports:
                                            suspicious_connections.append({
                                                'remote_address': ip,
                                                'port': port,
                                                'suspicious_reason': f'Connection to suspicious port: {port}',
                                                'risk_level': 'high'
                                            })
                    except:
                        pass
        
        except Exception as e:
            print(f"Network monitoring error: {e}")
        
        return suspicious_connections
    
    def is_private_ip(self, ip):
        """Check if IP is private"""
        private_ranges = [
            ('10.', True),
            ('192.168.', True),
            ('172.16.', True), ('172.17.', True), ('172.18.', True), ('172.19.', True),
            ('172.20.', True), ('172.21.', True), ('172.22.', True), ('172.23.', True),
            ('172.24.', True), ('172.25.', True), ('172.26.', True), ('172.27.', True),
            ('172.28.', True), ('172.29.', True), ('172.30.', True), ('172.31.', True),
            ('127.', True)
        ]
        return any(ip.startswith(prefix) for prefix, is_private in private_ranges)

class SystemActivityMonitor:
    def __init__(self):
        self.normal_cpu_usage = 30.0
        self.normal_memory_usage = 60.0
    
    def detect_system_anomalies(self):
        """Detect system anomalies"""
        anomalies = []
        
        try:
            if psutil:
                # Check CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > 90.0:
                    anomalies.append({
                        'anomaly_type': 'high_cpu_usage',
                        'description': f'Very high CPU usage: {cpu_percent}%',
                        'risk_level': 'medium'
                    })
                
                # Check memory usage
                memory = psutil.virtual_memory()
                if memory.percent > 90.0:
                    anomalies.append({
                        'anomaly_type': 'high_memory_usage',
                        'description': f'Very high memory usage: {memory.percent}%',
                        'risk_level': 'medium'
                    })
                
                # Check disk usage
                disk = psutil.disk_usage('/')
                if disk.percent > 95.0:
                    anomalies.append({
                        'anomaly_type': 'low_disk_space',
                        'description': f'Low disk space: {disk.percent}% used',
                        'risk_level': 'low'
                    })
            
        except Exception as e:
            print(f"System monitoring error: {e}")
        
        return anomalies

# ==================== SECURITY MONITOR ====================

class SecurityMonitor:
    def __init__(self):
        self.failed_attempts = defaultdict(int)
        self.last_attempt = defaultdict(float)
        self.suspicious_activities = []
        self.command_history = []
        # Add behavior analyzer
        self.behavior_analyzer = BehaviorAnalyzer()
        
    def log_activity(self, user_action, success=True):
        """Log user activity"""
        timestamp = time.time()
        self.command_history.append({
            'action': user_action,
            'timestamp': timestamp,
            'success': success
        })
        
        if not success:
            self.failed_attempts[user_action] += 1
            self.last_attempt[user_action] = timestamp
            
        # Detect intrusion attempts
        if self.failed_attempts[user_action] > 5:
            self.suspicious_activities.append({
                'action': user_action,
                'timestamp': timestamp,
                'attempts': self.failed_attempts[user_action],
                'type': 'brute_force'
            })
    
    def check_brute_force(self, user_action):
        """Detect brute force attacks"""
        current_time = time.time()
        if (current_time - self.last_attempt.get(user_action, 0)) < 60:
            if self.failed_attempts[user_action] > 3:
                return True
        return False
    
    def get_security_report(self):
        """Security report"""
        report = []
        report.append("=== SECURITY REPORT ===")
        report.append(f"Total commands executed: {len(self.command_history)}")
        report.append(f"Failed attempts: {sum(self.failed_attempts.values())}")
        report.append(f"Suspicious activities: {len(self.suspicious_activities)}")
        
        if self.suspicious_activities:
            report.append("\nSuspicious Activities:")
            for activity in self.suspicious_activities[-5:]:
                report.append(f"- {activity['action']} ({activity['type']})")
        
        return "\n".join(report)
    
    def start_behavior_monitoring(self):
        """Start behavior monitoring"""
        self.behavior_analyzer.start_continuous_monitoring()
        return "Behavior monitoring started"
    
    def get_behavior_report(self):
        """Get behavior analysis report"""
        return self.behavior_analyzer.get_behavior_report()

class SecurityUpdates:
    def __init__(self):
        self.last_update_check = None
        self.vulnerability_db = {}
        self.known_threats = [
            'cryptominer', 'keylogger', 'ransomware', 'trojan', 
            'backdoor', 'rootkit', 'spyware', 'adware'
        ]
    
    def check_for_updates(self):
        """Check for security updates"""
        if (self.last_update_check and 
            datetime.datetime.now() - self.last_update_check < datetime.timedelta(hours=24)):
            return
        
        try:
            # Local database of known threats
            self.vulnerability_db = {
                'threats': self.known_threats,
                'last_updated': datetime.datetime.now().isoformat()
            }
            self.last_update_check = datetime.datetime.now()
        except Exception as e:
            print(f"Security update check failed: {e}")
    
    def check_vulnerability(self, component, version):
        """Check for vulnerabilities"""
        self.check_for_updates()
        return component in self.vulnerability_db.get('threats', [])

# ==================== SECURITY FUNCTIONS ====================

def sanitize_input(user_input):
    """Sanitize and validate user input"""
    if not user_input:
        return ""
    
    # Remove dangerous characters
    sanitized = html.escape(user_input)
    # Remove injection attempts
    sanitized = re.sub(r'[;|&$`\\]', '', sanitized)
    # Prevent command injection
    sanitized = re.sub(r'\b(rm|del|format|shutdown|reboot|mkfs)\b', '[BLOCKED]', sanitized, flags=re.IGNORECASE)
    
    return sanitized.strip()

def validate_url(url):
    """Validate URL safety"""
    if not url:
        return False
        
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except:
        return False

def check_file_permissions(file_path):
    """Check file permissions for safety"""
    try:
        if not os.path.exists(file_path):
            return False
            
        file_stat = os.stat(file_path)
        # Check that file doesn't have dangerous execute permissions
        if file_stat.st_mode & (stat.S_IXGRP | stat.S_IXOTH):
            return False
        return True
    except:
        return False

def is_safe_directory(directory):
    """Check if directory is safe to access"""
    safe_dirs = [
        os.path.expanduser("~"),
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/Desktop"),
        ".",
        "temp_images"
    ]
    
    try:
        abs_directory = os.path.abspath(directory)
        return any(abs_directory.startswith(os.path.abspath(safe_dir)) for safe_dir in safe_dirs)
    except:
        return False

def generate_secure_token(length=32):
    """Generate secure token"""
    return secrets.token_hex(length)

def hash_sensitive_data(data, salt=None):
    """Hash sensitive data"""
    if salt is None:
        salt = secrets.token_bytes(16)
    return hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000)

def create_secure_context():
    """Create secure SSL context"""
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context

def is_safe_port(port):
    """Check if port is safe to use"""
    unsafe_ports = [1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 
                   53, 69, 77, 79, 87, 95, 101, 102, 103, 104, 109, 110, 111, 
                   113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389]
    return port not in unsafe_ports and 1024 <= port <= 65535

def validate_domain(domain):
    """Validate domain"""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def safe_system_command(cmd):
    """Execute system commands safely"""
    allowed_commands = ['ls', 'pwd', 'whoami', 'date', 'ping', 'netstat', 'tasklist']
    dangerous_patterns = [
        r'rm\s+-rf',
        r'del\s+\*',
        r'format\s+',
        r'mkfs',
        r'shutdown',
        r'reboot',
        r'passwd',
        r'chmod\s+777',
        r'chown\s+root',
        r'wget\s.*\|\s*sh',
        r'curl\s.*\|\s*sh',
        r'nc\s+-e',
        r'python\s+-c',
        r'perl\s+-e',
        r'bash\s+-i',
        r'>\s*/dev',
        r'2>&1',
    ]
    
    if not cmd:
        return False, "Empty command"
    
    cmd_base = cmd.split()[0] if cmd else ''
    
    # Check allowed commands
    if cmd_base not in allowed_commands:
        return False, f"Command '{cmd_base}' not allowed"
    
    # Check dangerous patterns
    for pattern in dangerous_patterns:
        if re.search(pattern, cmd, re.IGNORECASE):
            return False, f"Dangerous pattern detected: {pattern}"
    
    # Check allowed characters only
    safe_pattern = r'^[a-zA-Z0-9\s\./_ -]+$'
    if not re.match(safe_pattern, cmd):
        return False, "Invalid characters in command"
    
    return True, "Command is safe"

def sanitize_file_path(file_path):
    """Sanitize file paths"""
    if not file_path:
        return None
        
    # Prevent directory traversal
    if '..' in file_path or file_path.startswith('/') or file_path.startswith('\\'):
        return None
        
    # Only allow specific base paths
    safe_base = os.path.expanduser('~')
    try:
        full_path = os.path.abspath(os.path.join(safe_base, file_path))
        if not full_path.startswith(safe_base):
            return None
        return full_path
    except:
        return None

def detect_malicious_patterns(text):
    """Detect malicious patterns"""
    malicious_patterns = [
        r'<script.*?>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'onload=',
        r'onerror=',
        r'eval\(',
        r'exec\(',
        r'base64_decode\(',
        r'from_char_code\(',
        r'document\.cookie',
        r'window\.location',
    ]
    
    for pattern in malicious_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True, pattern
            
    return False, None

# ==================== UI WIDGETS ====================

KV = '''
<LoadingWidget>:
    size_hint_y: None
    height: dp(60)
    padding: dp(12)
    canvas.before:
        Color:
            rgba: (0.15, 0.25, 0.42, 0.8)
        RoundedRectangle:
            pos: self.pos[0] + dp(5), self.pos[1] + dp(5)
            size: self.size[0] - dp(10), self.size[1] - dp(10)
            radius: [dp(15),]
        Color:
            rgba: (0.12, 0.22, 0.38, 1)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(15),]

    BoxLayout:
        orientation: 'horizontal'
        spacing: dp(15)
        padding: dp(10)
        
        BoxLayout:
            size_hint_x: 0.2
            canvas:
                Color:
                    rgba: (0.4, 0.8, 1, 1)
                Line:
                    circle: (self.center_x, self.center_y, dp(12), 0, root.loading_angle)
                    width: dp(2)
                    
        Label:
            text: root.loading_text
            font_size: '14sp'
            color: (0.9, 0.95, 1, 1)
            text_size: self.width, None
            halign: 'left'
            valign: 'middle'

<MediaWidget>:
    size_hint_y: None
    height: dp(300)
    padding: dp(12)
    canvas.before:
        Color:
            rgba: (0.15, 0.25, 0.42, 0.8)
        RoundedRectangle:
            pos: self.pos[0] + dp(5), self.pos[1] + dp(5)
            size: self.size[0] - dp(10), self.size[1] - dp(10)
            radius: [dp(15),]
        Color:
            rgba: (0.12, 0.22, 0.38, 1)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(15),]

    BoxLayout:
        orientation: 'vertical'
        spacing: dp(10)
        padding: dp(10)
        
        Label:
            text: root.media_title
            font_size: '14sp'
            color: (0.9, 0.95, 1, 1)
            text_size: self.width, None
            halign: 'center'
            valign: 'middle'
            size_hint_y: None
            height: dp(30)
            
        Image:
            id: media_content
            source: root.media_path
            allow_stretch: True
            keep_ratio: True
            size_hint_y: 0.8
            
        BoxLayout:
            orientation: 'horizontal'
            size_hint_y: None
            height: dp(40)
            spacing: dp(10)
            
            Button:
                text: "Open Link"
                font_size: '12sp'
                background_normal: ''
                background_color: (0.2, 0.6, 0.3, 1)
                color: (1, 1, 1, 1)
                on_release: root.open_link()
                
            Button:
                text: "Image Info"
                font_size: '12sp'
                background_normal: ''
                background_color: (0.8, 0.2, 0.2, 1)
                color: (1, 1, 1, 1)
                on_release: root.show_image_info()

<AudioControlWidget>:
    size_hint_y: None
    height: dp(120)
    padding: dp(12)
    canvas.before:
        Color:
            rgba: (0.15, 0.25, 0.42, 0.8)
        RoundedRectangle:
            pos: self.pos[0] + dp(5), self.pos[1] + dp(5)
            size: self.size[0] - dp(10), self.size[1] - dp(10)
            radius: [dp(15),]
        Color:
            rgba: (0.12, 0.22, 0.38, 1)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(15),]

    BoxLayout:
        orientation: 'vertical'
        spacing: dp(8)
        padding: dp(10)
        
        Label:
            text: root.audio_title
            font_size: '14sp'
            color: (0.9, 0.95, 1, 1)
            text_size: self.width, None
            halign: 'center'
            valign: 'middle'
            size_hint_y: None
            height: dp(25)
            
        BoxLayout:
            orientation: 'horizontal'
            size_hint_y: None
            height: dp(40)
            spacing: dp(10)
            
            Button:
                text: "Play" if not root.is_playing else "Pause"
                font_size: '12sp'
                background_normal: ''
                background_color: (0.2, 0.6, 0.3, 1) if not root.is_playing else (0.8, 0.6, 0.1, 1)
                color: (1, 1, 1, 1)
                on_release: root.toggle_play()
                
            Button:
                text: "Stop"
                font_size: '12sp'
                background_normal: ''
                background_color: (0.8, 0.2, 0.2, 1)
                color: (1, 1, 1, 1)
                on_release: root.stop_audio()
                
            Button:
                text: "Volume +"
                font_size: '11sp'
                background_normal: ''
                background_color: (0.3, 0.4, 0.7, 1)
                color: (1, 1, 1, 1)
                on_release: root.volume_up()
                
            Button:
                text: "Volume -"
                font_size: '11sp'
                background_normal: ''
                background_color: (0.3, 0.4, 0.7, 1)
                color: (1, 1, 1, 1)
                on_release: root.volume_down()
        
        Label:
            text: f"Volume: {int(root.audio_volume * 100)}%"
            font_size: '11sp'
            color: (0.8, 0.9, 1, 1)
            text_size: self.width, None
            halign: 'center'
            valign: 'middle'

<ClickableLabel>:
    size_hint_y: None
    height: self.texture_size[1] + dp(10)
    font_size: '14.5sp'
    markup: True
    text_size: self.width - dp(20), None
    halign: 'right' if root.is_user else 'left'
    valign: 'top'
    color: (0.95, 0.97, 1, 1) if root.is_user else (0.95, 0.95, 0.95, 1)
    padding: [dp(10), dp(5)]
    on_ref_press: root.open_link(args[1])
    on_touch_down: 
        if self.collide_point(*args[1].pos): root.on_label_touch_down(args[1])
    on_touch_up: 
        if self.collide_point(*args[1].pos): root.on_label_touch_up(args[1])

<ChatRow>:
    size_hint_y: None
    height: self.minimum_height + dp(25)
    padding: [dp(15), dp(10)]
    canvas.before:
        Color:
            rgba: root.user_color if root.is_user else (0.15, 0.25, 0.42, 1)
        RoundedRectangle:
            pos: self.pos[0] + dp(5), self.pos[1] + dp(5)
            size: self.size[0] - dp(10), self.size[1] - dp(10)
            radius: [dp(20), dp(20), dp(20), dp(5)] if root.is_user else [dp(20), dp(20), dp(5), dp(20)]
        Color:
            rgba: root.user_color if root.is_user else (0.12, 0.22, 0.38, 1)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(20), dp(20), dp(20), dp(5)] if root.is_user else [dp(20), dp(20), dp(5), dp(20)]

    BoxLayout:
        orientation: 'horizontal'
        size_hint_y: None
        height: self.minimum_height
        spacing: dp(10)
        padding: [dp(8), dp(8), dp(8), dp(8)]

        ClickableLabel:
            id: chat_label
            text: root.display_text
            size_hint_x: 0.92
            is_user: root.is_user
            text_size: self.width - dp(15), None

        Button:
            text: "COPY"
            size_hint_x: 0.08
            size_hint_min_x: dp(55)
            size_hint_max_x: dp(85)
            font_size: '11sp'
            background_normal: ''
            background_color: (0.2, 0.4, 0.7, 0.8)
            color: (1, 1, 1, 1)
            on_release: root.copy_to_clipboard()

<HeaderLabel@Label>:
    font_size: '12sp'
    color: (0.7, 0.8, 1, 0.9)
    size_hint_y: None
    height: self.texture_size[1]
    text_size: self.width, None
    halign: 'center'

BoxLayout:
    orientation: 'vertical'
    padding: dp(0)
    spacing: dp(0)
    canvas.before:
        Color:
            rgba: (0.05, 0.06, 0.08, 1)
        Rectangle:
            pos: self.pos
            size: self.size
        Color:
            rgba: (0.12, 0.15, 0.2, 1)
        Rectangle:
            pos: self.pos[0], self.pos[1] + self.height - dp(40)
            size: self.width, dp(40)

    BoxLayout:
        size_hint_y: None
        height: dp(40)
        padding: dp(10), dp(5)
        canvas.before:
            Color:
                rgba: (0.12, 0.15, 0.2, 1)
            Rectangle:
                pos: self.pos
                size: self.size

        HeaderLabel:
            text: "NANO SOLVER v2 - REALITY EDITION"
            font_size: '16sp'
            bold: True
            color: (0.4, 0.8, 1, 1)

        HeaderLabel:
            text: "Passive Security & Utility Toolkit"
            font_size: '12sp'

    ScrollView:
        id: scroll
        do_scroll_x: False
        do_scroll_y: True
        scroll_timeout: 100
        bar_width: dp(6)
        bar_color: (0.3, 0.5, 0.8, 0.7)
        bar_inactive_color: (0.3, 0.5, 0.8, 0.3)
        effect_cls: "ScrollEffect"

        GridLayout:
            id: chat_layout
            cols: 1
            size_hint_y: None
            height: self.minimum_height
            spacing: dp(8)
            padding: dp(15), dp(10)

    BoxLayout:
        id: bottom_bar
        size_hint_y: None
        height: dp(65)
        spacing: dp(10)
        padding: dp(10), dp(8)
        canvas.before:
            Color:
                rgba: (0.09, 0.11, 0.15, 1)
            RoundedRectangle:
                pos: self.pos[0], self.pos[1] + dp(2)
                size: self.size[0], self.size[1] - dp(2)
                radius: [dp(15), dp(15), 0, 0]
            Color:
                rgba: (0.15, 0.18, 0.22, 1)
            RoundedRectangle:
                pos: self.pos
                size: self.size
                radius: [dp(15), dp(15), 0, 0]

        BoxLayout:
            size_hint_x: 0.78
            canvas.before:
                Color:
                    rgba: (0.08, 0.1, 0.14, 1)
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [dp(12),]

            TextInput:
                id: user_input
                hint_text: "Enter command or 'help' for options..."
                multiline: False
                foreground_color: (0.9, 0.95, 1, 1)
                hint_text_color: (0.5, 0.6, 0.8, 0.7)
                background_normal: ''
                background_active: ''
                background_color: (0, 0, 0, 0)
                padding: [dp(15), dp(12)]
                cursor_color: (0.4, 0.85, 1, 1)
                cursor_width: dp(2)
                font_size: '15sp'
                on_text_validate: app.process_command(self.text)
                on_focus: app.on_focus(self.focus)

        BoxLayout:
            size_hint_x: 0.22
            padding: dp(5), 0
            Button:
                id: send_btn
                text: "SEND" if not app.processing_command else "WORKING..."
                font_size: '15sp'
                bold: True
                background_normal: ''
                background_color: (0.15, 0.5, 0.9, 1) if not app.processing_command else (0.5, 0.3, 0.1, 1)
                color: (1, 1, 1, 1)
                on_release: 
                    app.animate_button(self)
                    app.process_command(user_input.text)
'''

class AudioControlWidget(BoxLayout):
    audio_path = StringProperty("")
    audio_title = StringProperty("")
    is_playing = BooleanProperty(False)
    audio_volume = NumericProperty(0.5)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.sound = None
        self.load_audio()
    
    def load_audio(self):
        """Load audio file"""
        if SoundLoader and self.audio_path:
            try:
                # Check audio file safety
                if not check_file_permissions(self.audio_path):
                    return
                    
                self.sound = SoundLoader.load(self.audio_path)
                if self.sound:
                    self.sound.volume = self.audio_volume
                    self.is_playing = False
            except Exception as e:
                print(f"Audio load error: {e}")
    
    def toggle_play(self):
        """Play/pause audio"""
        if self.sound:
            if self.is_playing:
                self.sound.stop()
                self.is_playing = False
            else:
                self.sound.play()
                self.is_playing = True
    
    def stop_audio(self):
        """Stop audio"""
        if self.sound and self.is_playing:
            self.sound.stop()
            self.is_playing = False
    
    def volume_up(self):
        """Increase volume"""
        if self.sound and self.audio_volume < 1.0:
            self.audio_volume = min(1.0, self.audio_volume + 0.1)
            self.sound.volume = self.audio_volume
    
    def volume_down(self):
        """Decrease volume"""
        if self.sound and self.audio_volume > 0.0:
            self.audio_volume = max(0.0, self.audio_volume - 0.1)
            self.sound.volume = self.audio_volume

class MediaWidget(BoxLayout):
    media_path = StringProperty("")
    media_title = StringProperty("")
    is_url = BooleanProperty(False)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    
    def open_link(self):
        """Open the image URL in browser"""
        try:
            if self.is_url:
                # Check link safety before opening
                if validate_url(self.media_path):
                    webbrowser.open(self.media_path)
            else:
                # For local files - check permissions
                if check_file_permissions(self.media_path):
                    import subprocess
                    if platform.system() == "Windows":
                        os.startfile(self.media_path)
                    elif platform.system() == "Darwin":  # macOS
                        subprocess.run(["open", self.media_path])
                    else:  # Linux and Android
                        subprocess.run(["xdg-open", self.media_path])
        except Exception as e:
            print(f"Cannot open: {e}")
    
    def show_image_info(self):
        """Show detailed image information"""
        try:
            if self.is_url:
                # For URLs, show URL info
                info = f"Image URL: {self.media_path}\nSource: External URL\nType: Online Image\nSecurity: {'Valid URL' if validate_url(self.media_path) else 'Invalid URL'}"
            else:
                # For local files
                info = "Local file information not available"
            
            print(f"Image Info:\n{info}")
        except Exception as e:
            print(f"Cannot get image info: {e}")

class LoadingWidget(BoxLayout):
    loading_angle = NumericProperty(0)
    loading_text = StringProperty("Processing...")
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.start_animation()
    
    def start_animation(self):
        anim = Animation(loading_angle=360, duration=1.5)
        anim += Animation(loading_angle=0, duration=0)
        anim.repeat = True
        anim.start(self)

class ClickableLabel(Label):
    is_user = BooleanProperty(False)
    _touch_time = 0
    _long_press_triggered = False
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.long_press_duration = 0.8  # seconds for long press
        self.bind(texture_size=self._update_height)
        
    def _update_height(self, instance, value):
        """Automatically update height when text size changes"""
        self.height = self.texture_size[1] + dp(15)
        
    def on_label_touch_down(self, touch):
        """When text is pressed"""
        self._touch_time = time.time()
        self._long_press_triggered = False
        
        # Schedule long press check
        Clock.schedule_once(self._check_long_press, self.long_press_duration)
        return True
        
    def on_label_touch_up(self, touch):
        """When finger is released"""
        Clock.unschedule(self._check_long_press)
        
        # If not long press, let links work normally
        if not self._long_press_triggered:
            # Find links in text
            urls = re.findall(r'https?://[^\s\]]+', self.text)
            if urls:
                # Check link safety before opening
                safe_urls = [url for url in urls if validate_url(url)]
                if safe_urls:
                    # Open first safe link
                    self.open_link(safe_urls[0])
        return True
        
    def _check_long_press(self, dt):
        """Check if it's a long press"""
        self._long_press_triggered = True
        self.copy_all_links()
        
    def copy_all_links(self):
        """Copy all links in the text"""
        urls = re.findall(r'https?://[^\s\]]+', self.text)
        if urls:
            # Filter only safe links
            safe_urls = [url for url in urls if validate_url(url)]
            links_text = "\n".join(safe_urls)
            try:
                Clipboard.copy(links_text)
                print(f"Copied {len(safe_urls)} safe links to clipboard!")
            except Exception as e:
                print(f"Failed to copy links: {e}")
        else:
            print("No safe links found in this text")
    
    def open_link(self, url):
        """Open link (for normal press)"""
        try:
            if validate_url(url):
                webbrowser.open(url)
            else:
                print("Unsafe URL blocked")
        except Exception as e:
            print("Cannot open url:", e)

class ChatRow(BoxLayout):
    text = StringProperty("")
    display_text = StringProperty("")
    is_user = BooleanProperty(False)
    user_color = ListProperty([0.12, 0.3, 0.5, 1])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        Clock.schedule_once(self._update_text, 0.1)

    def _update_text(self, dt):
        """Update text after widget initialization"""
        # Fix newlines in the text
        if self.text:
            self.display_text = self._prepare_display(self.text)
        else:
            self.display_text = ""

    def _update_height(self, dt):
        """Update height based on text content"""
        if hasattr(self, 'ids'):
            label = self.ids.chat_label
            label.texture_update()
            self.height = label.texture_size[1] + dp(40)

    def _prepare_display(self, text: str) -> str:
        """Prepare text for display with link support and proper newlines"""
        if not text:
            return ""
        
        # Replace escaped newlines with actual newlines
        text = text.replace('\\n', '\n')
        
        # Detect malicious patterns
        is_malicious, pattern = detect_malicious_patterns(text)
        if is_malicious:
            return f"[SECURITY BLOCKED] Malicious pattern detected: {pattern}"
        
        # Find and convert links only
        url_pattern = re.compile(r'(https?://[^\s\]]+)')
        parts = []
        last_end = 0
        
        for m in url_pattern.finditer(text):
            # Text before link
            pre = text[last_end:m.start()]
            parts.append(pre)
            
            # Link with formatting - Check link safety first
            url = m.group(0)
            if validate_url(url):
                parts.append(f"[ref={url}][color=88ff88][u]{url}[/u][/color][/ref]")
            else:
                parts.append(f"[color=ff8888][BLOCKED: {url}][/color]")
            last_end = m.end()
        
        # Remaining text after last link
        tail = text[last_end:]
        parts.append(tail)
        
        return "".join(parts)

    def on_text(self, instance, value):
        """When text changes, update display_text"""
        if value:
            # Process text with proper newline handling
            self.display_text = self._prepare_display(value)
        else:
            self.display_text = ""
        
        # Recalculate height after text update
        Clock.schedule_once(self._update_height, 0.1)

    def open_link(self, url):
        try:
            if validate_url(url):
                webbrowser.open(url)
            else:
                print("Unsafe URL blocked")
        except Exception as e:
            print("Cannot open url:", e)

    def copy_to_clipboard(self):
        try:
            # Clean text before copying
            safe_text = sanitize_input(self.text)
            Clipboard.copy(safe_text)
            print("Text copied to clipboard (sanitized).")
        except Exception as e:
            print(f"Cannot copy to clipboard: {e}")

# ==================== CUSTOM HTTP SERVER ====================

class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    """HTTP server handler with custom logging and security"""
    
    def log_message(self, format, *args):
        """Custom log message to avoid console spam"""
        pass
    
    def do_GET(self):
        """Handle GET requests with security checks"""
        # Check path for unauthorized access
        if '..' in self.path or self.path.startswith('/etc') or self.path.startswith('/proc'):
            self.send_error(403, "Forbidden: Access denied")
            return
            
        # Serve files from current directory
        super().do_GET()

class ServerManager:
    """Server manager to start and stop servers with security"""
    
    def __init__(self):
        self.servers = {}  # {port: server_thread}
        # Ports blocked by common browsers
        self.unsafe_ports = [
            1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79,
            87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137,
            139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532,
            540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723,
            2049, 3659, 4045, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6697,
            10080
        ]
    
    def start_server(self, port=0, directory="."):
        """Start HTTP server on specified port with security checks"""
        try:
            if port == 0:
                port = self.get_safe_random_port()
            elif port in self.unsafe_ports:
                return None, f"Port {port} is blocked by browsers. Use a different port."
            
            # Check port safety
            if not is_safe_port(port):
                return None, f"Port {port} is not safe for use"
            
            # Check if port is available
            if not self.is_port_available(port):
                return None, f"Port {port} is already in use"
            
            # Check directory safety
            if not is_safe_directory(directory):
                return None, f"Directory {directory} is not safe for serving"
            
            # Change directory if specified
            original_dir = os.getcwd()
            if directory != "." and os.path.exists(directory):
                os.chdir(directory)
            
            # Create server
            handler = CustomHTTPRequestHandler
            server = socketserver.TCPServer(("", port), handler)
            
            # Start server in separate thread
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            # Save server info
            self.servers[port] = {
                'server': server,
                'thread': server_thread,
                'directory': directory,
                'original_dir': original_dir
            }
            
            return port, None
            
        except Exception as e:
            # Restore original directory on error
            if 'original_dir' in locals():
                os.chdir(original_dir)
            return None, str(e)
    
    def stop_server(self, port):
        """Stop server on specific port"""
        if port in self.servers:
            try:
                server_info = self.servers[port]
                server_info['server'].shutdown()
                server_info['server'].server_close()
                
                # Restore original directory
                os.chdir(server_info['original_dir'])
                
                del self.servers[port]
                return True, None
            except Exception as e:
                return False, str(e)
        return False, f"No server running on port {port}"
    
    def stop_all_servers(self):
        """Stop all active servers"""
        results = []
        for port in list(self.servers.keys()):
            success, error = self.stop_server(port)
            results.append((port, success, error))
        return results
    
    def get_running_servers(self):
        """Get list of active servers"""
        return list(self.servers.keys())
    
    def get_safe_random_port(self):
        """Get a safe random port"""
        safe_ports = [8000, 8080, 8888, 9000, 9090, 3000, 3001, 4200, 5000, 5500]
        
        # First try common safe ports
        for port in safe_ports:
            if self.is_port_available(port) and port not in self.unsafe_ports:
                return port
        
        # If not available, find a random safe port
        while True:
            port = random.randint(1024, 65535)
            if port not in self.unsafe_ports and self.is_port_available(port) and is_safe_port(port):
                return port
    
    def is_port_available(self, port):
        """Check if port is available"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                return True
            except OSError:
                return False
    
    def get_safe_ports_suggestion(self):
        """Suggest safe ports to use"""
        safe_ports = [8000, 8080, 8888, 9000, 9090, 3000, 3001, 4200, 5000, 5500]
        available_safe_ports = [port for port in safe_ports if self.is_port_available(port)]
        return available_safe_ports[:3]  # Return first 3 available ports

# ==================== NANO SOLVER APP ====================

class NanoSolverApp(App):
    processing_command = BooleanProperty(False)
    current_loading_widget = None
    current_streaming_row = None
    streaming_text = ""
    streaming_index = 0
    streaming_speed = 0.01  # seconds between characters
    server_manager = ServerManager()
    current_audio_widget = None
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.shifted = False
        self.shift_height = 500
        self.user_name = "Reality"
        self.user_bubble_color = [0.12, 0.3, 0.5, 1]
        self.db = {}
        self.search_results_cache = []
        
        # Initialize security systems
        self.security_monitor = SecurityMonitor()
        self.security_updates = SecurityUpdates()
        self.encryption_key = generate_secure_token()
        
        # Initialize scanners
        self.auto_scanner = AutoScanner()
        self.advanced_scanner = AdvancedWebsiteScanner()
        self.log_analyzer = LogAnalyzer()
        self.pdf_generator = PDFReportGenerator()
        
        # Initialize plugin system
        self.plugin_manager = PluginManager(self)
        
        # Start behavior monitoring after app initialization
        Clock.schedule_once(self.start_behavior_monitoring, 5)

    def start_behavior_monitoring(self, dt):
        """Start behavior monitoring after app loads"""
        self.security_monitor.start_behavior_monitoring()
        print("Behavior analysis system started")

    def build(self):
        self.title = "Nano Solver v2 - Reality"
        
        # Load database after UI builds
        Clock.schedule_once(self._load_database, 0.1)
        
        self.root = Builder.load_string(KV)
        
        # Load plugins
        Clock.schedule_once(self._load_plugins, 0.2)
        
        # Add welcome message
        Clock.schedule_once(self._show_welcome_message, 0.5)
        
        return self.root

    def _load_database(self, dt):
        """Load database after UI initialization"""
        self.db = self.load_database("Nano Solver.txt")

    def _load_plugins(self, dt):
        """Load plugins after UI initialization"""
        self.plugin_manager.load_plugins()
        plugin_count = len(self.plugin_manager.loaded_plugins)
        print(f"✅ Loaded {plugin_count} plugins")

    def _show_welcome_message(self, dt):
        """Show welcome message with plugin information"""
        plugin_commands = self.plugin_manager.get_plugin_commands()
        plugin_info = f"\n🔌 Plugins: {len(plugin_commands)} commands loaded"
        
        welcome_msg = (
            "🚀 NANO SOLVER v2 - REALITY EDITION INITIALIZED\n\n"
            "🔒 ADVANCED SECURITY FEATURES:\n"
            "• Behavior Analysis & Monitoring\n"
            "• Deep Website Vulnerability Scanning\n"
            "• Auto Security Hardening\n"
            "• PDF Report Generation\n"
            "• Log Analysis & Attack Detection\n"
            "• Real-time System Monitoring\n"
            "• Plugin System Extension\n\n"
            "💡 Type 'help' for complete command list\n"
            "🔌 Try plugin commands or 'plugins' for plugin info\n"
            "🔍 Try: autoscan example.com | deepscan url | analyzelogs"
        )
        
        self.add_message(welcome_msg, is_user=False)

    # ==================== PLUGIN COMMANDS ====================

    def _process_command_internal(self, cmd):
        """Internal command processing - runs in background thread"""
        
        # PLUGIN SYSTEM COMMANDS
        if cmd.lower() == "plugins":
            return self.list_plugins()
        
        if cmd.lower() == "reload plugins":
            return self.plugin_manager.reload_plugins()
        
        if cmd.lower().startswith("plugin info "):
            plugin_name = cmd[12:].strip()
            return self.show_plugin_info(plugin_name)
        
        # Check if command is a plugin command
        parts = cmd.split()
        if parts:
            plugin_result = self.plugin_manager.execute_plugin_command(parts[0], parts[1:])
            if plugin_result is not None:
                return plugin_result
        
        # EXISTING COMMANDS
        # NEW: Advanced Website Scanning
        if cmd.lower().startswith("deepscan "):
            url = cmd[9:].strip()
            return self.deep_scan_website(url)
        
        # NEW: Auto Scanning
        if cmd.lower().startswith("autoscan "):
            url = cmd[9:].strip()
            return self.auto_scan_command(url)
        
        # NEW: Log Analysis
        if cmd.lower().startswith("analyzelogs "):
            log_data = cmd[12:].strip()
            return self.analyze_logs_command(log_data)
        
        # NEW: Auto Hardening Tips
        if cmd.lower() in ["hardening", "security tips", "auto harden"]:
            return self.get_auto_hardening_tips()
        
        # NEW: Behavior Analysis Commands
        if cmd.lower() == "behavior scan":
            return self.behavior_analysis_scan()
        
        if cmd.lower() == "behavior monitor":
            return self.real_time_behavior_monitor()
        
        if cmd.lower() == "start behavior monitoring":
            return self.security_monitor.start_behavior_monitoring()

        # NEW: System Security Scan
        if cmd.lower() == "scan system":
            return self.scan_system_for_malware()

        # NEW: Security report
        if cmd.lower() == "security report":
            return self.security_monitor.get_security_report()

        # NEW: Audio Playback
        m = re.match(r'^play\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            file_path = m.group(1).strip()
            return self.play_audio_file(file_path)

        # NEW: Image preview from URL
        m = re.match(r'^preview\s+(https?://[^\s]+)$', cmd, flags=re.IGNORECASE)
        if m:
            url = m.group(1).strip()
            
            # Check if it's an image URL
            if self.is_image_url(url):
                # Preview image directly from URL
                self.preview_image_url(url)
                return f"NanoSolver: 🖼️ Loading image preview from URL..."
            else:
                return f"NanoSolver: ❌ URL doesn't appear to be an image. Supported formats: jpg, jpeg, png, gif, bmp, webp, svg"

        # NEW: File search command
        m = re.match(r'^search\s+(.+?)(?:\s+in\s+(.+))?$', cmd, flags=re.IGNORECASE)
        if m:
            pattern = m.group(1).strip()
            directory = m.group(2) or "."
            
            if pattern.startswith('"') and pattern.endswith('"'):
                pattern = pattern[1:-1]
            
            # Check if it's content search
            content_search = None
            if pattern.startswith('content:'):
                content_search = pattern[8:].strip()
                pattern = "*"
            elif ' content:' in pattern:
                parts = pattern.split(' content:', 1)
                pattern = parts[0].strip()
                content_search = parts[1].strip()
            
            results = self.search_files(directory, pattern, content_search)
            
            if isinstance(results, str):  # Error message
                return f"NanoSolver: {results}"
            
            if not results:
                search_type = "content" if content_search else "filename"
                return f"NanoSolver: 🔍 No files found matching {search_type} pattern '{pattern}' in {directory}"
            
            result_list = []
            for i, file_path in enumerate(results[:20], 1):
                file_size = os.path.getsize(file_path)
                result_list.append(f"{i}. {os.path.basename(file_path)} ({file_size} bytes) - {file_path}")
            
            if len(results) > 20:
                result_list.append(f"\n... and {len(results) - 20} more files")
            
            return "NanoSolver: 🔍 Search results:\n" + "\n".join(result_list)

        # NEW: File preview command (local files)
        m = re.match(r'^preview\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            file_path = m.group(1).strip()
            
            if not os.path.exists(file_path):
                return "NanoSolver: ❌ File not found"
            
            # Check if it's a supported media file
            supported_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp']
            if any(file_path.lower().endswith(ext) for ext in supported_extensions):
                # Schedule media widget on main thread
                Clock.schedule_once(lambda dt: self.add_media_widget(
                    file_path=file_path,
                    file_title=os.path.basename(file_path),
                    is_url=False
                ), 0.1)
                
                file_info = self.get_file_info(file_path)
                return f"NanoSolver: ✅ Media preview loaded for: {os.path.basename(file_path)}\n\nFile Info:\n{file_info}"
            else:
                return f"NanoSolver: ❌ File type not supported for preview. Supported: {', '.join(supported_extensions)}"

        # NEW: File info command
        m = re.match(r'^fileinfo\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            file_path = m.group(1).strip()
            info = self.get_file_info(file_path)
            return f"NanoSolver: 📄 File Information:\n{info}"

        # NEW: Directory analysis command
        m = re.match(r'^analyze\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            directory = m.group(1).strip()
            analysis = self.analyze_directory(directory)
            return f"NanoSolver: 📊 {analysis}"

        m = re.match(r'^analyze$', cmd, flags=re.IGNORECASE)
        if m:
            analysis = self.analyze_directory(".")
            return f"NanoSolver: 📊 {analysis}"

        # NEW: Find large files
        m = re.match(r'^largefiles\s+(\d+)(?:\s+(.+))?$', cmd, flags=re.IGNORECASE)
        if m:
            min_size_mb = int(m.group(1))
            directory = m.group(2) or "."
            
            large_files = []
            for root, dirs, files in os.walk(directory):
                for file in files:
                    full_path = os.path.join(root, file)
                    try:
                        file_size = os.path.getsize(full_path)
                        if file_size >= min_size_mb * 1024 * 1024:
                            large_files.append((full_path, file_size))
                    except:
                        continue
            
            if not large_files:
                return f"NanoSolver: 🔍 No files larger than {min_size_mb} MB found in {directory}"
            
            # Sort by size descending
            large_files.sort(key=lambda x: x[1], reverse=True)
            
            result_list = []
            for i, (file_path, file_size) in enumerate(large_files[:15], 1):
                size_mb = file_size / (1024 * 1024)
                result_list.append(f"{i}. {os.path.basename(file_path)} ({size_mb:.2f} MB) - {file_path}")
            
            return f"NanoSolver: 📁 Files larger than {min_size_mb} MB:\n" + "\n".join(result_list)

        # NEW: Bulk passwords command
        m = re.match(r'^(passwords|bulkpass|multipass)\s+(\d+)(?:\s+(\d+))?$', cmd, flags=re.IGNORECASE)
        if m:
            count = int(m.group(2))
            length = int(m.group(3)) if m.group(3) else 12
            
            if count > 50:
                return "NanoSolver: ❌ Maximum 50 passwords at once for performance reasons"
            if count < 1:
                return "NanoSolver: ❌ Please generate at least 1 password"
            if length < 8:
                return "NanoSolver: ❌ Minimum password length is 8 characters"
            if length > 64:
                return "NanoSolver: ❌ Maximum password length is 64 characters"
            
            passwords = self.generate_multiple_passwords(count, length)
            password_list = "\n".join([f"{i+1}. {pwd}" for i, pwd in enumerate(passwords)])
            
            return (f"NanoSolver: ✅ Generated {count} passwords ({length} chars each):\n\n"
                   f"{password_list}\n\n"
                   f"📋 All passwords copied to clipboard! Use long press to copy individual passwords.")

        # NEW: Advanced password generation with options
        m = re.match(r'^(passwords|bulkpass|multipass)$', cmd, flags=re.IGNORECASE)
        if m:
            # Default: 10 passwords of 16 characters
            passwords = self.generate_multiple_passwords(10, 16)
            password_list = "\n".join([f"{i+1}. {pwd}" for i, pwd in enumerate(passwords)])
            
            return (f"NanoSolver: ✅ Generated 10 passwords (16 chars each):\n\n"
                   f"{password_list}\n\n"
                   f"📋 All passwords copied to clipboard!\n"
                   f"💡 Usage: passwords <count> <length> | passwords 5 12")

        # Server commands
        m = re.match(r'^(server|serve|http)\s+(\d+)(?:\s+(.+))?$', cmd, flags=re.IGNORECASE)
        if m:
            port = int(m.group(2))
            directory = m.group(3) or "."
            
            # Check if port is blocked
            if port in self.server_manager.unsafe_ports:
                safe_suggestions = self.server_manager.get_safe_ports_suggestion()
                return (f"NanoSolver: ❌ Port {port} is blocked by browsers!\n\n"
                       f"💡 Safe port suggestions: {', '.join(map(str, safe_suggestions))}\n"
                       f"Use: 'server' for auto-safe-port or 'server <safe-port>'")
            
            port_used, error = self.server_manager.start_server(port, directory)
            if error:
                safe_suggestions = self.server_manager.get_safe_ports_suggestion()
                return (f"NanoSolver: ❌ Failed to start server: {error}\n\n"
                       f"💡 Try these safe ports: {', '.join(map(str, safe_suggestions))}")
            
            # Get local IP address
            local_ip = self.get_local_ip()
            return (f"NanoSolver: ✅ HTTP Server started successfully!\n"
                   f"🌐 Port: {port_used}\n"
                   f"📁 Directory: {directory}\n"
                   f"🔗 Local URL: http://localhost:{port_used}\n"
                   f"🌍 Network URL: http://{local_ip}:{port_used}\n\n"
                   f"Use 'stop {port_used}' to stop this server")

        m = re.match(r'^(server|serve|http)(?:\s+(.+))?$', cmd, flags=re.IGNORECASE)
        if m:
            directory = m.group(2) or "."
            port_used, error = self.server_manager.start_server(0, directory)
            if error:
                safe_suggestions = self.server_manager.get_safe_ports_suggestion()
                return (f"NanoSolver: ❌ Failed to start server: {error}\n\n"
                       f"💡 Try these safe ports: {', '.join(map(str, safe_suggestions))}")
            
            local_ip = self.get_local_ip()
            return (f"NanoSolver: ✅ HTTP Server started successfully!\n"
                   f"🌐 Port: {port_used} (auto-safe-port)\n"
                   f"📁 Directory: {directory}\n"
                   f"🔗 Local URL: http://localhost:{port_used}\n"
                   f"🌍 Network URL: http://{local_ip}:{port_used}\n\n"
                   f"Use 'stop {port_used}' to stop this server")

        m = re.match(r'^stop\s+(\d+)$', cmd, flags=re.IGNORECASE)
        if m:
            port = int(m.group(1))
            success, error = self.server_manager.stop_server(port)
            if error:
                return f"NanoSolver: ❌ Failed to stop server on port {port}: {error}"
            return f"NanoSolver: ✅ Server on port {port} stopped successfully"

        if cmd.lower() == "stop all":
            results = self.server_manager.stop_all_servers()
            stopped = []
            failed = []
            for port, success, error in results:
                if success:
                    stopped.append(str(port))
                else:
                    failed.append(f"Port {port}: {error}")
            
            response = "NanoSolver: Server stop results:\n"
            if stopped:
                response += f"✅ Stopped: {', '.join(stopped)}\n"
            if failed:
                response += f"❌ Failed: {', '.join(failed)}"
            return response

        if cmd.lower() == "servers":
            running = self.server_manager.get_running_servers()
            if not running:
                return "NanoSolver: 🔍 No servers currently running"
            
            local_ip = self.get_local_ip()
            server_list = []
            for port in running:
                server_list.append(f"🌐 Port {port}: http://localhost:{port} | http://{local_ip}:{port}")
            
            return "NanoSolver: 🌐 Running servers:\n" + "\n".join(server_list)

        if cmd.lower() == "safe ports":
            safe_suggestions = self.server_manager.get_safe_ports_suggestion()
            return f"NanoSolver: 💡 Safe port suggestions: {', '.join(map(str, safe_suggestions))}"

        # Single password generation (existing)
        m = re.match(r'^(genpass)\s+(\d+)$', cmd, flags=re.IGNORECASE)
        if m:
            length = int(m.group(2))
            out = self.genpass(length)
            return f"NanoSolver: 🔑 Generated password ({length} chars):\n{out}"
        
        m = re.match(r'^(genpass)$', cmd, flags=re.IGNORECASE)
        if m:
            out = self.genpass(16)
            return f"NanoSolver: 🔑 Generated password (16 chars):\n{out}"

        # GitHub explain/open
        if cmd.lower().startswith("explain "):
            term = cmd[len("explain "):].strip()
            meta = self.github_search(term, per_page=5)
            if "error" in meta:
                return f"NanoSolver: ❌ Could not query GitHub: {meta['error']}"
            items = meta.get("items", [])
            if not items:
                return "NanoSolver: 🔍 No repositories found for that query."
            self.search_results_cache = items
            lines = []
            for i, it in enumerate(items, start=1):
                desc = (it['description'][:140] + '...') if len(it['description']) > 140 else it['description']
                line = f"{i}. {it['full_name']} -- {desc} (Stars:{it['stargazers_count']}, Forks:{it['forks_count']}, License:{it['license']}) [ref={it['html_url']}][color=88ff88][u]open</u></color></ref>"
                lines.append(line)
            return ("NanoSolver: 🔍 Found these repositories (metadata). To fetch README/installation for a specific repository type: open <n>\n\n"
                   + "\n".join(lines) +
                   "\n\n💡 Note: README content will be sanitized to redact potentially dangerous commands/downloads.")

        m = re.match(r'^open\s+(\d+)$', cmd.lower())
        if m:
            idx = int(m.group(1)) - 1
            if idx < 0 or idx >= len(self.search_results_cache):
                return "NanoSolver: ❌ invalid index. Use 'explain <term>' first and then 'open <n>'."
            repo = self.search_results_cache[idx]
            read = self.github_get_readme(repo['full_name'])
            if "error" in read:
                return f"NanoSolver: ❌ Could not fetch README: {read['error']}"
            content = read.get("content", "")
            install = self.extract_installation_sections(content)
            if install:
                sanitized = self.sanitize_readme(install)
                wrapped = "\n".join([textwrap.fill(line, width=90) for line in sanitized.splitlines()])
                return (f"NanoSolver: 📖 Extracted installation/setup sections from {repo['full_name']} (sanitized):\n\n{wrapped}\n\n"
                       f"(Open repo: [ref={repo['html_url']}][color=88ff88][u]open repo</u></color></ref>)")
            else:
                snippet = content[:2500].strip()
                snippet_s = self.sanitize_readme(snippet)
                snippet_s = snippet_s + ("\n\n... (truncated)" if len(content) > 2500 else "")
                return (f"NanoSolver: 📖 Couldn't detect a clear 'installation' section. Showing sanitized README snippet for {repo['full_name']}:\n\n"
                       f"{snippet_s}\n\n[ref={repo['html_url']}][color=88ff88][u]open repo</u></color></ref>")

        # calculate
        m = re.match(r'^calculate\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            expr = m.group(1).strip()
            result = self.safe_eval(expr)
            return f"NanoSolver: 🧮 {expr} = {result}"

        # time
        if cmd.lower() == "time":
            now = datetime.datetime.now()
            return f"NanoSolver: 🕒 {now.strftime('%d %b %Y -- %H:%M:%S')}"

        # path
        if cmd.lower() == "path":
            try:
                cwd = os.getcwd()
                return f"NanoSolver: 📁 Current path: {cwd}"
            except Exception as e:
                return f"NanoSolver: ❌ Cannot determine path: {e}"

        # ls / list files
        m = re.match(r'^(ls|list files)(?:\s+(.+))?$', cmd, flags=re.IGNORECASE)
        if m:
            path = m.group(2) or "."
            out = self.list_files(path)
            return f"NanoSolver: 📁 Files in '{path}':\n{out}"

        # read
        m = re.match(r'^read\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            filename = m.group(1).strip()
            out = self.read_file_head(filename)
            return f"NanoSolver: 📄 First lines of {filename}:\n{out}"

        # battery
        if cmd.lower() == "battery":
            out = self.get_battery_info()
            return f"NanoSolver: 🔋 Battery: {out}"

        # systeminfo
        if cmd.lower() == "systeminfo":
            out = self.get_system_info()
            return f"NanoSolver: 💻 System info:\n{out}"

        # name
        m = re.match(r'^name\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            new_name = m.group(1).strip()
            old = self.user_name
            self.user_name = new_name
            return f"NanoSolver: 👤 User display name changed: {old} -> {self.user_name}"

        # color
        m = re.match(r'^color\s+([#]?[0-9a-fA-F]{6})$', cmd, flags=re.IGNORECASE)
        if m:
            hexv = m.group(1).lstrip("#")
            try:
                r = int(hexv[0:2], 16) / 255.0
                g = int(hexv[2:4], 16) / 255.0
                b = int(hexv[4:6], 16) / 255.0
                self.user_bubble_color = [r, g, b, 1]
                return f"NanoSolver: 🎨 User bubble color set to #{hexv.upper()}"
            except Exception as e:
                return f"NanoSolver: ❌ Invalid hex color: {e}"

        # Security scanning commands
        m = re.match(r'^scan\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            target = m.group(1).strip()
            out = self.scan_website(target)
            wrapped = "\n".join([textwrap.fill(line, width=90) for line in out.splitlines()])
            return f"NanoSolver: 🔍 Scan results for {target}:\n{wrapped}"

        m = re.match(r'^headers\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            url = m.group(1).strip()
            out = self.headers_for(url)
            return f"NanoSolver: 📋 Headers for {url}:\n{out}"

        m = re.match(r'^(check_ssl|ssl)\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            domain = m.group(2).strip()
            out = self.check_ssl(domain)
            return f"NanoSolver: 🔒 SSL info for {domain}:\n{out}"

        m = re.match(r'^(robots)\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            domain = m.group(2).strip()
            out = self.read_robots(domain)
            return f"NanoSolver: 🤖 robots.txt for {domain}:\n{out}"

        m = re.match(r'^(dns_lookup|dns)\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            domain = m.group(2).strip()
            out = self.dns_lookup(domain)
            return f"NanoSolver: 🌐 DNS lookup for {domain}:\n{out}"

        m = re.match(r'^(ping)\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            target = m.group(2).strip()
            out = self.ping_host(target)
            return f"NanoSolver: 📡 Ping result:\n{out}"

        m = re.match(r'^(ports)\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            host = m.group(2).strip()
            out = self.common_ports_scan(host)
            return f"NanoSolver: 🔒 Port scan (common) for {host}:\n{out}"

        m = re.match(r'^(subdomains)\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            domain = m.group(2).strip()
            out = self.subdomain_discover(domain)
            return f"NanoSolver: 🌐 Subdomains (simple) for {domain}:\n{out}"

        m = re.match(r'^(whois)\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            domain = m.group(2).strip()
            out = self.whois_lookup(domain)
            return f"NanoSolver: 🔍 Whois for {domain}:\n{out}"

        m = re.match(r'^(vuln)\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            domain = m.group(2).strip()
            out = self.vuln_quick(domain)
            return f"NanoSolver: ⚠️ Quick vulnerability hints for {domain}:\n{out}"

        # Utility commands
        m = re.match(r'^(hash)\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            txt = m.group(2)
            out = self.hash_sha256(txt)
            return f"NanoSolver: 🔐 SHA256({txt}) = {out}"

        m = re.match(r'^(encode)\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            txt = m.group(2)
            out = self.b64_encode(txt)
            return f"NanoSolver: 🔒 base64 encode = {out}"

        m = re.match(r'^(decode)\s+(.+)$', cmd, flags=re.IGNORECASE)
        if m:
            txt = m.group(2)
            out = self.b64_decode(txt)
            return f"NanoSolver: 🔓 base64 decode = {out}"

        # Fallback to simple commands
        return self.run_command(cmd)

    def list_plugins(self):
        """List all loaded plugins and their commands"""
        plugins = self.plugin_manager.loaded_plugins
        plugin_commands = self.plugin_manager.get_plugin_commands()
        
        if not plugins:
            return "NanoSolver: 🔌 No plugins loaded. Add .py files to the 'plugins' directory."
        
        result = []
        result.append("🔌 LOADED PLUGINS & COMMANDS")
        result.append("=" * 40)
        
        for plugin_name, plugin_data in plugins.items():
            plugin_info = plugin_data['info']
            result.append(f"\n📦 {plugin_name} v{plugin_info.get('version', '1.0.0')}")
            result.append(f"   Author: {plugin_info.get('author', 'Unknown')}")
            result.append(f"   Description: {plugin_info.get('description', 'No description')}")
            
            # List commands for this plugin
            plugin_cmds = [cmd for cmd in plugin_commands if cmd['plugin'] == plugin_name]
            if plugin_cmds:
                result.append("   Commands:")
                for cmd in plugin_cmds:
                    desc = cmd['description'].split('\n')[0] if cmd['description'] else "No description"
                    result.append(f"     • {cmd['command']} - {desc}")
        
        result.append(f"\n💡 Total: {len(plugins)} plugins, {len(plugin_commands)} commands available")
        result.append("🔧 Use 'reload plugins' to reload all plugins")
        result.append("📖 Use 'plugin info <name>' for detailed plugin information")
        
        return "\n".join(result)

    def show_plugin_info(self, plugin_name):
        """Show detailed information about a specific plugin"""
        plugin = self.plugin_manager.loaded_plugins.get(plugin_name)
        
        if not plugin:
            available_plugins = ", ".join(self.plugin_manager.loaded_plugins.keys())
            return f"NanoSolver: ❌ Plugin '{plugin_name}' not found. Available plugins: {available_plugins}"
        
        plugin_info = plugin['info']
        commands = plugin['commands']
        
        result = []
        result.append(f"📦 PLUGIN INFO: {plugin_name}")
        result.append("=" * 40)
        result.append(f"Version: {plugin_info.get('version', '1.0.0')}")
        result.append(f"Author: {plugin_info.get('author', 'Unknown')}")
        result.append(f"Description: {plugin_info.get('description', 'No description')}")
        
        result.append("\n🛠️ AVAILABLE COMMANDS:")
        for cmd_name, cmd_func in commands.items():
            docstring = cmd_func.__doc__ or "No description available"
            result.append(f"\n🔹 {cmd_name}")
            # Format docstring with proper indentation
            doc_lines = docstring.strip().split('\n')
            for line in doc_lines:
                result.append(f"   {line.strip()}")
        
        return "\n".join(result)

    # ==================== EXISTING METHODS ====================

    def animate_button(self, button):
        if not self.processing_command:
            anim = Animation(background_color=(0.3, 0.7, 1, 1), duration=0.1) + \
                   Animation(background_color=(0.15, 0.5, 0.9, 1), duration=0.3)
            anim.start(button)

    def show_loading(self, message="Processing..."):
        """Show loading indicator"""
        if hasattr(self, 'root') and self.root and hasattr(self.root, 'ids'):
            self.current_loading_widget = LoadingWidget(loading_text=message)
            self.root.ids.chat_layout.add_widget(self.current_loading_widget)
            Clock.schedule_once(lambda dt: setattr(self.root.ids.scroll, 'scroll_y', 0), 0.05)

    def hide_loading(self, dt=None):
        """Hide loading indicator - accepts optional dt parameter for Clock"""
        if self.current_loading_widget and hasattr(self, 'root') and self.root and hasattr(self.root, 'ids'):
            self.root.ids.chat_layout.remove_widget(self.current_loading_widget)
            self.current_loading_widget = None

    def start_streaming_response(self, text):
        """Start streaming text character by character"""
        if hasattr(self, 'root') and self.root and hasattr(self.root, 'ids'):
            self.streaming_text = text
            self.streaming_index = 0
            self.current_streaming_row = ChatRow(text="", is_user=False)
            self.root.ids.chat_layout.add_widget(self.current_streaming_row)
            self.schedule_next_character()

    def schedule_next_character(self):
        """Schedule next character to be displayed"""
        if self.streaming_index < len(self.streaming_text):
            Clock.schedule_once(self._add_next_character, self.streaming_speed)

    def _add_next_character(self, dt):
        """Add next character to streaming row"""
        if self.current_streaming_row and self.streaming_index < len(self.streaming_text):
            char = self.streaming_text[self.streaming_index]
            self.current_streaming_row.text += char
            self.streaming_index += 1
            self.schedule_next_character()
            
            # Auto-scroll to bottom
            if self.streaming_index % 10 == 0:
                Clock.schedule_once(self._scroll_to_bottom, 0.01)

    def _scroll_to_bottom(self, dt):
        """Scroll to bottom of chat"""
        if hasattr(self, 'root') and self.root and hasattr(self.root, 'ids'):
            self.root.ids.scroll.scroll_y = 0

    def add_media_widget(self, file_path, file_title, is_url=False):
        """Add media widget to chat"""
        if hasattr(self, 'root') and self.root and hasattr(self.root, 'ids'):
            media_widget = MediaWidget(
                media_path=file_path,
                media_title=file_title,
                is_url=is_url
            )
            self.root.ids.chat_layout.add_widget(media_widget)
            Clock.schedule_once(self._scroll_to_bottom, 0.05)

    def add_audio_widget(self, file_path, file_title):
        """Add audio control widget to chat"""
        # Stop any currently playing audio
        if self.current_audio_widget:
            self.current_audio_widget.stop_audio()
        
        if hasattr(self, 'root') and self.root and hasattr(self.root, 'ids'):
            self.current_audio_widget = AudioControlWidget(
                audio_path=file_path,
                audio_title=file_title
            )
            self.root.ids.chat_layout.add_widget(self.current_audio_widget)
            Clock.schedule_once(self._scroll_to_bottom, 0.05)

    def deep_scan_website(self, url):
        """Perform deep website security scan"""
        try:
            self.show_loading("🔍 Performing deep website security scan...")
            
            scan_results = self.advanced_scanner.deep_scan_website(url)
            
            report = []
            report.append("🌐 DEEP WEBSITE SECURITY SCAN")
            report.append("="*50)
            report.append(f"📊 URL: {scan_results['url']}")
            report.append(f"⚠️ Risk Score: {scan_results['risk_score']}/100")
            report.append(f"🕒 Scan Date: {scan_results['timestamp']}")
            
            # Security headers
            report.append("\n🔒 SECURITY HEADERS ANALYSIS:")
            headers = scan_results['security_headers']
            for header_name, header_info in headers.items():
                status = "✅ PRESENT" if header_info['present'] else "❌ MISSING"
                report.append(f"  {header_name}: {status} (Score: {header_info['score']}/10)")
            
            # Vulnerabilities
            if scan_results['vulnerabilities']:
                report.append(f"\n⚠️ DETECTED VULNERABILITIES ({len(scan_results['vulnerabilities'])} found):")
                for i, vuln in enumerate(scan_results['vulnerabilities'][:5], 1):
                    report.append(f"  {i}. [{vuln['risk']}] {vuln['type']}")
                    report.append(f"     {vuln['description']}")
            else:
                report.append("\n✅ No critical vulnerabilities detected")
            
            # Recommendations
            report.append("\n💡 SECURITY RECOMMENDATIONS:")
            for i, recommendation in enumerate(scan_results['recommendations'][:5], 1):
                report.append(f"  {i}. {recommendation}")
            
            # Generate PDF report
            pdf_result = self.pdf_generator.generate_website_security_report(scan_results)
            report.append(f"\n📄 PDF Report: {pdf_result}")
            
            return "\n".join(report)
            
        except Exception as e:
            return f"❌ Deep scan failed: {str(e)}"

    def auto_scan_command(self, url):
        """Comprehensive automatic scan"""
        try:
            result = self.auto_scanner.auto_scan_website(url)
            
            report = []
            report.append("🚀 AUTO SECURITY SCAN COMPLETED")
            report.append("="*50)
            report.append(f"📊 Scan Summary for: {url}")
            report.append(f"⚠️ Risk Level: {result['risk_level']}")
            report.append(f"📈 Risk Score: {result['scan_results']['risk_score']}/100")
            
            report.append("\n🔒 AUTO HARDENING TIPS:")
            for tip in result['hardening_tips'][:6]:
                report.append(f"  {tip}")
            
            report.append(f"\n📄 {result['pdf_report']}")
            report.append("\n💡 Use 'deepscan <url>' for detailed analysis")
            
            return "\n".join(report)
            
        except Exception as e:
            return f"❌ Auto scan failed: {str(e)}"

    def analyze_logs_command(self, log_data):
        """Analyze system logs"""
        try:
            if not log_data or log_data.strip() == "":
                return "Please provide log data to analyze"
            
            self.show_loading("📊 Analyzing security logs...")
            
            analysis_results = self.log_analyzer.analyze_logs(log_data)
            
            report = []
            report.append("📊 SECURITY LOG ANALYSIS REPORT")
            report.append("=" * 40)
            report.append(f"Total log entries: {analysis_results['total_entries']}")
            report.append(f"Attacks detected: {analysis_results['attacks_detected']}")
            
            if analysis_results['attack_types']:
                report.append("\n⚠️ DETECTED ATTACK TYPES:")
                for attack_type, count in analysis_results['attack_types'].items():
                    report.append(f"  {attack_type.upper()}: {count} occurrences")
            
            if analysis_results['suspicious_ips']:
                report.append("\n🔍 SUSPICIOUS IP ADDRESSES:")
                for ip, attacks in list(analysis_results['suspicious_ips'].items())[:3]:
                    report.append(f"  {ip}: {', '.join(set(attacks))}")
            
            report.append("\n🛡️ SECURITY RECOMMENDATIONS:")
            for i, recommendation in enumerate(analysis_results['recommendations'][:4], 1):
                report.append(f"  {i}. {recommendation}")
            
            # Generate PDF report
            pdf_result = self.pdf_generator.generate_log_analysis_report(analysis_results)
            report.append(f"\n📄 PDF Report: {pdf_result}")
            
            return "\n".join(report)
            
        except Exception as e:
            return f"❌ Log analysis failed: {str(e)}"

    def get_auto_hardening_tips(self):
        """Get automatic security hardening tips"""
        tips = [
            "🔒 Use strong Content Security Policy (CSP)",
            "🚫 Disable directory listing in server config",
            "🛡️ Implement Web Application Firewall (WAF)",
            "📝 Remove sensitive info from source code comments",
            "🔑 Use HTTPS exclusively with HSTS enabled",
            "📊 Regular security audits and penetration testing",
            "🔄 Keep all software and dependencies updated",
            "📋 Implement proper logging and monitoring",
            "🔍 Regular vulnerability scanning",
            "🚀 Implement rate limiting for API endpoints",
            "📧 Set secure email headers (DMARC, SPF, DKIM)",
            "🗄️ Use parameterized queries to prevent SQL injection",
            "🌐 Validate and sanitize all user inputs",
            "🔐 Implement proper session management",
            "📱 Use secure cookies with HttpOnly and Secure flags"
        ]
        
        report = ["🛡️ AUTO HARDENING SECURITY TIPS", "="*35]
        report.extend(tips[:10])
        report.append("\n💡 Implement these recommendations to improve your security posture")
        
        return "\n".join(report)

    def behavior_analysis_scan(self):
        """Scan and analyze system behavior"""
        try:
            # Get behavior analysis report
            behavior_report = self.security_monitor.get_behavior_report()
            
            # Additional pattern analysis
            patterns = self.security_monitor.behavior_analyzer.analyze_behavior_patterns()
            
            report = []
            report.append("🔍 BEHAVIOR ANALYSIS SCAN")
            report.append("="*40)
            report.append(behavior_report)
            
            if patterns:
                report.append("\n🎯 DETECTED BEHAVIOR PATTERNS:")
                for pattern in patterns:
                    report.append(f"\n🔸 Pattern: {pattern['pattern']}")
                    report.append(f"📝 Description: {pattern['description']}")
                    report.append(f"⚠️ Risk Level: {pattern['risk_level']}")
            
            return "\n".join(report)
            
        except Exception as e:
            return f"❌ Behavior analysis error: {str(e)}"

    def real_time_behavior_monitor(self):
        """Real-time behavior monitoring"""
        try:
            current_behaviors = self.security_monitor.behavior_analyzer.behavior_log
            recent_behaviors = [b for b in current_behaviors 
                              if time.time() - b['timestamp'] < 300]
            
            if not recent_behaviors:
                return "📊 No recent behavior activities detected in the last 5 minutes."
            
            report = []
            report.append("🕒 REAL-TIME BEHAVIOR MONITOR")
            report.append("="*35)
            report.append(f"Activities in last 5 minutes: {len(recent_behaviors)}")
            
            for behavior in recent_behaviors[-10:]:
                timestamp = datetime.datetime.fromtimestamp(behavior['timestamp']).strftime('%H:%M:%S')
                report.append(f"\n[{timestamp}] {behavior['type'].upper()}")
                report.append(f"Behavior: {behavior['behavior']}")
                report.append(f"Risk Level: {behavior['risk_level']}")
            
            return "\n".join(report)
            
        except Exception as e:
            return f"❌ Real-time monitoring error: {str(e)}"

    def play_audio_file(self, file_path):
        """Play audio file in background"""
        if not SoundLoader:
            return "NanoSolver: ❌ Audio playback not supported on this platform"
        
        # Clean file path and check safety
        safe_path = sanitize_file_path(file_path)
        if not safe_path:
            return f"NanoSolver: ❌ Invalid or unsafe file path: {file_path}"
        
        if not os.path.exists(safe_path):
            return f"NanoSolver: ❌ Audio file not found: {safe_path}"
        
        # Check file permissions
        if not check_file_permissions(safe_path):
            return f"NanoSolver: ❌ File access denied for security reasons: {safe_path}"
        
        # Check if it's a supported audio file
        supported_extensions = ['.mp3', '.wav', '.ogg', '.m4a', '.aac']
        file_ext = os.path.splitext(safe_path)[1].lower()
        
        if file_ext not in supported_extensions:
            return f"NanoSolver: ❌ Unsupported audio format. Supported: {', '.join(supported_extensions)}"
        
        try:
            # Get file info
            file_size = os.path.getsize(safe_path)
            file_name = os.path.basename(safe_path)
            
            # Add audio control widget
            self.add_audio_widget(safe_path, f"Audio: {file_name}")
            
            return (f"NanoSolver: ✅ Audio loaded successfully!\n"
                   f"File: {file_name}\n"
                   f"Size: {file_size} bytes\n"
                   f"Format: {file_ext.upper()}\n\n"
                   f"Use the audio controls to play/pause/stop.")
                   
        except Exception as e:
            return f"NanoSolver: ❌ Failed to load audio: {str(e)}"

    def scan_system_for_malware(self):
        """Scan system for malware detection"""
        scan_results = []
        scan_results.append("🔍 SYSTEM SECURITY SCAN")
        scan_results.append("="*30)
        scan_results.append("Scanning for potential malware and security issues...")
        
        # 1. Check suspicious processes
        scan_results.append("\n[1] PROCESS SCAN:")
        suspicious_processes = self.scan_suspicious_processes()
        scan_results.extend(suspicious_processes)
        
        # 2. Check suspicious files
        scan_results.append("\n[2] FILE SCAN:")
        suspicious_files = self.scan_suspicious_files()
        scan_results.extend(suspicious_files)
        
        # 3. Check network connections
        scan_results.append("\n[3] NETWORK SCAN:")
        network_issues = self.scan_network_connections()
        scan_results.extend(network_issues)
        
        # 4. Check system integrity
        scan_results.append("\n[4] SYSTEM INTEGRITY:")
        system_issues = self.check_system_integrity()
        scan_results.extend(system_issues)
        
        # 5. Check startup programs
        scan_results.append("\n[5] STARTUP PROGRAMS:")
        startup_issues = self.check_startup_programs()
        scan_results.extend(startup_issues)
        
        # 6. Security monitor report
        scan_results.append("\n[6] SECURITY MONITOR:")
        security_report = self.security_monitor.get_security_report()
        scan_results.extend(security_report.split('\n'))
        
        # 7. Summary
        scan_results.append("\n[7] SCAN SUMMARY:")
        total_warnings = len([r for r in scan_results if "[!]" in r])
        total_info = len([r for r in scan_results if "[*]" in r])
        
        if total_warnings == 0:
            scan_results.append("✅ No obvious security issues detected.")
        else:
            scan_results.append(f"⚠️ Found {total_warnings} potential security issues that need attention.")
        
        scan_results.append(f"📊 Found {total_info} items for review")
        scan_results.append("💡 For comprehensive protection, use dedicated antivirus software.")
        
        return "\n".join(scan_results)

    def scan_suspicious_processes(self):
        """Scan for suspicious processes"""
        results = []
        
        try:
            # Try using system commands to get process list
            if platform.system() == "Windows":
                try:
                    import subprocess
                    # Use tasklist on Windows
                    output = subprocess.check_output(["tasklist", "/fo", "csv"], 
                                                   text=True, timeout=10)
                    processes = [line.split(',')[0].strip('"') for line in output.splitlines()[1:] if line]
                    
                    suspicious_keywords = [
                        'miner', 'coin', 'bitcoin', 'monero', 'crypto', 
                        'keylogger', 'spy', 'trojan', 'backdoor', 'rootkit',
                        'ransom', 'malware', 'virus', 'worm', 'botnet'
                    ]
                    
                    for proc in processes:
                        proc_lower = proc.lower()
                        for keyword in suspicious_keywords:
                            if keyword in proc_lower:
                                results.append(f"[!] Suspicious process name: {proc}")
                                break
                                
                except Exception as e:
                    results.append("[-] Could not scan processes on Windows")
                    
            else:  # Linux/Mac/Android
                try:
                    import subprocess
                    # Use ps command on Unix-like systems
                    output = subprocess.check_output(["ps", "aux"], text=True, timeout=10)
                    lines = output.splitlines()[1:]  # Skip header
                    
                    suspicious_keywords = [
                        'miner', 'coin', 'bitcoin', 'monero', 'crypto', 
                        'keylogger', 'spy', 'trojan', 'backdoor', 'rootkit',
                        'ransom', 'malware', 'virus', 'worm', 'botnet',
                        'xmrig', 'ccminer', 'cpuminer'
                    ]
                    
                    for line in lines:
                        for keyword in suspicious_keywords:
                            if keyword in line.lower():
                                results.append(f"[!] Suspicious process: {line.split()[10] if len(line.split()) > 10 else line}")
                                break
                                
                except Exception as e:
                    results.append("[-] Could not scan processes on this system")
            
        except Exception as e:
            results.append(f"[-] Process scan error: {str(e)}")
        
        if not any("[!]" in r for r in results):
            results.append("[+] No obviously suspicious processes detected")
        else:
            results.append("[*] Install 'psutil' for more detailed process analysis")
            
        return results

    def scan_suspicious_files(self):
        """Scan for suspicious files in more depth"""
        results = []
        
        # Suspicious executable files
        suspicious_extensions = [
            '.exe', '.bat', '.cmd', '.vbs', '.ps1', '.scr',
            '.com', '.pif', '.application', '.gadget', '.msi',
            '.msp', '.scr', '.hta', '.cpl', '.msc', '.jar'
        ]
        
        # Common directories for suspicious files
        scan_directories = [
            os.path.expanduser("~"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/AppData/Local/Temp") if platform.system() == "Windows" else "/tmp"
        ]
        
        # Suspicious filename patterns
        suspicious_patterns = [
            r'cryptominer', r'keylogger', r'trojan', r'backdoor',
            r'ransomware', r'malware', r'virus', r'worm',
            r'bitcoin.*miner', r'monero.*miner', r'crypto.*miner',
            r'crack', r'keygen', r'serial', r'patch'
        ]
        
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in suspicious_patterns]
        
        try:
            for directory in scan_directories:
                if os.path.exists(directory) and is_safe_directory(directory):
                    files_found = 0
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            file_lower = file.lower()
                            
                            # Check suspicious extensions
                            file_ext = os.path.splitext(file)[1].lower()
                            if file_ext in suspicious_extensions:
                                # Check file size (very small files may be suspicious)
                                try:
                                    file_size = os.path.getsize(file_path)
                                    if file_size < 1024:  # Less than 1KB
                                        results.append(f"[!] Very small executable: {file_path} ({file_size} bytes)")
                                    elif file_size > 100 * 1024 * 1024:  # Larger than 100MB
                                        results.append(f"[*] Large executable: {file_path} ({file_size/(1024*1024):.1f} MB)")
                                    else:
                                        results.append(f"[*] Executable found: {file_path}")
                                except:
                                    pass
                            
                            # Check suspicious names
                            for pattern in compiled_patterns:
                                if pattern.search(file_lower):
                                    results.append(f"[!] Suspicious filename: {file_path}")
                                    break
                            
                            # Check double extensions
                            if file.count('.') > 1:
                                name_parts = file.split('.')
                                if len(name_parts) > 2:
                                    # Example: document.pdf.exe
                                    if name_parts[-1].lower() in ['exe', 'bat', 'cmd', 'scr']:
                                        results.append(f"[!] Double extension detected: {file_path}")
                            
                            files_found += 1
                            if files_found > 1000:  # Performance limit
                                break
                        
                        if files_found > 1000:
                            break
                            
        except Exception as e:
            results.append(f"[-] File scan error: {str(e)}")
        
        if not any("[!]" in r for r in results):
            results.append("[+] No obviously suspicious files detected")
        else:
            results.append("[*] Review the flagged files above for potential threats")
            
        return results

    def scan_network_connections(self):
        """Scan network connections"""
        results = []
        
        try:
            # Known suspicious ports
            suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321]
            
            if platform.system() == "Windows":
                try:
                    import subprocess
                    # Use netstat on Windows
                    output = subprocess.check_output(["netstat", "-an"], text=True, timeout=10)
                    for line in output.splitlines():
                        if "ESTABLISHED" in line:
                            for port in suspicious_ports:
                                if f":{port}" in line:
                                    results.append(f"[!] Connection to suspicious port {port}: {line.strip()}")
                                    break
                except:
                    results.append("[-] Could not check network connections on Windows")
            else:
                try:
                    import subprocess
                    # Use netstat on Linux/Mac
                    output = subprocess.check_output(["netstat", "-tunap"], text=True, timeout=10)
                    for line in output.splitlines():
                        if "ESTABLISHED" in line:
                            for port in suspicious_ports:
                                if f":{port} " in line:
                                    results.append(f"[!] Connection to suspicious port {port}")
                                    break
                except:
                    results.append("[-] Could not check network connections on this system")
                    
        except Exception as e:
            results.append(f"[-] Network scan error: {str(e)}")
        
        if not any("[!]" in r for r in results):
            results.append("[+] No suspicious network connections detected")
        else:
            results.append("[*] Install 'psutil' for detailed network connection analysis")
            
        return results

    def check_startup_programs(self):
        """Check startup programs"""
        results = []
        
        try:
            startup_locations = []
            
            if platform.system() == "Windows":
                # Windows startup folders
                startup_locations = [
                    os.path.expanduser("~\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup"),
                    "C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup"
                ]
            else:
                # Linux/Mac/Android startup folders
                startup_locations = [
                    os.path.expanduser("~/.config/autostart"),
                    "/etc/xdg/autostart",
                    os.path.expanduser("~/.bashrc"),
                    os.path.expanduser("~/.bash_profile"),
                    os.path.expanduser("~/.zshrc")
                ]
            
            suspicious_startup_keywords = ['miner', 'crypto', 'keylogger', 'spy', 'trojan']
            
            for location in startup_locations:
                if os.path.exists(location) and is_safe_directory(location):
                    if os.path.isdir(location):
                        for file in os.listdir(location):
                            file_lower = file.lower()
                            for keyword in suspicious_startup_keywords:
                                if keyword in file_lower:
                                    results.append(f"[!] Suspicious startup item: {os.path.join(location, file)}")
                                    break
                    else:  # File
                        try:
                            with open(location, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read().lower()
                                for keyword in suspicious_startup_keywords:
                                    if keyword in content:
                                        results.append(f"[!] Suspicious content in: {location}")
                                        break
                        except:
                            pass
                            
        except Exception as e:
            results.append(f"[-] Startup scan error: {str(e)}")
        
        if not any("[!]" in r for r in results):
            results.append("[+] No suspicious startup programs detected")
            
        return results

    def check_system_integrity(self):
        """Check system integrity"""
        results = []
        
        try:
            # Check for unusual system modifications
            system_dirs = [
                "/etc", "/usr/bin", "/usr/local/bin", 
                "C:\\\\Windows\\\\System32", "C:\\\\Windows\\\\SysWOW64"
            ]
            
            for sys_dir in system_dirs:
                if os.path.exists(sys_dir) and is_safe_directory(sys_dir):
                    # Check for recently modified system files (last 7 days)
                    recent_cutoff = time.time() - (7 * 24 * 60 * 60)
                    try:
                        for root, dirs, files in os.walk(sys_dir):
                            for file in files:
                                file_path = os.path.join(root, file)
                                try:
                                    mod_time = os.path.getmtime(file_path)
                                    if mod_time > recent_cutoff:
                                        # This could indicate system tampering
                                        results.append(f"[*] Recently modified system file: {file_path}")
                                except:
                                    pass
                                
                            # Limit depth for performance
                            if root.count(os.sep) - sys_dir.count(os.sep) > 1:
                                del dirs[:]
                    except:
                        pass
            
            # Check environment variables for suspicious entries
            env_vars = os.environ
            suspicious_env_patterns = ['miner', 'coin', 'crypto', 'bot', 'malware']
            for key, value in env_vars.items():
                for pattern in suspicious_env_patterns:
                    if pattern in key.lower() or pattern in value.lower():
                        results.append(f"[!] Suspicious environment variable: {key}={value}")
                        
        except Exception as e:
            results.append(f"[-] System integrity check error: {str(e)}")
        
        if not any("[!]" in r for r in results):
            results.append("[+] System integrity appears normal")
            
        return results

    def download_and_preview_image(self, url):
        """Download image from URL and preview it"""
        def download_thread():
            try:
                # Check link safety first
                if not validate_url(url):
                    Clock.schedule_once(lambda dt: self.add_message("NanoSolver: ❌ Invalid or unsafe URL", is_user=False), 0.1)
                    return
                
                # Show loading
                Clock.schedule_once(lambda dt: self.show_loading("Downloading image..."), 0.1)
                
                # Download image with security headers
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                response = requests.get(url, timeout=10, headers=headers)
                response.raise_for_status()
                
                # Check content type
                content_type = response.headers.get('content-type', '')
                if not content_type.startswith('image/'):
                    Clock.schedule_once(lambda dt: self.add_message("NanoSolver: ❌ URL does not point to an image", is_user=False), 0.1)
                    return
                
                # Get file extension from URL or content type
                parsed_url = urlparse(url)
                filename = os.path.basename(parsed_url.path)
                if not filename or '.' not in filename:
                    filename = f"image_{int(time.time())}.jpg"
                
                # Create temp directory if not exists
                temp_dir = "temp_images"
                if not os.path.exists(temp_dir):
                    os.makedirs(temp_dir)
                
                # Save image temporarily
                temp_path = os.path.join(temp_dir, filename)
                with open(temp_path, 'wb') as f:
                    f.write(response.content)
                
                # Get image info
                file_size = len(response.content)
                
                # Hide loading and show preview
                Clock.schedule_once(lambda dt: self.hide_loading(), 0.1)
                Clock.schedule_once(lambda dt: self.add_media_widget(
                    file_path=temp_path,
                    file_title=f"Image: {filename}",
                    is_url=False
                ), 0.1)
                
                # Show success message
                info_msg = (f"NanoSolver: ✅ Image downloaded successfully!\n"
                           f"URL: {url}\n"
                           f"Filename: {filename}\n"
                           f"Size: {file_size} bytes\n"
                           f"Type: {content_type}")
                Clock.schedule_once(lambda dt: self.add_message(info_msg, is_user=False), 0.2)
                
            except Exception as download_error:
                # Hide loading and show error
                Clock.schedule_once(lambda dt: self.hide_loading(), 0.1)
                error_msg = f"NanoSolver: ❌ Failed to download image: {str(download_error)}"
                Clock.schedule_once(lambda dt: self.add_message(error_msg, is_user=False), 0.1)
        
        # Start download in background thread
        thread = threading.Thread(target=download_thread)
        thread.daemon = True
        thread.start()

    def preview_image_url(self, url):
        """Preview image directly from URL without downloading"""
        try:
            # Check link safety first
            if not validate_url(url):
                self.add_message("NanoSolver: ❌ Invalid or unsafe URL", is_user=False)
                return
            
            # Show loading
            self.show_loading("Loading image from URL...")
            
            # Schedule media widget with URL
            Clock.schedule_once(lambda dt: self.add_media_widget(
                file_path=url,
                file_title=f"Online Image: {os.path.basename(urlparse(url).path)}",
                is_url=True
            ), 0.1)
            
            # Get URL info
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            filename = os.path.basename(parsed_url.path)
            
            info_msg = (f"NanoSolver: ✅ Image preview loaded from URL!\n"
                       f"Domain: {domain}\n"
                       f"Filename: {filename}\n"
                       f"URL: {url}\n"
                       f"Security: URL validated")
            
            Clock.schedule_once(lambda dt: self.hide_loading(), 0.2)
            Clock.schedule_once(lambda dt: self.add_message(info_msg, is_user=False), 0.3)
            
        except Exception as e:
            Clock.schedule_once(lambda dt: self.hide_loading(), 0.1)
            error_msg = f"NanoSolver: ❌ Failed to load image from URL: {str(e)}"
            Clock.schedule_once(lambda dt: self.add_message(error_msg, is_user=False), 0.1)

    def is_image_url(self, url):
        """Check if URL points to an image"""
        image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg']
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        return any(path.endswith(ext) for ext in image_extensions)

    def search_files(self, directory=".", pattern="*", content_search=None):
        """Search for files with pattern and optional content search"""
        try:
            # Check directory safety
            if not is_safe_directory(directory):
                return "Error: Directory is not safe for searching"
                
            import fnmatch
            matches = []
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if fnmatch.fnmatch(file, pattern):
                        full_path = os.path.join(root, file)
                        
                        # Check file safety
                        if not check_file_permissions(full_path):
                            continue
                        
                        # If content search is specified
                        if content_search:
                            try:
                                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    if content_search.lower() in content.lower():
                                        matches.append(full_path)
                            except:
                                continue
                        else:
                            matches.append(full_path)
            
            return matches
        except Exception as e:
            return f"Error searching files: {str(e)}"

    def get_file_info(self, file_path):
        """Get detailed file information"""
        try:
            if not os.path.exists(file_path):
                return "File not found"
            
            # Check file safety
            if not check_file_permissions(file_path):
                return "File access denied for security reasons"
            
            stat = os.stat(file_path)
            file_size = stat.st_size
            modified_time = datetime.datetime.fromtimestamp(stat.st_mtime)
            created_time = datetime.datetime.fromtimestamp(stat.st_ctime)
            
            info = []
            info.append(f"Name: {os.path.basename(file_path)}")
            info.append(f"Path: {file_path}")
            info.append(f"Size: {file_size} bytes ({file_size/1024:.2f} KB)")
            info.append(f"Created: {created_time}")
            info.append(f"Modified: {modified_time}")
            info.append(f"Type: {self.get_file_type(file_path)}")
            info.append(f"Security: {'Safe' if check_file_permissions(file_path) else 'Warning: Check permissions'}")
            
            # For text files, show line count
            if file_path.endswith(('.txt', '.py', '.js', '.html', '.css', '.md')):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        info.append(f"Lines: {len(lines)}")
                        info.append(f"Characters: {sum(len(line) for line in lines)}")
                except:
                    pass
            
            return "\n".join(info)
        except Exception as e:
            return f"Error getting file info: {str(e)}"

    def get_file_type(self, file_path):
        """Determine file type based on extension"""
        ext = os.path.splitext(file_path)[1].lower()
        file_types = {
            '.txt': 'Text File',
            '.py': 'Python Script',
            '.js': 'JavaScript File',
            '.html': 'HTML Document',
            '.css': 'CSS Stylesheet',
            '.md': 'Markdown File',
            '.jpg': 'JPEG Image',
            '.jpeg': 'JPEG Image',
            '.png': 'PNG Image',
            '.gif': 'GIF Image',
            '.mp4': 'MP4 Video',
            '.avi': 'AVI Video',
            '.mp3': 'MP3 Audio',
            '.wav': 'WAV Audio',
            '.pdf': 'PDF Document',
            '.doc': 'Word Document',
            '.docx': 'Word Document',
            '.xls': 'Excel Spreadsheet',
            '.xlsx': 'Excel Spreadsheet',
            '.zip': 'ZIP Archive',
            '.rar': 'RAR Archive'
        }
        return file_types.get(ext, 'Unknown File Type')

    def analyze_directory(self, directory="."):
        """Analyze directory structure and file statistics"""
        try:
            if not os.path.exists(directory):
                return "Directory not found"
            
            # Check directory safety
            if not is_safe_directory(directory):
                return "Error: Directory is not safe for analysis"
            
            stats = {
                'total_files': 0,
                'total_size': 0,
                'file_types': {},
                'largest_file': ('', 0),
                'oldest_file': ('', float('inf')),
                'newest_file': ('', 0)
            }
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    full_path = os.path.join(root, file)
                    try:
                        # Skip unsafe files
                        if not check_file_permissions(full_path):
                            continue
                            
                        stat = os.stat(full_path)
                        file_size = stat.st_size
                        
                        # Update statistics
                        stats['total_files'] += 1
                        stats['total_size'] += file_size
                        
                        # File type
                        ext = os.path.splitext(file)[1].lower() or 'no extension'
                        stats['file_types'][ext] = stats['file_types'].get(ext, 0) + 1
                        
                        # Largest file
                        if file_size > stats['largest_file'][1]:
                            stats['largest_file'] = (full_path, file_size)
                        
                        # Oldest and newest files
                        if stat.st_mtime < stats['oldest_file'][1]:
                            stats['oldest_file'] = (full_path, stat.st_mtime)
                        if stat.st_mtime > stats['newest_file'][1]:
                            stats['newest_file'] = (full_path, stat.st_mtime)
                            
                    except:
                        continue
            
            # Format results
            result = []
            result.append(f"Directory Analysis: {directory}")
            result.append(f"Total Files: {stats['total_files']}")
            result.append(f"Total Size: {stats['total_size']/1024/1024:.2f} MB")
            result.append(f"Largest File: {os.path.basename(stats['largest_file'][0])} ({stats['largest_file'][1]/1024/1024:.2f} MB)")
            result.append(f"Oldest File: {os.path.basename(stats['oldest_file'][0])} ({datetime.datetime.fromtimestamp(stats['oldest_file'][1])})")
            result.append(f"Newest File: {os.path.basename(stats['newest_file'][0])} ({datetime.datetime.fromtimestamp(stats['newest_file'][1])})")
            result.append("File Types:")
            for ext, count in sorted(stats['file_types'].items(), key=lambda x: x[1], reverse=True)[:10]:
                result.append(f"  {ext}: {count} files")
            
            return "\n".join(result)
        except Exception as e:
            return f"Error analyzing directory: {str(e)}"

    def load_database(self, filename):
        db = {}
        try:
            # Check database file safety
            if not check_file_permissions(filename):
                print("Database file access denied for security")
                return db
                
            with open(filename, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split("||")
                    if len(parts) > 1:
                        q = parts[0].lower()
                        ans = parts[1:]
                        db[q] = ans
        except FileNotFoundError:
            print(f"{filename} not found.")
        return db

    def add_message(self, text, is_user=False):
        """Add new message to chat"""
        if not hasattr(self, 'root') or not self.root or not hasattr(self.root, 'ids'):
            print(f"Message: {text}")
            return
            
        try:
            # Fix newlines in the text before displaying
            if text:
                text = text.replace('\\n', '\n')
            
            if is_user:
                row = ChatRow(text=text, is_user=True, user_color=self.user_bubble_color)
            else:
                row = ChatRow(text=text, is_user=False)
            
            self.root.ids.chat_layout.add_widget(row)
            
            # Delay scrolling to ensure correct height calculation
            Clock.schedule_once(self._scroll_to_bottom, 0.15)
        except Exception as e:
            print(f"Error adding message: {e}")

    def _scroll_to_bottom(self, dt):
        """Scroll to bottom"""
        if hasattr(self, 'root') and self.root and hasattr(self.root, 'ids'):
            try:
                self.root.ids.scroll.scroll_y = 0
            except:
                pass

    def on_focus(self, focus):
        if not hasattr(self, 'root') or not self.root or not hasattr(self.root, 'ids'):
            return
            
        bottom_bar = self.root.ids.bottom_bar
        send_btn = self.root.ids.send_btn
        anim_time = 0.25
        kb_height = self.shift_height
        if focus and not self.shifted:
            Animation(y=bottom_bar.y + kb_height, duration=anim_time, t='out_quad').start(bottom_bar)
            self.shifted = True
        elif not focus and self.shifted:
            Animation(y=bottom_bar.y - kb_height, duration=anim_time, t='out_quad').start(bottom_bar)
            self.shifted = False

    def process_command(self, command):
        if self.processing_command:
            return
            
        if not hasattr(self, 'root') or not self.root or not hasattr(self.root, 'ids'):
            return
            
        ui = self.root
        user_input = ui.ids.user_input
        if not command or not command.strip():
            return
            
        # Clean and sanitize inputs
        cmd = sanitize_input(command.strip())
        
        # Log activity in security monitor
        self.security_monitor.log_activity(cmd)
        
        # Detect brute force attacks
        if self.security_monitor.check_brute_force(cmd):
            self.add_message("NanoSolver: ⚠️ Suspicious activity detected - too many failed attempts", is_user=False)
            self.processing_command = False
            return
        
        # Detect dangerous commands
        dangerous_commands = ['rm -rf', 'format', 'del ', 'shutdown', 'reboot', 'mkfs', 'passwd']
        if any(dangerous_cmd in cmd.lower() for dangerous_cmd in dangerous_commands):
            self.add_message("NanoSolver: ❌ Dangerous command blocked for security reasons", is_user=False)
            self.processing_command = False
            return
        
        self.add_message(f"{self.user_name}: {cmd}", is_user=True)
        user_input.text = ""
        self.processing_command = True

        # Show loading indicator
        loading_messages = {
            'scan system': '🔍 Scanning system for malware...',
            'behavior scan': '🧠 Analyzing system behavior...',
            'behavior monitor': '📊 Monitoring real-time behavior...',
            'deepscan': '🌐 Performing deep website scan...',
            'autoscan': '🚀 Running auto security scan...',
            'analyzelogs': '📊 Analyzing security logs...',
            'play': '🎵 Loading audio...',
            'scan': '🔍 Scanning website...',
            'explain': '🔍 Searching GitHub...', 
            'open': '📖 Fetching README...',
            'dns': '🌐 Performing DNS lookup...',
            'ping': '📡 Pinging host...',
            'whois': '🔍 Querying WHOIS...',
            'ports': '🔒 Scanning ports...',
            'hash': '🔐 Hashing...',
            'encode': '🔒 Encoding...',
            'decode': '🔓 Decoding...',
            'genpass': '🔑 Generating password...',
            'passwords': '🔑 Generating multiple passwords...',
            'server': '🌐 Starting server...',
            'stop': '🛑 Stopping server...',
            'search': '🔍 Searching files...',
            'analyze': '📊 Analyzing directory...',
            'preview': '🖼️ Loading media...',
            'security': '🔒 Security check...',
            'hardening': '🛡️ Generating security tips...'
        }
        
        loading_msg = 'Processing command...'
        for key, msg in loading_messages.items():
            if cmd.lower().startswith(key):
                loading_msg = msg
                break
                
        self.show_loading(loading_msg)

        # Process command in background thread
        thread = threading.Thread(target=self._execute_command, args=(cmd,))
        thread.daemon = True
        thread.start()

    def _execute_command(self, cmd):
        """Execute command in background thread"""
        try:
            result = self._process_command_internal(cmd)
            
            # Log successful execution
            self.security_monitor.log_activity(cmd, success=True)
            
            # Schedule UI updates on main thread
            Clock.schedule_once(lambda dt: self._show_result(result), 0.1)
            
        except Exception as e:
            # Log failed execution
            self.security_monitor.log_activity(cmd, success=False)
            
            error_msg = f"❌ Error executing command: {str(e)}"
            Clock.schedule_once(lambda dt: self._show_result(error_msg), 0.1)

    def _show_result(self, result):
        """Show result in UI - runs on main thread"""
        self.hide_loading()
        # Only stream text responses, not media widgets
        if isinstance(result, str):
            self.start_streaming_response(result)
        self.processing_command = False

    def generate_multiple_passwords(self, count=10, length=16):
        """Generate multiple secure passwords at once"""
        passwords = []
        for i in range(count):
            password = self.genpass_advanced(length)
            passwords.append(password)
        
        # Copy all passwords to clipboard
        all_passwords = "\n".join(passwords)
        try:
            Clipboard.copy(all_passwords)
        except Exception as e:
            print(f"Could not copy to clipboard: {e}")
        
        return passwords

    def genpass_advanced(self, length=16):
        """Generate a single secure password with better randomness"""
        try:
            length = int(length)
        except Exception:
            length = 16
        
        if length < 8:
            length = 8
        if length > 64:
            length = 64

        # Character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()-_=+[]{};:,.<>/?"
        
        # Ensure at least one of each category
        password_chars = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(symbols)
        ]
        
        # Fill the rest with random characters from all sets
        all_chars = lowercase + uppercase + digits + symbols
        password_chars.extend(secrets.choice(all_chars) for _ in range(length - len(password_chars)))
        
        # Shuffle thoroughly
        secrets.SystemRandom().shuffle(password_chars)
        
        return "".join(password_chars)

    def get_local_ip(self):
        """Get local IP address"""
        try:
            # Connect to external address to get device IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"  # fallback to localhost

    def github_search(self, query, per_page=5):
        api = "https://api.github.com/search/repositories"
        headers = {"Accept": "application/vnd.github.v3+json"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"token {GITHUB_TOKEN}"
        params = {"q": f"{query} in:name,description", "sort": "stars", "order": "desc", "per_page": per_page}
        try:
            r = requests.get(api, params=params, headers=headers, timeout=8)
            if r.status_code != 200:
                return {"error": f"GitHub API {r.status_code} - {r.text[:200]}"}
            j = r.json()
            items = []
            for it in j.get("items", []):
                items.append({
                    "full_name": it.get("full_name"),
                    "name": it.get("name"),
                    "description": it.get("description") or "",
                    "html_url": it.get("html_url"),
                    "stargazers_count": it.get("stargazers_count", 0),
                    "forks_count": it.get("forks_count", 0),
                    "license": (it.get("license") or {}).get("name") if it.get("license") else "No license",
                    "language": it.get("language"),
                    "owner": it.get("owner", {}).get("login")
                })
            return {"items": items}
        except requests.RequestException as e:
            return {"error": f"Network error: {e}"}

    def github_get_readme(self, full_name):
        api = f"https://api.github.com/repos/{full_name}/readme"
        headers = {"Accept": "application/vnd.github.v3+json"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"token {GITHUB_TOKEN}"
        try:
            r = requests.get(api, headers=headers, timeout=8)
            if r.status_code == 404:
                return {"error": "README not found"}
            if r.status_code != 200:
                return {"error": f"GitHub API {r.status_code}: {r.text[:200]}"}
            j = r.json()
            content_b64 = j.get("content", "")
            encoding = j.get("encoding", "base64")
            if encoding == "base64":
                raw = base64.b64decode(content_b64).decode(errors="ignore")
                return {"content": raw}
            else:
                return {"error": "Unknown README encoding"}
        except requests.RequestException as e:
            return {"error": f"Network error: {e}"}

    def genpass(self, length=16):
        try:
            length = int(length)
        except Exception:
            length = 16
        if length < 4:
            length = 4
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>/?"
        # ensure at least one of each category
        pw = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*()-_=+")
        ]
        pw += [secrets.choice(alphabet) for _ in range(length - len(pw))]
        secrets.SystemRandom().shuffle(pw)
        return "".join(pw)

    def sanitize_readme(self, text):
        if not text:
            return text
        dangerous_patterns = [
            r'curl\s+[^\n\r]*\|\s*sh',
            r'wget\s+[^\n\r]*\|\s*sh',
            r'bash\s+<\(\s*curl',
            r'curl\s+-sSL\s+[^\n\r]*\|\s*sh',
            r'pip\s+install\s+https?://',
            r'python\s+-c\s+["\'].*base64',
            r'rm\s+-rf\s+/',
            r'rm\s+-rf\s+\S+',
            r'sshpass',
            r'nc\s+-e',
            r'perl\s+-e',
            r'curl\s+--output',
            r'wget\s+-O',
            r'chmod\s+\+\w+\s+[^\n\r]*',
            r'openssl\s+.*\s*enc',
        ]
        regs = [re.compile(p, re.IGNORECASE) for p in dangerous_patterns]

        out_lines = []
        for line in text.splitlines():
            stripped = line.strip()
            redacted = False
            for rx in regs:
                if rx.search(line):
                    out_lines.append("[REDACTED - potentially dangerous command or download blocked]")
                    redacted = True
                    break
            if redacted:
                continue
            if re.match(r'^\s*\$.*', line):
                out_lines.append("[REDACTED - shell prompt snippet removed]")
                continue
            out_lines.append(line)
        sanitized = "\n".join(out_lines)
        if "[REDACTED" in sanitized:
            banner = ("\n\n[WARNING] Some lines were redacted because they contained commands or downloads that "
                      "could be dangerous if executed. Review the repository manually in an isolated environment.")
            sanitized = sanitized + banner
        return sanitized

    def extract_installation_sections(self, readme_text, max_chars=2000):
        if not readme_text:
            return None
        pattern = re.compile(r'(^|\n)(#{1,6}\s*(installation|install|usage|setup|getting started|quick start|requirements)\b.*?)(\n#|\Z)', re.IGNORECASE | re.DOTALL)
        matches = pattern.findall("\n" + readme_text)
        extracted = []
        for m in matches:
            block = m[1].strip()
            block = re.sub(r'^#{1,6}\s*', '', block).strip()
            extracted.append(block[:max_chars].strip())
        if extracted:
            return "\n\n---\n\n".join(extracted)
        lines = readme_text.splitlines()
        candidates = []
        for i, L in enumerate(lines):
            if re.search(r'\binstall\b', L, re.IGNORECASE):
                snippet = "\n".join(lines[max(0, i-3): min(len(lines), i+6)])
                candidates.append(snippet)
        if candidates:
            return "\n\n---\n\n".join([c[:max_chars] for c in candidates])
        return None

    def safe_eval(self, expr):
        allowed_nodes = {
            ast.Expression, ast.BinOp, ast.UnaryOp, ast.Num, ast.Load,
            ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow, ast.FloorDiv,
            ast.USub, ast.UAdd, ast.Call, ast.Name, ast.Tuple, ast.List, ast.Subscript,
            ast.Index, ast.Slice, ast.Attribute
        }
        import math
        safe_names = {k: getattr(math, k) for k in
                      ("sqrt", "sin", "cos", "tan", "asin", "acos", "atan",
                       "log", "log10", "exp", "floor", "ceil", "fabs", "factorial")}
        safe_names.update({"pi": math.pi, "e": math.e})

        try:
            node = ast.parse(expr, mode='eval')
        except Exception as e:
            return f"Error parsing expression: {e}"

        for n in ast.walk(node):
            if not isinstance(n, tuple(allowed_nodes)):
                return "Expression contains disallowed elements."
            if isinstance(n, ast.Attribute):
                return "Attribute access is not allowed."

        try:
            code = compile(node, "<safe_expr>", "eval")
            return str(eval(code, {"__builtins__": {}}, safe_names))
        except Exception as e:
            return f"Error evaluating expression: {e}"

    def get_battery_info(self):
        possible = [
            "/sys/class/power_supply/BAT0/capacity",
            "/sys/class/power_supply/battery/capacity",
            "/sys/class/power_supply/BAT1/capacity",
        ]
        for p in possible:
            if os.path.exists(p):
                try:
                    with open(p, "r") as f:
                        val = f.read().strip()
                        return f"{val}%"
                except:
                    pass
        try:
            import subprocess
            p = subprocess.run(["upower", "-i", "/org/freedesktop/UPower/devices/battery_BAT0"], capture_output=True, text=True)
            out = p.stdout
            m = re.search(r'percentage:\s+([0-9]+%)', out)
            if m:
                return m.group(1)
        except Exception:
            pass
        try:
            import psutil
            bat = psutil.sensors_battery()
            if bat:
                return f"{int(bat.percent)}% {'(charging)' if bat.power_plugged else ''}"
        except Exception:
            pass
        return "Battery info not available"

    def list_files(self, path="."):
        try:
            if not os.path.exists(path):
                return f"Path '{path}' does not exist"
            
            # Check path safety
            if not is_safe_directory(path):
                return f"Access to path '{path}' is restricted for security"
            
            items = os.listdir(path)
            if not items:
                return "Directory is empty"
            
            # Separate files and directories
            dirs = []
            files = []
            
            for item in items:
                full_path = os.path.join(path, item)
                try:
                    if os.path.isdir(full_path):
                        dirs.append(f"📁 {item}/")
                    else:
                        size = os.path.getsize(full_path)
                        files.append(f"📄 {item} ({size} bytes)")
                except:
                    files.append(f"📄 {item} (access denied)")
            
            # Alphabetical order
            dirs.sort()
            files.sort()
            
            result = []
            if dirs:
                result.append("📁 Directories:")
                result.extend(dirs[:20])  # Limit to 20 items
            if files:
                result.append("\n📄 Files:")
                result.extend(files[:20])
            
            if len(dirs) > 20 or len(files) > 20:
                result.append(f"\n... and {max(0, len(dirs)-20) + max(0, len(files)-20)} more items")
            
            return "\n".join(result)
            
        except Exception as e:
            return f"Error listing files: {str(e)}"

    def read_file_head(self, filename, lines=20):
        try:
            if not os.path.exists(filename):
                return f"File '{filename}' not found"
            
            # Check file safety
            if not check_file_permissions(filename):
                return "File access denied for security reasons"
            
            # Check file size
            file_size = os.path.getsize(filename)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                return f"File too large ({file_size/1024/1024:.1f} MB). Use a smaller file."
            
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                content_lines = []
                for i, line in enumerate(f):
                    if i >= lines:
                        content_lines.append(f"... and {file_size} bytes more")
                        break
                    content_lines.append(line.rstrip())
                
                return "\n".join(content_lines)
                
        except Exception as e:
            return f"Error reading file: {str(e)}"

    def get_system_info(self):
        info = []
        
        # Platform
        info.append(f"Platform: {platform.system()} {platform.release()}")
        info.append(f"Architecture: {platform.architecture()[0]}")
        info.append(f"Processor: {platform.processor() or 'Unknown'}")
        
        # Memory
        try:
            if psutil:
                memory = psutil.virtual_memory()
                info.append(f"Memory: {memory.percent}% used ({memory.used//(1024**3)}GB/{memory.total//(1024**3)}GB)")
                
                # CPU
                cpu_percent = psutil.cpu_percent(interval=0.1)
                info.append(f"CPU: {cpu_percent}% used")
                
                # Disk
                disk = psutil.disk_usage('/')
                info.append(f"Disk: {disk.percent}% used ({disk.used//(1024**3)}GB/{disk.total//(1024**3)}GB)")
            else:
                info.append("Install 'psutil' for detailed system info")
        except:
            info.append("System monitoring not available")
        
        # Python version
        info.append(f"Python: {platform.python_version()}")
        
        # User
        try:
            import getpass
            info.append(f"User: {getpass.getuser()}")
        except:
            pass
        
        # Working directory
        info.append(f"Current directory: {os.getcwd()}")
        
        return "\n".join(info)

    def scan_website(self, url):
        """Basic website scan"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Validate URL
            if not validate_url(url):
                return "Invalid or unsafe URL"
            
            results = []
            results.append(f"Scanning: {url}")
            results.append("=" * 40)
            
            # Check SSL/HTTPS
            if url.startswith('https://'):
                results.append("🔒 HTTPS: Enabled (Secure)")
            else:
                results.append("⚠️ HTTP: No encryption (Insecure)")
            
            try:
                response = requests.get(url, timeout=10, verify=False)
                results.append(f"📊 Status Code: {response.status_code}")
                
                # Check security headers
                security_headers = [
                    'Content-Security-Policy',
                    'X-Content-Type-Options', 
                    'X-Frame-Options',
                    'Strict-Transport-Security',
                    'X-XSS-Protection'
                ]
                
                results.append("\n🔍 Security Headers:")
                for header in security_headers:
                    if header in response.headers:
                        results.append(f"  ✅ {header}: Present")
                    else:
                        results.append(f"  ❌ {header}: Missing")
                
                # Check information leaks
                server_info = response.headers.get('Server', '')
                if server_info:
                    results.append(f"ℹ️ Server: {server_info}")
                
                # Check external links
                external_links = re.findall(r'href="(https?://[^"]*)"', response.text)
                unique_domains = set()
                for link in external_links:
                    domain = urlparse(link).netloc
                    if domain not in unique_domains and domain != urlparse(url).netloc:
                        unique_domains.add(domain)
                
                if unique_domains:
                    results.append(f"\n🌐 External domains referenced: {len(unique_domains)}")
                
            except requests.RequestException as e:
                results.append(f"❌ Connection failed: {str(e)}")
            
            return "\n".join(results)
            
        except Exception as e:
            return f"Scan error: {str(e)}"

    def headers_for(self, url):
        """Get HTTP headers"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            if not validate_url(url):
                return "Invalid or unsafe URL"
            
            response = requests.head(url, timeout=10, verify=False)
            headers = []
            headers.append(f"Headers for: {url}")
            headers.append("=" * 30)
            
            for key, value in response.headers.items():
                headers.append(f"{key}: {value}")
            
            return "\n".join(headers)
            
        except Exception as e:
            return f"Error getting headers: {str(e)}"

    def check_ssl(self, domain):
        """Check SSL certificate"""
        try:
            if not validate_domain(domain):
                return "Invalid domain"
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    info = []
                    info.append(f"SSL Certificate for: {domain}")
                    info.append("=" * 35)
                    
                    # Basic information
                    if 'subject' in cert:
                        subject = dict(x[0] for x in cert['subject'])
                        info.append(f"Subject: {subject.get('commonName', 'N/A')}")
                    
                    # Expiration date
                    if 'notAfter' in cert:
                        from datetime import datetime
                        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_left = (expire_date - datetime.now()).days
                        info.append(f"Expires: {expire_date.strftime('%Y-%m-%d')} ({days_left} days left)")
                    
                    # Issuer
                    if 'issuer' in cert:
                        issuer = dict(x[0] for x in cert['issuer'])
                        info.append(f"Issuer: {issuer.get('organizationName', 'N/A')}")
                    
                    return "\n".join(info)
                    
        except Exception as e:
            return f"SSL check failed: {str(e)}"

    def read_robots(self, domain):
        """Read robots.txt file"""
        try:
            if not validate_domain(domain):
                return "Invalid domain"
            
            url = f"https://{domain}/robots.txt"
            response = requests.get(url, timeout=10, verify=False)
            
            if response.status_code == 200:
                return f"robots.txt for {domain}:\n\n{response.text}"
            else:
                return f"robots.txt not found (Status: {response.status_code})"
                
        except Exception as e:
            return f"Error reading robots.txt: {str(e)}"

    def dns_lookup(self, domain):
        """DNS lookup"""
        try:
            if not validate_domain(domain):
                return "Invalid domain"
            
            results = []
            results.append(f"DNS Lookup for: {domain}")
            results.append("=" * 30)
            
            # Common DNS queries
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
            
            for record_type in record_types:
                try:
                    if dns_resolver:
                        answers = dns_resolver.resolve(domain, record_type)
                        if answers:
                            results.append(f"\n{record_type}:")
                            for answer in answers:
                                results.append(f"  {answer}")
                    else:
                        # Fallback without dnspython
                        if record_type == 'A':
                            ip = socket.gethostbyname(domain)
                            results.append(f"\nA: {ip}")
                        break
                except:
                    results.append(f"\n{record_type}: No records")
            
            if not dns_resolver:
                results.append("\n💡 Install 'dnspython' for full DNS lookup")
            
            return "\n".join(results)
            
        except Exception as e:
            return f"DNS lookup failed: {str(e)}"

    def ping_host(self, target):
        """Send ping requests"""
        try:
            import subprocess
            
            # Clean target
            target = sanitize_input(target)
            
            if platform.system().lower() == "Windows":
                cmd = ["ping", "-n", "4", target]
            else:
                cmd = ["ping", "-c", "4", target]
            
            # Check command safety
            is_safe, reason = safe_system_command(' '.join(cmd))
            if not is_safe:
                return f"Command blocked: {reason}"
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                return f"Ping results for {target}:\n\n{result.stdout}"
            else:
                return f"Ping failed for {target}:\n\n{result.stderr}"
                
        except subprocess.TimeoutExpired:
            return "Ping timeout - host may be down or blocking ICMP"
        except Exception as e:
            return f"Ping error: {str(e)}"

    def common_ports_scan(self, host):
        """Scan common ports"""
        try:
            # Clean host
            host = sanitize_input(host)
            
            common_ports = {
                21: "FTP",
                22: "SSH", 
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                80: "HTTP",
                110: "POP3",
                143: "IMAP",
                443: "HTTPS",
                587: "SMTP SSL",
                993: "IMAP SSL",
                995: "POP3 SSL",
                1433: "MSSQL",
                3306: "MySQL",
                3389: "RDP",
                5432: "PostgreSQL",
                5900: "VNC",
                6379: "Redis",
                27017: "MongoDB"
            }
            
            results = []
            results.append(f"Port scan for: {host}")
            results.append("=" * 30)
            
            open_ports = []
            
            for port, service in common_ports.items():
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(2)
                        result = sock.connect_ex((host, port))
                        if result == 0:
                            open_ports.append(f"✅ {port}/tcp - {service} - OPEN")
                        else:
                            open_ports.append(f"❌ {port}/tcp - {service} - Closed")
                except:
                    open_ports.append(f"⚠️ {port}/tcp - {service} - Error")
            
            results.extend(open_ports)
            results.append(f"\n📊 Summary: {len([p for p in open_ports if 'OPEN' in p])} open ports out of {len(common_ports)} checked")
            
            return "\n".join(results)
            
        except Exception as e:
            return f"Port scan error: {str(e)}"

    def subdomain_discover(self, domain):
        """Discover subdomains"""
        try:
            if not validate_domain(domain):
                return "Invalid domain"
            
            common_subdomains = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
                'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
                'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
                'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
                'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
                'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3',
                'upload', 'mysql', 'private', 'vhost', 'forums', 'files', 'dhcp', 'server',
                'apps', 'online', 'ads', 'sms', 'chat', 'search', 'site', 'sites', 'backup',
                'join', 'meet', 'portal', 'live', 'cms', 'signin', 'signup', 'support',
                'help', 'kb', 'knowledgebase', 'host', 'img', 'images', 'assets', 'cdn',
                'static', 'media', 'uploads', 'download', 'downloads', 'ftp', 'file',
                'files', 'storage', 'db', 'database', 'dev', 'development', 'staging',
                'stage', 'test', 'testing', 'qa', 'prod', 'production', 'backup', 'bak',
                'archive', 'old', 'new', 'temp', 'tmp', 'm', 'mobile', 'app', 'apps',
                'api', 'apis', 'rest', 'soap', 'graphql', 'web', 'webapp', 'webapps',
                'service', 'services', 'microservice', 'microservices', 'gateway',
                'proxy', 'cache', 'cdn', 'loadbalancer', 'lb', 'cluster', 'k8s',
                'kubernetes', 'docker', 'container', 'vm', 'virtual', 'cloud', 'aws',
                'azure', 'gcp', 'google', 'ibm', 'oracle', 'alibaba', 'digitalocean',
                'linode', 'vultr', 'heroku', 'netlify', 'vercel', 'github', 'gitlab',
                'bitbucket', 'jenkins', 'travis', 'circleci', 'git', 'svn', 'cvs',
                'monitor', 'monitoring', 'metrics', 'grafana', 'prometheus', 'alert',
                'alerts', 'alertmanager', 'log', 'logs', 'logging', 'elk', 'kibana',
                'elastic', 'splunk', 'graylog', 'audit', 'auditing', 'compliance',
                'security', 'firewall', 'fw', 'ips', 'ids', 'waf', 'ddos', 'antivirus',
                'av', 'malware', 'virus', 'threat', 'threats', 'vulnerability',
                'vulnerabilities', 'patch', 'patching', 'update', 'updates', 'upgrade',
                'upgrades', 'hotfix', 'hotfixes', 'bugfix', 'bugfixes', 'critical',
                'emergency', 'urgent', 'important', 'major', 'minor', 'trivial',
                'blocker', 'critical', 'high', 'medium', 'low', 'info', 'debug',
                'trace', 'warning', 'error', 'fatal', 'panic', 'crash', 'crashes',
                'failure', 'failures', 'exception', 'exceptions', 'stacktrace',
                'stacktraces', 'core', 'dump', 'dumps', 'memory', 'leak', 'leaks',
                'performance', 'perf', 'benchmark', 'benchmarks', 'load', 'stress',
                'capacity', 'scalability', 'availability', 'reliability', 'durability',
                'consistency', 'latency', 'throughput', 'bandwidth', 'iops', 'qps',
                'rps', 'tps', 'connections', 'sessions', 'users', 'visitors', 'hits',
                'requests', 'responses', 'status', 'codes', 'redirects', 'errors',
                'timeouts', 'retries', 'circuitbreaker', 'fuse', 'fuses', 'bulkhead',
                'bulkheads', 'ratelimit', 'ratelimits', 'quota', 'quotas', 'throttle',
                'throttling', 'backoff', 'backpressure', 'loadshedding', 'failover',
                'failovers', 'redundancy', 'redundant', 'replication', 'replicas',
                'cluster', 'clusters', 'shard', 'shards', 'partition', 'partitions',
                'segment', 'segments', 'region', 'regions', 'zone', 'zones', 'dc',
                'datacenter', 'datacenters', 'rack', 'racks', 'server', 'servers',
                'node', 'nodes', 'instance', 'instances', 'container', 'containers',
                'pod', 'pods', 'deployment', 'deployments', 'daemonset', 'daemonsets',
                'statefulset', 'statefulsets', 'job', 'jobs', 'cronjob', 'cronjobs',
                'service', 'services', 'ingress', 'ingresses', 'egress', 'egresses',
                'network', 'networks', 'subnet', 'subnets', 'vpc', 'vpcs', 'cidr',
                'cidrs', 'ip', 'ips', 'dns', 'domain', 'domains', 'subdomain',
                'subdomains', 'host', 'hosts', 'hostname', 'hostnames', 'fqdn',
                'fqdns', 'url', 'urls', 'uri', 'uris', 'endpoint', 'endpoints',
                'route', 'routes', 'path', 'paths', 'query', 'queries', 'parameter',
                'parameters', 'header', 'headers', 'cookie', 'cookies', 'session',
                'sessions', 'token', 'tokens', 'jwt', 'jwts', 'oauth', 'openid',
                'saml', 'ldap', 'kerberos', 'active directory', 'ad', 'radius',
                'tacacs', 'certificate', 'certificates', 'pki', 'ca', 'cas', 'ssl',
                'tls', 'https', 'http', 'ftp', 'sftp', 'scp', 'ssh', 'telnet',
                'rdp', 'vnc', 'snmp', 'icmp', 'tcp', 'udp', 'ip', 'ipv4', 'ipv6',
                'ethernet', 'wifi', 'bluetooth', 'zigbee', 'lorawan', 'nbiot',
                'cellular', 'gsm', 'cdma', 'lte', '5g', 'satellite', 'fiber',
                'copper', 'wireless', 'wired', 'lan', 'wan', 'man', 'pan', 'wan',
                'internet', 'intranet', 'extranet', 'vpn', 'vpns', 'tunnel',
                'tunnels', 'proxy', 'proxies', 'gateway', 'gateways', 'router',
                'routers', 'switch', 'switches', 'firewall', 'firewalls', 'ids',
                'ips', 'waf', 'loadbalancer', 'loadbalancers', 'cdn', 'cdns',
                'dns', 'dhcp', 'ntp', 'smtp', 'pop3', 'imap', 'http', 'https',
                'ftp', 'sftp', 'scp', 'ssh', 'telnet', 'rdp', 'vnc', 'snmp',
                'icmp', 'tcp', 'udp', 'ip', 'ipv4', 'ipv6'
            ]
            
            found_subdomains = []
            
            for sub in common_subdomains[:50]:  # Limit to 50 for performance
                subdomain = f"{sub}.{domain}"
                try:
                    socket.gethostbyname(subdomain)
                    found_subdomains.append(f"✅ {subdomain}")
                except:
                    continue
            
            results = []
            results.append(f"Subdomain discovery for: {domain}")
            results.append("=" * 40)
            
            if found_subdomains:
                results.append(f"Found {len(found_subdomains)} subdomains:")
                results.extend(found_subdomains)
            else:
                results.append("No common subdomains found")
            
            results.append(f"\n💡 Scanned {len(common_subdomains[:50])} common subdomains")
            
            return "\n".join(results)
            
        except Exception as e:
            return f"Subdomain discovery error: {str(e)}"

    def whois_lookup(self, domain):
        """WHOIS lookup"""
        try:
            if not validate_domain(domain):
                return "Invalid domain"
            
            if pywhois:
                w = pywhois.whois(domain)
                return f"WHOIS for {domain}:\n\n{str(w)}"
            else:
                return "WHOIS lookup requires 'python-whois' library: pip install python-whois"
                
        except Exception as e:
            return f"WHOIS lookup failed: {str(e)}"

    def vuln_quick(self, domain):
        """Quick vulnerability check"""
        try:
            if not validate_domain(domain):
                return "Invalid domain"
            
            results = []
            results.append(f"Quick vulnerability assessment for: {domain}")
            results.append("=" * 50)
            
            # Check open ports
            common_vuln_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900]
            
            open_vuln_ports = []
            for port in common_vuln_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(2)
                        result = sock.connect_ex((domain, port))
                        if result == 0:
                            open_vuln_ports.append(port)
                except:
                    pass
            
            if open_vuln_ports:
                results.append(f"⚠️ Open ports that may need review: {open_vuln_ports}")
            else:
                results.append("✅ No obviously vulnerable ports found")
            
            # Check HTTPS
            try:
                response = requests.get(f"https://{domain}", timeout=5, verify=False)
                if response.status_code == 200:
                    results.append("✅ HTTPS is accessible")
                else:
                    results.append(f"⚠️ HTTPS returned status: {response.status_code}")
            except:
                results.append("❌ HTTPS not accessible")
            
            # Check HTTP
            try:
                response = requests.get(f"http://{domain}", timeout=5)
                if response.status_code == 200:
                    results.append("⚠️ HTTP is accessible (consider redirecting to HTTPS)")
            except:
                results.append("✅ HTTP not accessible")
            
            # Check security headers
            try:
                response = requests.head(f"https://{domain}", timeout=5)
                security_headers = ['Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options']
                missing_headers = []
                
                for header in security_headers:
                    if header not in response.headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    results.append(f"⚠️ Missing security headers: {missing_headers}")
                else:
                    results.append("✅ All basic security headers present")
                    
            except:
                results.append("❌ Could not check security headers")
            
            results.append("\n💡 This is a basic check. Use 'deepscan' for comprehensive analysis")
            
            return "\n".join(results)
            
        except Exception as e:
            return f"Vulnerability check failed: {str(e)}"

    def hash_sha256(self, text):
        """Hash text using SHA256"""
        return hashlib.sha256(text.encode()).hexdigest()

    def b64_encode(self, text):
        """Base64 encode"""
        return base64.b64encode(text.encode()).decode()

    def b64_decode(self, text):
        """Base64 decode"""
        try:
            return base64.b64decode(text).decode()
        except:
            return "Invalid base64 string"

    def run_command(self, cmd):
        """Run simple commands"""
        cmd_lower = cmd.lower().strip()
        
        if cmd_lower in ['help', 'commands', 'menu']:
            return self.show_help()
        
        elif cmd_lower in ['clear', 'reset']:
            if hasattr(self, 'root') and self.root and hasattr(self.root, 'ids'):
                self.root.ids.chat_layout.clear_widgets()
            return "NanoSolver: 💬 Chat cleared"
        
        elif cmd_lower in ['about', 'info']:
            return ("NanoSolver v2 - Reality Edition \n"
                   "🔒 Advanced Security Toolkit with:\n"
                   "• Website Vulnerability Scanning\n"
                   "• System Security Monitoring\n"
                   "• Behavior Analysis \n"
                   "• Log Analysis \n"
                   "• Auto Hardening Tips \n"
                   "• PDF Report Generation \n \n"
                   "💡 Type 'help' for complete command list")
        
        elif cmd_lower in ['version', 'ver']:
            return "NanoSolver v2.0 - Reality Edition"
        
        elif cmd_lower in ['exit', 'quit']:
            # Stop all servers before exit
            self.server_manager.stop_all_servers()
            return "NanoSolver: 👋 Goodbye! Stopping all services..."
        
        else:
            # Search in database
            query = cmd_lower
            if query in self.db:
                answers = self.db[query]
                return f"NanoSolver: {random.choice(answers)}"
            else:
                return ("NanoSolver: ❓ Command not recognized"
                       "💡 Try these commands:\n"
                       "• 'help' - Show all commands\n"
                       "• 'scan system' - Security scan\n" 
                       "• 'autoscan example.com' - Auto website scan\n"
                       "• 'deepscan url' - Deep website analysis\n"
                       "• 'behavior scan' - Behavior analysis \n"
                       "• 'analyzelogs' - Log analysis \n"
                       "• 'hardening' - Security tips")

    def show_help(self):
        """Show command list with plugin commands included"""
        plugin_commands = self.plugin_manager.get_plugin_commands()
        
        help_text = [
            "🚀 NANO SOLVER v2 - COMPLETE COMMAND LIST",
            "=" * 50,
            "",
            "🔌 PLUGIN SYSTEM:",
            "  plugins - List all loaded plugins and commands",
            "  reload plugins - Reload all plugins",
            "  plugin info <name> - Show detailed plugin information",
        ]
        
        # Add plugin commands to help
        if plugin_commands:
            help_text.append("")
            help_text.append("🔌 PLUGIN COMMANDS:")
            for cmd in plugin_commands:
                short_desc = cmd['description'].split('\n')[0] if cmd['description'] else "No description"
                help_text.append(f"  {cmd['command']} - {short_desc}")
        
        # Add the rest of existing help text
        help_text.extend([
            "",
            "🔒 SECURITY SCANNING:",
            "  scan system - Full system security scan",
            "  scan <url> - Basic website security scan", 
            "  autoscan <url> - Auto comprehensive website scan",
            "  deepscan <url> - Deep website vulnerability analysis",
            "  headers <url> - Show HTTP headers",
            "  ssl <domain> - Check SSL certificate",
            "  ports <host> - Scan common ports",
            "  dns <domain> - DNS lookup",
            "  whois <domain> - WHOIS information",
            "  subdomains <domain> - Discover subdomains",
            "  robots <domain> - Check robots.txt",
            "  ping <host> - Ping a host",
            "",
            "🧠 BEHAVIOR & MONITORING:",
            "  behavior scan - System behavior analysis", 
            "  behavior monitor - Real-time behavior monitoring",
            "  security report - Security activity report",
            "  analyzelogs <log data> - Analyze security logs",
            "",
            "🛡️ SECURITY HARDENING:",
            "  hardening - Auto security hardening tips",
            "  security tips - Security recommendations",
            "",
            "📁 FILE & SYSTEM:",
            "  ls [path] - List files and directories",
            "  read <file> - Read file content",
            "  search <pattern> [in path] - Search files",
            "  fileinfo <file> - Detailed file information", 
            "  analyze [path] - Analyze directory structure",
            "  largefiles <size_mb> [path] - Find large files",
            "  systeminfo - System information",
            "  battery - Battery status",
            "  path - Current directory",
            "",
            "🌐 NETWORK & SERVERS:",
            "  server [port] [dir] - Start HTTP server",
            "  stop <port> - Stop specific server", 
            "  stop all - Stop all servers",
            "  servers - List running servers",
            "  safe ports - Show safe port suggestions",
            "",
            "🔧 UTILITIES:",
            "  calculate <expression> - Safe calculator",
            "  time - Current date and time", 
            "  genpass [length] - Generate password",
            "  passwords [count] [length] - Generate multiple passwords",
            "  hash <text> - SHA256 hash",
            "  encode <text> - Base64 encode",
            "  decode <text> - Base64 decode",
            "",
            "🖼️ MEDIA & AUDIO:",
            "  preview <image_url> - Preview image from URL",
            "  preview <image_file> - Preview local image", 
            "  play <audio_file> - Play audio file",
            "",
            "🔍 GITHUB & CODE:",
            "  explain <term> - Search GitHub repositories",
            "  open <number> - Open repository README",
            "",
            "⚙️ SETTINGS:",
            "  name <new_name> - Change display name",
            "  color <hex> - Change bubble color",
            "  clear - Clear chat",
            "  about - About NanoSolver",
            "  help - This help message",
            "",
            f"💡 Total: {len(plugin_commands)} plugin commands available",
            "🔒 Security: All commands are sanitized and monitored"
        ])
        
        return "\n".join(help_text)

# ==================== MAIN ENTRY POINT ====================

if __name__ == "__main__":
    try:
        # Check required dependencies
        missing_deps = []
        
        try:
            import requests
        except ImportError:
            missing_deps.append("requests")
            
        try:
            import kivy
        except ImportError:
            missing_deps.append("kivy")
        
        optional_deps = {
            "psutil": "System monitoring features",
            "reportlab": "PDF report generation", 
            "dnspython": "Advanced DNS lookups",
            "python-whois": "WHOIS lookups",
            "yara": "Malware pattern detection"
        }
        
        missing_optional = []
        for dep, feature in optional_deps.items():
            try:
                __import__(dep)
            except ImportError:
                missing_optional.append(f"{dep} ({feature})")
        
        if missing_deps:
            print("❌ Missing required dependencies:")
            for dep in missing_deps:
                print(f"   - {dep}")
            print("\n💡 Install with: pip install " + " ".join(missing_deps))
            exit(1)
            
        if missing_optional:
            print("⚠️ Missing optional dependencies (some features limited):")
            for dep in missing_optional:
                print(f"   - {dep}")
            print("\n💡 Install with: pip install " + " ".join([d.split()[0] for d in missing_optional]))
        
        # Start the application
        print("🚀 Starting Nano Solver v2 - Reality Edition...")
        print("🔒 Security systems initializing...")
        print("🔌 Plugin system loading...")
        
        # Create temporary directory
        temp_dir = "temp_images"
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
            print(f"📁 Created temporary directory: {temp_dir}")
        
        # Create plugins directory
        plugins_dir = "plugins"
        if not os.path.exists(plugins_dir):
            os.makedirs(plugins_dir)
            print(f"📁 Created plugins directory: {plugins_dir}")
        
        print("🔍 Starting security monitoring systems...")
        
        NanoSolverApp().run()
        
    except KeyboardInterrupt:
        print("\n👋 Nano Solver stopped by user")
    except Exception as e:
        print(f"❌ Failed to start Nano Solver: {e}")
        print("💡 Check dependencies and try again")