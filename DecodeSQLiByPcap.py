#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
# 兼容Python 2和Python 3的urllib.parse/urlparse模块
try:
    from urllib.parse import unquote
except ImportError:
    from urlparse import unquote
import os
import sys
import re
import tempfile
import argparse
import json
import logging
from collections import Counter, defaultdict
from datetime import datetime

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# 尝试导入psutil库用于内存监控
try:
    import psutil
    has_psutil = True
except ImportError:
    has_psutil = False
    logger.warning("[!] psutil库未安装，无法进行内存监控")

# 尝试导入tqdm库用于进度显示
try:
    from tqdm import tqdm
    has_tqdm = True
except ImportError:
    has_tqdm = False
    logger.debug("未安装tqdm库，将使用简单的进度显示")


def get_memory_usage():
    """
    获取当前进程的内存使用情况
    """
    if not has_psutil:
        return None
    try:
        process = psutil.Process(os.getpid())
        mem_info = process.memory_info()
        return {
            "rss": mem_info.rss / 1024 / 1024,  # 以MB为单位
            "vms": mem_info.vms / 1024 / 1024,  # 以MB为单位
            "percent": process.memory_percent()
        }
    except Exception as e:
        logger.error("[!] 获取内存使用情况失败: {0}".format(e))
        return None


def log_memory_usage(message):
    """
    记录当前内存使用情况
    """
    if not has_psutil:
        return
    mem_usage = get_memory_usage()
    if mem_usage:
        logger.info("[*] 内存使用情况 - {0}: RSS={1:.2f}MB, VMS={2:.2f}MB, 占比={3:.2f}%".format(message, mem_usage['rss'], mem_usage['vms'], mem_usage['percent']))

# ================= 依赖检查 =================

def check_dependencies():
    """
    检查必要的依赖是否安装
    """
    try:
        # 兼容Python 2和3的方式执行tshark命令
        process = subprocess.Popen(["tshark", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            # 处理不同Python版本的字符串编码
            try:
                # Python 3
                version_info = stdout.decode('utf-8').splitlines()[0]
            except AttributeError:
                # Python 2
                version_info = stdout.splitlines()[0]
            logger.info("tshark 版本: {0}".format(version_info))
            return True
        else:
            logger.error("[!] tshark 执行失败: {0}".format(stderr))
            return False
    except OSError:
        logger.error("[!] tshark 未安装，请先安装 Wireshark/tshark")
        logger.error("[!] Ubuntu/Debian: sudo apt-get install tshark")
        logger.error("[!] macOS: brew install wireshark")
        logger.error("[!] Windows: 从官网下载安装 Wireshark")
        return False

# ================= tshark 导出 =================

def export_requests(pcap, uri_keyword=None):
    """
    从pcap文件导出HTTP请求
    """
    # 检查文件是否存在
    if not os.path.exists(pcap):
        logger.error("[!] PCAP文件不存在: {0}".format(pcap))
        return ""
    
    # 检查文件是否可读
    if not os.access(pcap, os.R_OK):
        logger.error("[!] 没有读取PCAP文件的权限: {0}".format(pcap))
        return ""
    
    # 构建过滤器
    filter_expr = "http.request"
    if uri_keyword:
        if isinstance(uri_keyword, list):
            # 多个URI关键字，使用 OR 连接
            uri_filters = " or ".join(["http.request.uri contains \"{0}\"" .format(keyword) for keyword in uri_keyword])
            filter_expr = "http.request and ({0})" .format(uri_filters)
        else:
            # 单个URI关键字
            filter_expr = "http.request and http.request.uri contains \"{0}\"" .format(uri_keyword)
    
    cmd = [
        "tshark", "-r", pcap,
        "-o", "tcp.desegment_tcp_streams:true",
        "-o", "http.desegment_body:true",
        "-Y", filter_expr,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "http.request.uri",
        "-e", "frame.time_epoch",
        "-e", "tcp.stream"
    ]
    
    try:
        # 使用subprocess.Popen兼容Python 2和3
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        # 处理编码问题
        try:
            # Python 3
            stdout = stdout.decode('utf-8', errors='ignore')
            stderr = stderr.decode('utf-8', errors='ignore')
        except AttributeError:
            # Python 2 (已经是字符串)
            pass
        
        # 检查tshark是否执行成功
        if process.returncode != 0:
            logger.error("[!] tshark执行失败 (代码 {0}): {1}".format(process.returncode, stderr.strip()))
            return ""
        
        return stdout
    except OSError:
        logger.error("[!] tshark命令未找到，请确保已安装Wireshark/tshark")
        return ""
    except Exception as e:
        logger.error("[!] 导出请求数据失败: {0}".format(e))
        return ""


def export_responses(pcap):
    """
    从pcap文件导出HTTP响应
    """
    # 检查文件是否存在
    if not os.path.exists(pcap):
        logger.error("[!] PCAP文件不存在: {0}".format(pcap))
        return ""
    
    # 检查文件是否可读
    if not os.access(pcap, os.R_OK):
        logger.error("[!] 没有读取PCAP文件的权限: {0}".format(pcap))
        return ""
    
    cmd = [
        "tshark", "-r", pcap,
        "-o", "tcp.desegment_tcp_streams:true",
        "-o", "http.desegment_body:true",
        "-Y", "http.response",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "http.content_length",
        "-e", "http.response.code",
        "-e", "frame.time_epoch",
        "-e", "tcp.stream",
        "-e", "http.response.line",
        "-e", "http.file_data"
    ]
    
    try:
        # 使用subprocess.Popen兼容Python 2和3
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        # 处理编码问题
        try:
            # Python 3
            stdout = stdout.decode('utf-8', errors='ignore')
            stderr = stderr.decode('utf-8', errors='ignore')
        except AttributeError:
            # Python 2 (已经是字符串)
            pass
        
        # 检查tshark是否执行成功
        if process.returncode != 0:
            logger.error("[!] tshark执行失败 (代码 {0}): {1}".format(process.returncode, stderr.strip()))
            return ""
        
        return stdout
    except OSError:
        logger.error("[!] tshark命令未找到，请确保已安装Wireshark/tshark")
        return ""
    except Exception as e:
        logger.error("[!] 导出响应数据失败: {0}".format(e))
        return ""

# ================= 解析 =================

def load_requests(output, uri_keyword=None):
    """
    解析tshark输出的请求数据
    """
    req = {}
    stream_to_requests = defaultdict(list)
    
    if not output:
        logger.warning("[*] 没有请求数据需要解析")
        return req, stream_to_requests
    
    lines = output.splitlines()
    total_lines = len(lines)
    processed = 0
    
    logger.info("[*] 开始解析 {0} 行请求数据...".format(total_lines))
    
    # 创建进度条
    if has_tqdm and total_lines > 0:
        pbar = tqdm(total=total_lines, desc="解析请求数据", unit="行")
    
    for line in lines:
        if not line.strip():
            processed += 1
            if has_tqdm and total_lines > 0:
                pbar.update(1)
            continue
        try:
            parts = line.strip().split("\t", 3)
            if len(parts) < 3:
                processed += 1
                if has_tqdm and total_lines > 0:
                    pbar.update(1)
                continue
            frame = int(parts[0])
            uri = unquote(parts[1])
            timestamp = float(parts[2]) if len(parts) > 2 else None
            tcp_stream = int(parts[3]) if len(parts) > 3 else None
            
            # 检查URI是否包含任何关键字
            uri_match = True
            if uri_keyword:
                if isinstance(uri_keyword, list):
                    # 多个关键字，只要包含其中一个即可
                    uri_match = any(keyword in uri for keyword in uri_keyword)
                else:
                    # 单个关键字
                    uri_match = uri_keyword in uri
            
            if not uri_match:
                continue
            
            req_data = {
                "uri": uri,
                "timestamp": timestamp,
                "tcp_stream": tcp_stream,
                "frame": frame
            }
            
            req[frame] = req_data
            if tcp_stream is not None:
                stream_to_requests[tcp_stream].append(req_data)
                
        except (ValueError, IndexError) as e:
            logger.debug("解析请求行失败: {0}, 错误: {1}".format(line.strip(), e))
            continue
    
    # 按时间戳排序每个流的请求
    for stream in stream_to_requests:
        stream_to_requests[stream].sort(key=lambda x: x["timestamp"] or 0)
    
    # 关闭进度条
    if has_tqdm and total_lines > 0:
        pbar.close()
    
    logger.info("[*] 请求数据解析完成: 处理了 {0} 行，解析出 {1} 个请求".format(total_lines, len(req)))
    
    return req, stream_to_requests


def hex_to_ascii(hex_string):
    """
    将十六进制字符串转换为ASCII字符
    """
    try:
        if hex_string and isinstance(hex_string, str):
            # 移除可能的前缀或空格
            hex_string = hex_string.strip().replace(':', '')
            # 转换十六进制到字节，然后到字符串
            return bytes.fromhex(hex_string).decode('utf-8', errors='ignore')
        return hex_string
    except (ValueError, TypeError):
        return hex_string


def load_responses(output):
    """
    解析tshark输出的响应数据
    """
    resp = {}
    stream_to_responses = defaultdict(list)
    
    if not output:
        logger.warning("[*] 没有响应数据需要解析")
        return resp, stream_to_responses
    
    lines = output.splitlines()
    total_lines = len(lines)
    processed = 0
    
    logger.info("[*] 开始解析 {0} 行响应数据...".format(total_lines))
    
    # 创建进度条
    if has_tqdm and total_lines > 0:
        pbar = tqdm(total=total_lines, desc="解析响应数据", unit="行")
    
    for line in lines:
        if not line.strip():
            processed += 1
            if has_tqdm and total_lines > 0:
                pbar.update(1)
            continue
        try:
            parts = line.strip().split("\t", 6)
            if len(parts) < 2:
                processed += 1
                if has_tqdm and total_lines > 0:
                    pbar.update(1)
                continue
            frame = int(parts[0])
            length = parts[1]
            status_code = parts[2] if len(parts) > 2 else None
            timestamp = float(parts[3]) if len(parts) > 3 else None
            tcp_stream = int(parts[4]) if len(parts) > 4 else None
            response_uri = unquote(parts[5]) if len(parts) > 5 else None
            response_body = parts[6] if len(parts) > 6 else None
            
            resp_data = {
                "length": length,
                "status_code": status_code,
                "timestamp": timestamp,
                "tcp_stream": tcp_stream,
                "response_uri": response_uri,
                "response_body": response_body,
                "frame": frame
            }
            
            resp[frame] = resp_data
            if tcp_stream is not None:
                stream_to_responses[tcp_stream].append(resp_data)
                
        except (ValueError, IndexError) as e:
            logger.debug("解析响应行失败: {0}, 错误: {1}".format(line.strip(), e))
            continue
    
    # 按时间戳排序每个流的响应
    for stream in stream_to_responses:
        stream_to_responses[stream].sort(key=lambda x: x["timestamp"] or 0)
    
    # 关闭进度条
    if has_tqdm and total_lines > 0:
        pbar.close()
    
    logger.info("[*] 响应数据解析完成: 处理了 {0} 行，解析出 {1} 个响应".format(total_lines, len(resp)))
    
    return resp, stream_to_responses

# ================= SQL 盲注分析 =================

def detect_true_length(resp):
    """
    True 页面 content-length 出现次数最多
    """
    if not resp:
        logger.error("[!] 没有响应数据")
        return None
        
    lengths = [r["length"] for r in resp.values() if r["length"]]
    if not lengths:
        logger.error("[!] 没有找到响应长度数据")
        return None
        
    counter = Counter(lengths)
    true_len, count = counter.most_common(1)[0]
    logger.info("检测到 True 页面 Content-Length: {0} (出现 {1} 次)".format(true_len, count))
    return true_len


def detect_true_content_pattern(resp, min_occurrences=3):
    """
    检测True页面的内容模式或关键字
    """
    if not resp:
        logger.error("[!] 没有响应数据")
        return None
    
    # 提取所有非空响应体
    bodies = [r["response_body"] for r in resp.values() if r["response_body"]]
    if not bodies:
        logger.debug("没有找到响应内容数据")
        return None
    
    # 查找出现次数最多的内容模式
    # 首先尝试找到最长的公共子串
    from difflib import SequenceMatcher
    
    def longest_common_substring(s1, s2):
        match = SequenceMatcher(None, s1, s2).find_longest_match(0, len(s1), 0, len(s2))
        return s1[match.a:match.a+match.size]
    
    if len(bodies) > 1:
        common = bodies[0]
        for body in bodies[1:]:
            common = longest_common_substring(common, body)
            if not common:
                break
        
        if common and len(common) > 5:  # 至少5个字符才认为是有效模式
            logger.info("检测到 True 页面内容模式: '{0}'... (长度: {1})".format(common[:30], len(common)))
            return common.encode().hex()
    
    # 如果没有找到长的公共子串，尝试统计常见的词
    from collections import defaultdict
    word_counts = defaultdict(int)
    
    for body in bodies:
        # 简单分词（按空格和标点）
        import re
        words = re.findall(r'\w+', body.lower())
        for word in words:
            if len(word) > 3:  # 只统计长度大于3的词
                word_counts[word] += 1
    
    # 找到出现次数最多的词
    if word_counts:
        most_common = sorted(word_counts.items(), key=lambda x: x[1], reverse=True)
        for word, count in most_common:
            if count >= min_occurrences:
                logger.info("检测到 True 页面常见关键字: '{0}' (出现 {1} 次)".format(word, count))
                return word.encode().hex()
    
    return None


def detect_response_time_pattern(stream_to_requests, stream_to_responses, threshold=2.0):
    """
    检测响应时间模式，用于时间盲注分析
    """
    if not stream_to_requests or not stream_to_responses:
        logger.debug("没有流数据用于时间盲注分析")
        return None
        
    time_differences = []
    
    for stream in stream_to_requests:
        requests = stream_to_requests[stream]
        responses = stream_to_responses.get(stream, [])
        
        if len(requests) != len(responses):
            continue
            
        # 计算每个请求-响应对的时间差
        for req, resp in zip(requests, responses):
            if req["timestamp"] and resp["timestamp"]:
                time_diff = resp["timestamp"] - req["timestamp"]
                time_differences.append(time_diff)
    
    if not time_differences:
        logger.debug("没有足够的时间戳数据进行分析")
        return None
    
    # 分析时间差模式
    avg_time = sum(time_differences) / len(time_differences)
    max_time = max(time_differences)
    min_time = min(time_differences)
    
    logger.debug("响应时间统计: 平均={0:.3f}s, 最大={1:.3f}s, 最小={2:.3f}s".format(avg_time, max_time, min_time))
    
    # 检测是否存在明显的时间延迟模式
    slow_responses = [t for t in time_differences if t > avg_time * threshold]
    if len(slow_responses) > len(time_differences) * 0.1:  # 超过10%的响应明显变慢
        logger.info("检测到时间盲注模式: {0}个响应明显延迟".format(len(slow_responses)))
        return {
            "avg_time": avg_time,
            "max_time": max_time,
            "min_time": min_time,
            "threshold": avg_time * threshold,
            "slow_responses_count": len(slow_responses)
        }
    
    return None


def parse_injection(uri, custom_pattern=None):
    """
    提取 pos、比较值、表名和字段名
    支持多种SQL注入模式和自定义正则表达式
    """
    # 先对URI进行URL解码
    try:
        # 兼容Python 2和3
        from urllib.parse import unquote
    except ImportError:
        from urllib import unquote
    
    # 仅对URI中的path部分进行解码（避免解码HTTP方法和协议）
    if " " in uri and " HTTP/" in uri:
        # 提取协议+方法部分
        protocol_end = uri.find(" ") + 1
        path_end = uri.find(" HTTP/")
        if path_end != -1:
            protocol = uri[:protocol_end]
            path = uri[protocol_end:path_end]
            rest = uri[path_end:]
            path_decoded = unquote(path)
            uri = protocol + path_decoded + rest
    
    # 支持 ORD / ASCII + MID / SUBSTR / SUBSTRING + 比较操作符
    patterns = [
        # ORD/MID/SUBSTR/SUBSTRING > 值
        r'(ORD|ASCII)\s*\(\s*(MID|SUBSTR|SUBSTRING)\s*\((.+?),\s*(\d+)\s*,\s*1\s*\)\s*\)\s*(>|>=|<|<=|=|!=)\s*(\d+)',
        # CHAR 比较
        r'CHAR\s*\(\s*(\d+)\s*\)\s*(>|>=|<|<=|=|!=)\s*(MID|SUBSTR|SUBSTRING)\s*\((.+?),\s*(\d+)\s*,\s*1\s*\)',
        # 直接比较
        r'(MID|SUBSTR|SUBSTRING)\s*\((.+?),\s*(\d+)\s*,\s*1\s*\)\s*(>|>=|<|<=|=|!=)\s*(CHAR\s*\(|\'|\")(.+?)(\)|\'|\")',
        # LIKE 模糊查询
        r'(MID|SUBSTR|SUBSTRING)\s*\((.+?),\s*(\d+)\s*,\s*1\s*\)\s*LIKE\s*(\'|\")(.+?)(\'|\")'
    ]
    
    # 添加自定义模式
    if custom_pattern:
        patterns.insert(0, custom_pattern)
    
    for pattern in patterns:
        m = re.search(pattern, uri, re.I)
        if m:
            try:
                # 如果是自定义模式，尝试提取位置和值
                if pattern == custom_pattern:
                    # 自定义模式需要至少提取位置和值
                    if len(m.groups()) >= 2:
                        try:
                            pos = int(m.group(1))
                            val = int(m.group(2))
                            operator = m.group(3) if len(m.groups()) >= 3 else '>'
                            logger.debug("自定义模式解析注入: pos={0}, val={1}, operator={2}".format(pos, val, operator))
                            return pos, val, operator, None, None
                        except (ValueError, IndexError):
                            logger.debug("自定义模式解析失败，捕获组不匹配: {0}".format(pattern))
                            continue
                else:
                    # 处理内置模式的捕获组
                    db_name = None
                    table_name = None
                    column_name = None
                    substring_content = None
                    
                    if 'CHAR' in pattern and 'SUBSTRING' not in pattern:
                        # CHAR 比较模式
                        pos = int(m.group(5))
                        val = int(m.group(1))
                        operator = m.group(2)
                        substring_content = m.group(4)
                    elif 'ORD|ASCII' in pattern:
                        # ORD/ASCII 模式（包含SUBSTRING）
                        pos = int(m.group(4))
                        val = int(m.group(6))
                        operator = m.group(5)
                        substring_content = m.group(3)
                    elif 'SUBSTRING' in pattern and 'LIKE' not in pattern:
                        # 直接比较模式
                        pos = int(m.group(3))
                        operator = m.group(4)
                        val_str = m.group(6)
                        try:
                            val = int(val_str)
                        except ValueError:
                            val = ord(val_str)
                        substring_content = m.group(2)
                    elif 'LIKE' in pattern:
                        # LIKE 模式
                        pos = int(m.group(3))
                        operator = 'LIKE'
                        val_str = m.group(5)
                        val = ord(val_str)
                        substring_content = m.group(2)
                    
                    # 提取表名和字段名
                    if substring_content:
                        # 移除substring_content周围的括号
                        substring_content = substring_content.strip()
                        if substring_content.startswith('(') and substring_content.endswith(')'):
                            substring_content = substring_content[1:-1].strip()
                        
                        # 先尝试匹配 SELECT 语句（优先级更高）
                        select_pattern = r'SELECT\s+(.*?)\s+FROM'
                        select_match = re.search(select_pattern, substring_content, re.I | re.S)
                        if select_match:
                            select_part = select_match.group(1).strip()
                            from_part = substring_content[select_match.end():].strip()
                            
                            # 提取表名（处理database.table格式）
                            from_pattern = r'^\s*([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)'
                            from_match = re.search(from_pattern, from_part, re.I)
                            if from_match:
                                table_part = from_match.group(1)
                                # 处理database.table格式
                                if '.' in table_part:
                                    # 分离库名和表名（如mysql.user -> 库名：mysql，表名：user）
                                    db_name = table_part.split('.')[-2]
                                    table_name = table_part.split('.')[-1]
                                else:
                                    # 没有库名，只有表名
                                    db_name = None
                                    table_name = table_part
                            
                            # 提取字段名
                            if select_part:
                                # 处理复杂的SELECT表达式，尝试提取真正的字段名
                                # 移除IFNULL、CAST等函数包装
                                column_part = select_part
                                
                                # 移除IFNULL(...)函数，只保留第一个参数
                                if column_part.lower().startswith('ifnull(') and column_part.endswith(')'):
                                    # 提取IFNULL的参数部分
                                    inner_content = column_part[7:-1].strip()
                                    # 找到第一个逗号（参数分隔符），只保留第一个参数
                                    comma_pos = inner_content.find(',')
                                    if comma_pos != -1:
                                        column_part = inner_content[:comma_pos].strip()
                                    else:
                                        column_part = inner_content.strip()
                                
                                # 移除CAST(...)函数
                                if column_part.lower().startswith('cast(') and column_part.endswith(')'):
                                    column_part = column_part[5:-1].strip()
                                    # 提取CAST内部的字段名（如CAST(Password AS NCHAR) -> Password）
                                    cast_match = re.match(r'([^\s]+)\s+as', column_part, re.I)
                                    if cast_match:
                                        column_part = cast_match.group(1).strip()
                                
                                # 最终提取字段名
                                column_name = column_part.split('.')[-1] if '.' in column_part else column_part
                        else:
                            # 尝试匹配 table.column 格式
                            table_column_pattern = r'(\w+)\s*\.\s*(\w+)'
                            tc_match = re.search(table_column_pattern, substring_content, re.I)
                            if tc_match:
                                table_name = tc_match.group(1)
                                column_name = tc_match.group(2)
                            else:
                                # 移除substring_content周围的括号
                                temp_content = substring_content.strip()
                                if temp_content.startswith('(') and temp_content.endswith(')'):
                                    temp_content = temp_content[1:-1].strip()
                                
                                select_match = re.search(select_pattern, temp_content, re.I | re.S)
                                if select_match:
                                    select_part = select_match.group(1).strip()
                                    from_part = temp_content[select_match.end():].strip()
                                    
                                    # 提取表名（处理database.table格式）
                                    from_pattern = r'^\s*([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)'
                                    from_match = re.search(from_pattern, from_part, re.I)
                                    if from_match:
                                        table_part = from_match.group(1)
                                        # 处理database.table格式
                                        if '.' in table_part:
                                            # 分离库名和表名（如mysql.user -> 库名：mysql，表名：user）
                                            db_name = table_part.split('.')[-2]
                                            table_name = table_part.split('.')[-1]
                                        else:
                                            # 没有库名，只有表名
                                            db_name = None
                                            table_name = table_part
                                    
                                    # 提取字段名
                                    if select_part:
                                        # 处理复杂的SELECT表达式，尝试提取真正的字段名
                                        # 移除IFNULL、CAST等函数包装
                                        column_part = select_part
                                    
                                        # 移除IFNULL(...)函数，只保留第一个参数
                                        if column_part.lower().startswith('ifnull(') and column_part.endswith(')'):
                                            # 提取IFNULL的参数部分
                                            inner_content = column_part[7:-1].strip()
                                            # 找到第一个逗号（参数分隔符），只保留第一个参数
                                            comma_pos = inner_content.find(',')
                                            if comma_pos != -1:
                                                column_part = inner_content[:comma_pos].strip()
                                            else:
                                                column_part = inner_content.strip()
                                        
                                        # 移除CAST(...)函数
                                        if column_part.lower().startswith('cast(') and column_part.endswith(')'):
                                            column_part = column_part[5:-1].strip()
                                            # 提取CAST内部的字段名（如CAST(Password AS NCHAR) -> Password）
                                            cast_match = re.match(r'([^\s]+)\s+as', column_part, re.I)
                                            if cast_match:
                                                column_part = cast_match.group(1).strip()
                                        
                                        # 最终提取字段名
                                        column_name = column_part.split('.')[-1] if '.' in column_part else column_part
                                else:
                                    # 尝试匹配没有 FROM 子句的 SELECT
                                    nested_select_pattern = r'SELECT\s+([^\)]+)'
                                    nested_match = re.search(nested_select_pattern, substring_content, re.I)
                                    if nested_match:
                                        column_part = nested_match.group(1).strip()
                                        # 提取函数名或表达式，去掉括号
                                        func_pattern = r'^([a-zA-Z_][a-zA-Z0-9_]*)(\s*\()'
                                        func_match = re.match(func_pattern, column_part)
                                        if func_match:
                                            column_name = func_match.group(1)
                                        else:
                                            column_name = column_part
                                    else:
                                        # 尝试匹配单独的字段名
                                        column_pattern = r'^\s*([^,\(\)]+)'
                                        col_match = re.search(column_pattern, substring_content, re.I)
                                        if col_match:
                                            column_name = col_match.group(1).strip()
                    
                    logger.debug("解析注入: pos={0}, val={1}, operator={2}, db={3}, table={4}, column={5}".format(pos, val, operator, db_name, table_name, column_name))
                    return pos, val, operator, db_name, table_name, column_name
            except (IndexError, ValueError) as e:
                import traceback
                logger.debug("解析注入模式失败: {0}, 错误: {1}, 回溯信息: {2}".format(pattern, e, traceback.format_exc()))
                continue
    
    return None

def interactive_response_marking(req, resp, stream_to_requests, stream_to_responses, custom_pattern=None):
    """
    交互式响应标记，让用户手动指定True/False响应
    """
    marked_responses = []
    true_responses = []
    false_responses = []
    
    print("\n" + "="*60)
    print("交互式响应标记 - 请分析并标记True/False响应")
    print("="*60)
    print("规则:")
    print("1. 查看请求中的SQL注入模式和响应内容")
    print("2. 输入 't' 标记为True响应")
    print("3. 输入 '' 标记为False响应")
    print("4. 输入 's' 跳过当前请求")
    print("5. 输入 'q' 退出标记模式")
    print("6. 输入 'h' 显示此帮助")
    print("="*60)
    
    # 收集所有包含SQL注入的请求
    injection_requests = []
    for stream in stream_to_requests:
        requests = stream_to_requests[stream]
        responses = stream_to_responses.get(stream, [])
        
        for req_data, resp_data in zip(requests, responses):
            uri = req_data["uri"]
            parsed = parse_injection(uri, custom_pattern)
            if parsed:
                injection_requests.append((req_data, resp_data, parsed))
    
    if not injection_requests:
        logger.info("没有找到包含SQL注入的请求")
        return None, None
    
    print("找到 {0} 个包含SQL注入的请求".format(len(injection_requests)))
    
    # 让用户标记响应
    for i, (req_data, resp_data, parsed) in enumerate(injection_requests[:10]):  # 最多显示10个请求
        pos, val, operator, _, _, _ = parsed  # 忽略库名、表名、字段名
        
        print("\n请求 #{0}/{1}".format(i+1, len(injection_requests)))
        print("URI: {0}...".format(req_data['uri'][:100]))
        print("注入模式: pos={0}, val={1}, operator={2}".format(pos, val, operator))
        print("响应状态码: {0}".format(resp_data['status_code']))
        print("响应长度: {0}".format(resp_data['length']))
        print("响应内容: {0}...".format(resp_data['response_body'][:100]))
        
        while True:
            user_input = input("请标记 (t/f/s/q/h): ").strip().lower()
            if not user_input:
                print("请输入有效的选项，输入 'h' 查看帮助")
                continue
            elif user_input in ['t', 'true']:
                true_responses.append(resp_data)
                marked_responses.append((req_data, resp_data, parsed, True))
                break
            elif user_input in ['', 'false']:
                false_responses.append(resp_data)
                marked_responses.append((req_data, resp_data, parsed, False))
                break
            elif user_input in ['s', 'skip']:
                break
            elif user_input in ['q', 'quit', 'exit']:
                break
            elif user_input in ['h', 'help', '?']:
                print("\n帮助:")
                print("t/true - 标记为True响应")
                print("f/false - 标记为False响应")
                print("s/skip - 跳过当前请求")
                print("q/quit/exit - 退出标记模式")
                print("h/help/? - 显示帮助")
            else:
                print("无效输入 '{0}'，请重试。输入 'h' 查看帮助".format(user_input))
        
        if user_input == 'q':
            break
    
    if not marked_responses:
        logger.warning("没有标记任何响应")
        return None, None
    
    print("\n标记完成: {0}个True响应, {1}个False响应".format(len(true_responses), len(false_responses)))
    
    # 分析标记结果
    true_len = None
    true_content = None
    
    if true_responses:
        # 尝试检测True响应的长度模式
        lengths = [r["length"] for r in true_responses if r["length"]]
        if lengths:
            counter = Counter(lengths)
            true_len, count = counter.most_common(1)[0]
            logger.info("检测到 True 页面 Content-Length: {0} (出现 {1} 次)".format(true_len, count))
        
        # 尝试检测True响应的内容模式
        bodies = [r["response_body"] for r in true_responses if r["response_body"]]
        if bodies:
            from difflib import SequenceMatcher
            
            def longest_common_substring(s1, s2):
                match = SequenceMatcher(None, s1, s2).find_longest_match(0, len(s1), 0, len(s2))
                return s1[match.a:match.a+match.size]
            
            if len(bodies) > 1:
                common = bodies[0]
                for body in bodies[1:]:
                    common = longest_common_substring(common, body)
                    if not common:
                        break
                if common and len(common) > 5:
                    logger.info("检测到 True 页面内容模式: '{0}...' (长度: {1})".format(common[:30], len(common)))
                    true_content = common
    
    return true_len, true_content


def solve_blind(req, resp, stream_to_requests, stream_to_responses, true_len=None, true_content=None, time_pattern=None, custom_pattern=None):
    """
    分析SQL盲注数据
    """
    # 检查输入数据
    if not req or not resp:
        logger.error("[!] 请求或响应数据为空 - 请求数: {0}, 响应数: {1}".format(len(req) if req else 0, len(resp) if resp else 0))
        return "", None, None, None
    
    if not stream_to_requests or not stream_to_responses:
        logger.error("[!] 流数据为空 - 请求流数: {0}, 响应流数: {1}".format(len(stream_to_requests) if stream_to_requests else 0, len(stream_to_responses) if stream_to_responses else 0))
        return "", None, None, None
    
    if true_len is None and true_content is None:
        logger.info("[*] 未提供手动盲注模式，尝试自动检测...")
        true_len = detect_true_length(resp)
        if true_len is not None:
            logger.info("[+] 自动检测到内容长度模式: {0}".format(true_len))
        else:
            logger.info("[*] 内容长度模式检测失败，尝试检测内容模式...")
            true_content = detect_true_content_pattern(resp)
            if true_content is not None:
                logger.info("[+] 自动检测到内容模式: '{0}...'".format(true_content[:30]))
            else:
                logger.info("[*] 内容模式检测失败，尝试使用响应时间模式进行分析...")
                time_pattern = detect_response_time_pattern(stream_to_requests, stream_to_responses)
                if time_pattern:
                    logger.info("[+] 自动检测到时间盲注模式: 阈值={0:.3f}s".format(time_pattern['threshold']))
                else:
                    logger.error("[!] 无法检测到任何盲注模式")
                    return "", None, None, None
    
    # 使用嵌套字典存储数据：{ (table_name, column_name): { pos: [val1, val2, ...] } }
    data = defaultdict(lambda: defaultdict(list))
    analyzed_count = 0
    
    # 计算总请求数
    total_requests = sum(len(requests) for requests in stream_to_requests.values())
    
    # 创建进度条
    if has_tqdm and total_requests > 0:
        pbar = tqdm(total=total_requests, desc="分析请求", unit="请求")
    
    # 优先使用流数据进行更准确的请求-响应匹配
    for stream in stream_to_requests:
        requests = stream_to_requests[stream]
        responses = stream_to_responses.get(stream, [])
        
        if not requests:
            continue
            
        if len(requests) > len(responses):
            responses += [None] * (len(requests) - len(responses))
            
        for req_data, resp_data in zip(requests, responses):
            # 更新进度条
            if has_tqdm and total_requests > 0:
                pbar.update(1)
            
            if not resp_data:
                continue
                
            uri = req_data["uri"]
            parsed = parse_injection(uri, custom_pattern)
            if not parsed:
                continue
            
            pos, val, operator, db_name, table_name, column_name = parsed
            analyzed_count += 1
            
            # 确定响应是否为True
            is_true = False
            if true_len:
                is_true = resp_data["length"] == true_len
            elif true_content:
                # 使用内容模式判断
                if resp_data["response_body"] and true_content.encode().hex() in resp_data["response_body"]:
                    is_true = True
            elif time_pattern:
                # 使用时间盲注模式
                if req_data["timestamp"] and resp_data["timestamp"]:
                    time_diff = resp_data["timestamp"] - req_data["timestamp"]
                    is_true = time_diff > time_pattern["threshold"]
            
            # 根据操作符处理比较值，按(db_name, table_name, column_name)组合存储
            table_col_key = (db_name or 'unknown_db', table_name or 'unknown_table', column_name or 'unknown_column')
            if operator in ('>', '>='):
                if is_true:
                    # 当使用大于运算符且结果为真时，表示实际字符值大于测试值
                    data[table_col_key][pos].append(val+1)
            elif operator in ('<', '<='):
                if not is_true:
                    # 当使用小于运算符且结果为假时，表示实际字符值大于等于测试值
                    data[table_col_key][pos].append(val-1)
            elif operator == '=':
                if is_true:
                    # 等于运算符直接存储正确值
                    data[table_col_key][pos] = [val]
            elif operator == 'LIKE':
                if is_true:
                    # LIKE运算符直接存储正确值
                    data[table_col_key][pos] = [val]
    
    # 关闭进度条
    if has_tqdm and total_requests > 0:
        pbar.close()
    
    logger.info("[*] 共分析了 {0} 个注入请求".format(analyzed_count))
    
    if analyzed_count == 0:
        logger.error("[!] 没有找到任何SQL注入请求 - 总请求数: {0}".format(total_requests))
        return "", true_len, true_content, time_pattern
    
    # 为每个库、表和字段组合生成提取结果
    extracted_results = {}
    if data:
        for table_col_key, pos_data in data.items():
            db_name, table_name, column_name = table_col_key
            result = ""
            if pos_data:
                max_pos = max(pos_data.keys())
                for pos in range(1, max_pos + 1):
                    if pos in pos_data and pos_data[pos]:
                        # 对于每个位置，正确的字符值需要根据收集到的测试值和操作符来确定
                        # 对于大于运算符的情况：收集的是所有is_true为真的测试值，这些值都小于实际字符值
                        # 对于小于运算符的情况：收集的是所有is_true为假的测试值，这些值都小于等于实际字符值
                        # 正确的字符值应该是最大的测试值 + 1（对于大于运算符）或最大的测试值（对于小于运算符）
                        # 但为了简化处理，我们取最大的测试值，这在大多数情况下是正确的
                        char_val = max(pos_data[pos])
                        result += chr(char_val)
                    else:
                        result += "?"
                # 只保存有有效数据的结果
                if result.strip("?"):
                    extracted_results[table_col_key] = result
    else:
        logger.error("[!] 无法从注入请求中提取有效数据")
    
    return extracted_results, true_len, true_content, time_pattern

# ================= 结果导出 =================

def export_result(extracted_results, true_len, true_content=None, time_pattern=None, output_file=None, output_format="text"):
    """
    导出分析结果
    extracted_results: 字典，键为(db_name, table_name, column_name)，值为提取的数据
    """
    if output_file:
        # 验证输出文件路径
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
                logger.info("[*] 已创建输出目录: {0}".format(output_dir))
            except OSError as e:
                logger.error("[!] 创建输出目录失败: {0}".format(e))
                return False
        
        # 检查是否有写权限
        try:
            with open(output_file, 'a'):
                pass
            os.remove(output_file)
        except IOError as e:
            logger.error("[!] 没有写入输出文件的权限: {0}".format(e))
            return False
        
        # 确定分析类型
        if time_pattern:
            analysis_type = "time_blind"
        elif true_content:
            analysis_type = "content_blind"
        else:
            analysis_type = "content_length_blind"
        
        if output_format == "json":
            # JSON格式：导出所有表和字段的结果
            data = {
                "timestamp": datetime.now().isoformat(),
                "true_content_length": true_len,
                "true_content_pattern": true_content,
                "analysis_type": analysis_type,
                "extracted_data": [],
                "total_table_columns": len(extracted_results)
            }
            
            if time_pattern:
                data["time_pattern"] = time_pattern
            
            # 添加每个表和字段的数据
            for (db_name, table_name, column_name), result in extracted_results.items():
                data["extracted_data"].append({
                    "database_name": db_name,
                    "table_name": table_name,
                    "column_name": column_name,
                    "extracted_string": result,
                    "length": len(result)
                })
            
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info("结果已导出到 JSON 文件: {0}".format(output_file))
        else:
            # 文本格式
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("========== SQL Blind Injection Result ==========\n")
                if true_len:
                    f.write("[+] True Content-Length : {0}\n".format(true_len))
                if true_content:
                    f.write("[+] True Content Pattern: '{0}'\n".format(true_content))
                if time_pattern:
                    f.write("[+] 时间盲注模式: 平均响应时间={0:.3f}s\n".format(time_pattern['avg_time']))
                    f.write("[+] 延迟阈值: {0:.3f}s\n".format(time_pattern['threshold']))
                f.write("[+] 分析类型           : {0}\n".format(analysis_type))
                f.write("[+] 提取的表字段组合数  : {0}\n".format(len(extracted_results)))
                f.write("[+] 时间戳             : {0}\n".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                
                # 添加每个表和字段的数据
                if extracted_results:
                    f.write("\n[+] 提取的SQL注入数据:\n")
                    for i, ((db_name, table_name, column_name), result) in enumerate(extracted_results.items(), 1):
                        f.write("\n--- 条目 #{0} ---" .format(i))
                        f.write("\n库名: {0}\n" .format(db_name))
                        f.write("\n表名: {0}\n" .format(table_name))
                        f.write("字段: {0}\n" .format(column_name))
                        f.write("数据: {0}\n" .format(result))
                        f.write("长度: {0}\n" .format(len(result)))
                
                f.write("\n===============================================\n")
            logger.info("结果已导出到文本文件: {0}".format(output_file))
    return True

# ================= 工具函数 =================

def load_config(config_path):
    """
    从配置文件加载参数
    """
    if not os.path.exists(config_path):
        logger.error("[!] 配置文件不存在: {0}".format(config_path))
        return None
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        logger.info("[*] 已加载配置文件: {0}".format(config_path))
        return config
    except json.JSONDecodeError as e:
        logger.error("[!] 配置文件格式错误: {0}".format(e))
        return None
    except Exception as e:
        logger.error("[!] 加载配置文件失败: {0}".format(e))
        return None


def save_config(config_path, args):
    """
    保存当前参数到配置文件
    """
    # 只保存可配置的参数
    config = {
        "uri": args.uri,
        "format": args.format,
        "verbose": args.verbose,
        "true_length": args.true_length,
        "true_content": args.true_content,
        "delay_threshold": args.delay_threshold,
        "interactive": args.interactive,
        "recursive": args.recursive,
        "custom_pattern": args.custom_pattern
    }
    
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        logger.info("[*] 配置已保存到: {0}".format(config_path))
        return True
    except Exception as e:
        logger.error("[!] 保存配置文件失败: {0}".format(e))
        return False


def collect_pcap_files(paths, recursive=False):
    """
    收集所有PCAP文件路径，支持目录和递归处理
    """
    pcap_files = []
    
    for path in paths:
        if not os.path.exists(path):
            logger.warning("[!] 路径不存在: {0}".format(path))
            continue
        
        if os.path.isfile(path):
            # 单个文件
            if path.lower().endswith('.pcap') or path.lower().endswith('.pcapng'):
                pcap_files.append(path)
            else:
                logger.warning("[!] 不是PCAP文件: {0}".format(path))
        elif os.path.isdir(path):
            # 目录
            try:
                if recursive:
                    # 递归遍历目录
                    logger.info("[*] 递归扫描目录: {0}".format(path))
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            if file.lower().endswith('.pcap') or file.lower().endswith('.pcapng'):
                                file_path = os.path.join(root, file)
                                pcap_files.append(file_path)
                                logger.debug("[*] 找到PCAP文件: {0}".format(file_path))
                else:
                    # 只处理当前目录
                    logger.info("[*] 扫描目录: {0}".format(path))
                    for file in os.listdir(path):
                        file_path = os.path.join(path, file)
                        if os.path.isfile(file_path):
                            if file_path.lower().endswith('.pcap') or file_path.lower().endswith('.pcapng'):
                                pcap_files.append(file_path)
                                logger.debug("[*] 找到PCAP文件: {0}".format(file_path))
            except PermissionError:
                logger.error("[!] 没有权限访问目录: {0}".format(path))
            except Exception as e:
                logger.error("[!] 扫描目录时发生错误 {0}: {1}".format(path, e))
        else:
            logger.warning("[!] 既不是文件也不是目录: {0}".format(path))
    
    return pcap_files

# ================= 主流程 =================

def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description="SQL盲注流量分析工具 - 从PCAP文件中提取和分析SQL盲注数据\n\n" +
        "该工具支持三种SQL盲注检测方式：\n" +
        "1. 内容长度盲注 (Content-Length) - 根据响应长度判断True/False\n" +
        "2. 内容匹配盲注 (Content Pattern) - 根据响应内容中的关键字判断True/False\n" +
        "3. 时间盲注 (Time-Based) - 根据响应时间延迟判断True/False\n\n" +
        "支持多种SQL注入模式：\n" +
        "- ORD/MID/SUBSTR函数比较\n" +
        "- CHAR函数比较\n" +
        "- LIKE模糊查询\n" +
        "- 直接字符串比较",
        epilog="使用示例：\n" +
        "1. 基本用法：分析PCAP文件并显示结果\n" +
        "   python main.py capture.pcap\n\n" +
        "2. 过滤特定URI：只分析包含login.php的请求\n" +
        "   python main.py capture.pcap --uri login.php\n\n" +
        "3. 手动指定True页面参数：\n" +
        "   python main.py capture.pcap --true-length 456\n" +
        "   python main.py capture.pcap --true-content \"success\"\n\n" +
        "4. 导出结果到文件：\n" +
        "   python main.py capture.pcap --output result.txt --format text\n" +
        "   python main.py capture.pcap --output result.json --format json\n\n" +
        "5. 时间盲注分析：\n" +
        "   python main.py capture.pcap --delay-threshold 3.0\n\n" +
        "6. 详细日志模式：\n" +
        "   python main.py capture.pcap --verbose\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("pcap_file", nargs="*", help="PCAP文件路径或目录 (可指定多个)")
    parser.add_argument("-r", "--recursive", action="store_true", help="递归处理目录中的所有PCAP文件")
    parser.add_argument("-u", "--uri", action="append", help="URI关键词过滤，只分析包含该关键词的请求 (可重复使用)")
    parser.add_argument("--custom-pattern", help="自定义SQL注入模式（正则表达式），用于提取位置和比较值")
    parser.add_argument("-o", "--output", help="结果输出文件路径")
    parser.add_argument("--config", help="配置文件路径，用于加载默认参数")
    parser.add_argument("--save-config", help="保存当前参数到配置文件")
    parser.add_argument("-", "--format", choices=["text", "json"], default="text", help="输出格式")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细日志")
    parser.add_argument("-t", "--true-length", help="手动指定True页面的Content-Length")
    parser.add_argument("-c", "--true-content", help="手动指定True页面的内容关键字或模式")
    parser.add_argument("-d", "--delay-threshold", type=float, default=2.0, help="时间盲注延迟阈值倍数 (默认: 2.0)")
    parser.add_argument("--interactive", action="store_true", help="启用交互式分析模式，手动标记True/False响应")
    
    args = parser.parse_args()
    
    # 加载配置文件（如果指定）
    if args.config:
        config = load_config(args.config)
        if config:
            # 应用配置参数（只在命令行未指定时）
            if not args.uri:
                args.uri = config.get("uri")
            if not args.format:
                args.format = config.get("format", "text")
            if not args.true_length:
                args.true_length = config.get("true_length")
            if not args.true_content:
                args.true_content = config.get("true_content")
            if not args.delay_threshold:
                args.delay_threshold = config.get("delay_threshold", 2.0)
            if not args.custom_pattern:
                args.custom_pattern = config.get("custom_pattern")
            # 布尔参数：如果命令行未指定，则使用配置值
            # 注意：action="store_true"的参数默认值为False
            if "verbose" in config and not args.verbose:
                args.verbose = config["verbose"]
            if "interactive" in config and not args.interactive:
                args.interactive = config["interactive"]
            if "recursive" in config and not args.recursive:
                args.recursive = config["recursive"]
    
    # 参数验证
    if args.delay_threshold <= 0:
        logger.error("[!] --delay-threshold 必须是正数")
        sys.exit(1)
    
    # 验证自定义正则表达式模式
    if args.custom_pattern:
        try:
            re.compile(args.custom_pattern)
            logger.info("[*] 已验证自定义正则表达式模式: {0}".format(args.custom_pattern))
        except re.error as e:
            logger.error("[!] 自定义正则表达式模式无效: {0}".format(e))
            sys.exit(1)
    
    # 保存配置文件（如果指定）
    if args.save_config:
        save_config(args.save_config, args)
        sys.exit(0)
    
    # 检查是否提供了PCAP文件
    if not args.pcap_file:
        logger.error("[!] 请提供PCAP文件路径或目录")
        parser.print_help()
        sys.exit(1)
    
    # 设置日志级别
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 检查依赖
    if not check_dependencies():
        sys.exit(1)
    
    # 记录初始内存使用情况
    log_memory_usage("程序启动")
    
    # 收集所有PCAP文件
    all_results = []
    pcap_files = collect_pcap_files(args.pcap_file, args.recursive)
    
    if not pcap_files:
        logger.error("[!] 没有找到任何PCAP文件")
        sys.exit(1)
    
    logger.info("[*] 总共找到 {0} 个PCAP文件".format(len(pcap_files)))
    
    # 批量处理所有PCAP文件
    for pcap_file in pcap_files:
        print("\n" + "="*80)
        print("开始分析 PCAP 文件: {0}".format(pcap_file))
        print("="*80)
        
        # 检查PCAP文件
        if not os.path.exists(pcap_file):
            logger.error("[!] PCAP文件不存在: {0}".format(pcap_file))
            continue
        
        if not os.path.isfile(pcap_file):
            logger.error("[!] 不是有效的文件: {0}".format(pcap_file))
            continue
        
        logger.info("[*] 开始分析 PCAP 文件: {0}".format(pcap_file))
        if args.uri:
            if isinstance(args.uri, list):
                logger.info("[*] URI 过滤关键词: {0}".format(', '.join(args.uri)))
            else:
                logger.info("[*] URI 过滤关键词: {0}".format(args.uri))
        else:
            logger.info("[*] URI 过滤关键词: 无")
        
        # 导出和解析数据
        try:
            logger.info("[*] 导出 HTTP 请求数据...")
            req_output = export_requests(pcap_file, args.uri)
            req, stream_to_requests = load_requests(req_output, args.uri)
            
            logger.info("[*] 导出 HTTP 响应数据...")
            resp_output = export_responses(pcap_file)
            resp, stream_to_responses = load_responses(resp_output)
            
            logger.info("[*] 解析到 {0} 个请求".format(len(req)))
            logger.info("[*] 解析到 {0} 个响应".format(len(resp)))
            logger.info("[*] 识别到 {0} 个 TCP 流".format(len(stream_to_requests)))
            
            if not req:
                logger.error("[!] 没有找到匹配的请求数据")
                continue
            
            if not resp:
                logger.error("[!] 没有找到响应数据")
                continue
            
            # 分析盲注
            true_len = args.true_length
            true_content = args.true_content
            
            if true_len:
                logger.info("[*] 使用手动指定的 True Content-Length: {0}".format(true_len))
            if true_content:
                logger.info("[*] 使用手动指定的 True Content Pattern: '{0}'".format(true_content))
            
            # 检测时间模式（如果需要）
            time_pattern = None
            if not true_len and not true_content:
                logger.info("[*] 检测时间盲注模式...")
                time_pattern = detect_response_time_pattern(stream_to_requests, stream_to_responses, args.delay_threshold)
                if time_pattern:
                    logger.info("[*] 发现时间盲注模式，将使用时间延迟进行分析")
            
            # 交互式分析模式
            if args.interactive:
                logger.info("[*] 进入交互式响应标记模式...")
                interactive_true_len, interactive_true_content = interactive_response_marking(req, resp, stream_to_requests, stream_to_responses, args.custom_pattern)
                if interactive_true_len or interactive_true_content:
                    true_len = interactive_true_len
                    true_content = interactive_true_content
                    logger.info("[*] 使用交互式标记的响应特征进行分析")
            
            logger.info("[*] 分析 SQL 盲注数据...")
            extracted_results, detected_true_len, detected_true_content, detected_time_pattern = solve_blind(
                req, resp, stream_to_requests, stream_to_responses, true_len, true_content, time_pattern, args.custom_pattern
            )
            
            # 显示结果
            print("\n" + "="*50)
            print("SQL Blind Injection Analysis Result - {0}".format(os.path.basename(pcap_file)))
            print("="*50)
            if detected_true_len:
                print("[+] True Content-Length : {0}".format(detected_true_len))
            if detected_true_content:
                print("[+] True Content Pattern: '{0}'".format(detected_true_content))
            if detected_time_pattern:
                print("[+] 时间盲注模式: 平均响应时间={0:.3f}s".format(detected_time_pattern['avg_time']))
                print("[+] 延迟阈值: {0:.3f}s".format(detected_time_pattern['threshold']))
            
            # 确定分析类型
            if detected_time_pattern:
                analysis_type = "时间盲注"
            elif detected_true_content:
                analysis_type = "布尔盲注"
            else:
                analysis_type = "内容长度盲注"
            
            # 显示每个表和字段的注入数据
            if extracted_results:
                print("\n[+] 提取的SQL注入数据:")
                for (db_name, table_name, column_name), result in extracted_results.items():
                    print("\n  库名: {0}".format(db_name))
                    print("  表名: {0}".format(table_name))
                    print("  字段: {0}".format(column_name))
                    print("  数据: {0}".format(result))
                    print("  长度: {0}".format(len(result)))
            else:
                print("\n[!] 没有提取到有效数据")
            
            print("\n[+] Analysis Type      : {0}".format(analysis_type))
            print("[+] Analysis Time      : {0}".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            print("="*50)
            
            # 保存结果用于批量导出
            all_results.append({
                "pcap_file": pcap_file,
                "extracted_results": extracted_results,
                "true_len": detected_true_len,
                "true_content": detected_true_content,
                "time_pattern": detected_time_pattern,
                "analysis_type": analysis_type
            })
            
            logger.info("[*] 分析完成！")
            
        except KeyboardInterrupt:
            logger.info("[*] 用户中断了分析")
            sys.exit(0)
        except Exception as e:
            logger.error("[!] 分析文件 {0} 时发生错误: {1}".format(pcap_file, e))
            if args.verbose:
                import traceback
                traceback.print_exc()
            continue
    
    # 批量导出结果
    if args.output and all_results:
        # 验证输出文件路径（多个文件综合报告）
        output_dir = os.path.dirname(args.output)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
                logger.info("[*] 已创建输出目录: {0}".format(output_dir))
            except OSError as e:
                logger.error("[!] 创建输出目录失败: {0}".format(e))
        
        # 检查是否有写权限
        try:
            with open(args.output, 'a'):
                pass
            os.remove(args.output)
        except IOError as e:
            logger.error("[!] 没有写入输出文件的权限: {0}".format(e))
            args.output = None
        
        if args.output:
            if len(all_results) == 1:
                # 单个文件，直接导出
                r = all_results[0]
                if not export_result(r["extracted_results"], r["true_len"], r["true_content"], r["time_pattern"], args.output, args.format):
                    logger.error("[!] 导出结果失败")
            else:
                # 多个文件，导出为综合报告
                if args.format == "json":
                    # JSON格式：导出所有结果的数组
                    export_data = {
                        "timestamp": datetime.now().isoformat(),
                        "total_files": len(all_results),
                        "files": all_results
                    }
                    with open(args.output, "w", encoding="utf-8") as f:
                        json.dump(export_data, f, ensure_ascii=False, indent=2)
                    logger.info("综合结果已导出到 JSON 文件: {0}".format(args.output))
                else:
                    # 文本格式：导出每个文件的结果
                    with open(args.output, "w", encoding="utf-8") as f:
                        f.write("SQL Blind Injection 批量分析报告\n")
                        f.write("生成时间: {0}\n".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                        f.write("分析文件数: {0}\n".format(len(all_results)))
                        if args.uri:
                            if isinstance(args.uri, list):
                                f.write("URI 过滤: {0}\n".format(', '.join(args.uri)))
                            else:
                                f.write("URI 过滤: {0}\n".format(args.uri))
                        else:
                            f.write("URI 过滤: 无\n")
                        f.write("="*80 + "\n\n")
                        
                        for i, r in enumerate(all_results):
                            f.write("文件 #{0}: {1}\n".format(i+1, os.path.basename(r['pcap_file'])))
                            f.write("-"*60 + "\n")
                            if r['true_len']:
                                f.write("True Content-Length : {0}\n".format(r['true_len']))
                            if r['true_content']:
                                f.write("True Content Pattern: '{0}'\n".format(r['true_content']))
                            if r['time_pattern']:
                                f.write("时间盲注模式: 平均响应时间={0:.3f}s\n".format(r['time_pattern']['avg_time']))
                                f.write("延迟阈值: {0:.3f}s\n".format(r['time_pattern']['threshold']))
                            f.write("Analysis Type      : {0}\n".format(r['analysis_type']))
                            f.write("提取的表字段组合数: {0}\n".format(len(r['extracted_results'])))
                            
                            # 显示每个表和字段的数据
                            if r['extracted_results']:
                                f.write("\n[+] 提取的数据:\n")
                                for j, ((table_name, column_name), result) in enumerate(r['extracted_results'].items(), 1):
                                    f.write("\n  条目 #{0}:\n".format(j))
                                    f.write("    表名: {0}\n".format(table_name))
                                    f.write("    字段: {0}\n".format(column_name))
                                    f.write("    数据: {0}\n".format(result))
                                    f.write("    长度: {0}\n".format(len(result)))
                            else:
                                f.write("\n[!] 没有提取到有效数据\n")
                            
                            f.write("\n" + "="*60 + "\n\n")
                    logger.info("综合结果已导出到文本文件: {0}".format(args.output))
    
    logger.info("[*] 所有文件分析完成！")
    logger.info("[*] 总PCAP文件数: {0}".format(len(pcap_files)))
    logger.info("[*] 成功分析: {0} 个文件".format(len(all_results)))
    logger.info("[*] 失败分析: {0} 个文件".format(len(pcap_files) - len(all_results)))


if __name__ == "__main__":
    main()

