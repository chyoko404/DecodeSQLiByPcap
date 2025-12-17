# DecodeSQLiByPcap
Auto decode SQLi with pcap at CTF game
SQL盲注流量分析工具 - 从PCAP文件中提取和分析SQL盲注数据

该工具支持三种SQL盲注检测方式：
1. 内容长度盲注 (Content-Length) - 根据响应长度判断True/False
2. 内容匹配盲注 (Content Pattern) - 根据响应内容中的关键字判断True/False
3. 时间盲注 (Time-Based) - 根据响应时间延迟判断True/False

支持多种SQL注入模式：
- ORD/MID/SUBSTR函数比较
- CHAR函数比较
- LIKE模糊查询
- 直接字符串比较

positional arguments:
  pcap_file             PCAP文件路径或目录 (可指定多个)

optional arguments:
  -h, --help            show this help message and exit
  -r, --recursive       递归处理目录中的所有PCAP文件
  -u URI, --uri URI     URI关键词过滤，只分析包含该关键词的请求 (可重复使用)
  --custom-pattern CUSTOM_PATTERN
                        自定义SQL注入模式（正则表达式），用于提取位置和比较值
  -o OUTPUT, --output OUTPUT
                        结果输出文件路径
  --config CONFIG       配置文件路径，用于加载默认参数
  --save-config SAVE_CONFIG
                        保存当前参数到配置文件
  - {text,json}, --format {text,json}
                        输出格式
  -v, --verbose         显示详细日志
  -t TRUE_LENGTH, --true-length TRUE_LENGTH
                        手动指定True页面的Content-Length
  -c TRUE_CONTENT, --true-content TRUE_CONTENT
                        手动指定True页面的内容关键字或模式
  -d DELAY_THRESHOLD, --delay-threshold DELAY_THRESHOLD
                        时间盲注延迟阈值倍数 (默认: 2.0)
  --interactive         启用交互式分析模式，手动标记True/False响应

使用示例：
1. 基本用法：分析PCAP文件并显示结果
   python main.py capture.pcap

2. 过滤特定URI：只分析包含login.php的请求
   python main.py capture.pcap --uri login.php

3. 手动指定True页面参数：
   python main.py capture.pcap --true-length 456
   python main.py capture.pcap --true-content "success"

4. 导出结果到文件：
   python main.py capture.pcap --output result.txt --format text
   python main.py capture.pcap --output result.json --format json

5. 时间盲注分析：
   python main.py capture.pcap --delay-threshold 3.0

6. 详细日志模式：
   python main.py capture.pcap --verbose
