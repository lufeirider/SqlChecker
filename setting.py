# encoding=utf8
from collections import defaultdict, OrderedDict

# 判断延迟的时间
TIMEOUT = 5

# 上限
UPPER_RATIO = -1

# 下限
LOWER_RATIO = 2

# 检测注入的ratio标准,这里比SQLMAP的0.05少是因为这里是检测可疑的注入，而非百分百判断
CHECK_RATIO = 0.04

# 注入标记 使用#号可能有问题
SQLMARK = "@@"

# 是否有注入标记
MARKFLAG = False

# 网站是否是https
SSLFLAG = False

# Regular expression used for detecting multipart POST data
MULTIPART_REGEX = "(?i)Content-Disposition:[^;]+;\s*name="

# Regular expression used for detecting JSON POST data
JSON_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null).*\}\s*(\]\s*)*\Z'

# Regular expression for XML POST data
XML_REGEX = r"(?s)\A\s*<[^>]+>(.+>)?\s*\Z"

# DBMS ERROR XML
ERROR_DBMS_XML = "xml/errors.xml"

# PAYLOADS XML
PAYLOADS_XML = "xml/payloads.xml"

# payload 字典
g_payload_dict = OrderedDict()

# 代理
g_proxy = {'http':'http://127.0.0.1:4321','https':'https://127.0.0.1:4321'}
#g_proxy = {}
# 当前注入的情况
g_sql_info = {}