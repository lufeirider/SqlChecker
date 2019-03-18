# encoding=utf8
import re
import urllib
import xml
from collections import OrderedDict
from difflib import SequenceMatcher
import requests


# DBMS ERROR XML
ERROR_DBMS_XML = "xml/errors.xml"

# 检测注入的ratio标准,这里比SQLMAP的0.05少是因为这里是检测可疑的注入，而非百分百判断
CHECK_RATIO = 0.04

# 上限
UPPER_RATIO = -1

# 下限
LOWER_RATIO = 2

# 代理
g_proxy = {'http':'http://127.0.0.1:4321','https':'https://127.0.0.1:4321'}

# 判断延迟的时间
TIMEOUT = 5

# 注入标记 使用#号可能有问题
SQLMARK = "@@"



class SqlChecker:
    dbms = ''
    payload = ''
    html = ''
    payload_dbms = ''
    true_payload = ''
    false_payload = ''
    #是否有mark标记
    mark_flag = False
    upper_ratio = ''
    upper_payload = ''
    lower_ratio = ''
    lower_payload = ''
    true_content = ''
    payload_dict = {}
    result_list = []

    def __init__(self):
        # 非字符数字类型再这里重新声明下
        self.mark_flag = False
        self.result_list = []
        # payload 有序字典，防止payload自动乱序
        self.payload_dict = OrderedDict()

    #输出结果
    def out_result(self):
        for result in self.result_list:
            if(result['type'] == 'time'):
                #g_sql_info.result_list.append({'type': 'time', 'dbms': g_sql_info.payload_dbms, 'payload': g_sql_info.payload, 'position': type, 'poc': req_info[type]})
                print('##############type:' + result['type'] + '##############dbms:' + result['dbms'] + '##############payload:' + result['payload'] + '##############position:' + result['position'])
                print(result['poc'])
            elif(result['type'] == 'error'):
                # g_sql_info.result_list.append({'type': 'error', 'dbms': self.dbms, 'payload': g_sql_info.payload})
                print('##############type:' + result['type'] + '##############dbms:' + result['dbms'] + '##############payload:' + result['payload'])
            elif(result['type'] == 'boolean'):
                #g_sql_info.result_list.append({'type': 'boolean', 'dbms': 'unknown', 'true payload': g_sql_info.true_payload, 'false payload': g_sql_info.false_payload, 'upper_ratio': str(g_sql_info.upper_ratio), 'lower_ratio': str(g_sql_info.lower_ratio)})
                print('##############type:' + result['type'] + '##############dbms:' + result['dbms'] + '##############true_payload:' + self.true_payload + '##############false_payload:'+ self.false_payload)

    # 检测报错日志报错信息
    def check_dbms_error(self):
        out_self = self
        class ErrorDbmsHandler(xml.sax.ContentHandler):
            def __init__(self):
                self.dbms = ""

            # 元素开始事件处理
            def startElement(self, tag, attr):
                self.CurrentData = tag
                if tag == "dbms":
                    dbms = attr["value"]
                    self.dbms = dbms

                if tag == "error":
                    regexp = attr["regexp"]
                    if re.search(regexp, out_self.html):
                        if out_self.dbms == '':
                            out_self.dbms = self.dbms
                            out_self.result_list.append({'type': 'error', 'dbms': self.dbms, 'payload': out_self.payload})
                            print("##############################################################dbms:" + self.dbms + "##############################################################")

        # 创建一个 XMLReader
        parser = xml.sax.make_parser()
        # turn off namepsaces
        parser.setFeature(xml.sax.handler.feature_namespaces, 0)

        # 重写 ContextHandler
        handler = ErrorDbmsHandler()
        parser.setContentHandler(handler)

        parser.parse(ERROR_DBMS_XML)

    # 检测boolean类型注入
    def check_boolean_inject(self):
        if self.payload_dbms == 'All' or self.payload_dbms == 'Test':
            s = SequenceMatcher(None, self.html.replace(urllib.unquote(self.payload).encode(), ''), self.true_content)
            ratio = s.ratio()
            # 这里使用or等于的情况是页面都是false情况下，数字型判断name=lufei*1还是返回正确，如果存在注入肯定是后面的'%20'这个payload
            if self.upper_ratio < ratio or self.upper_ratio == ratio:
                self.upper_ratio = ratio
                self.true_payload = self.payload
            # 这里没有使用or等于的情况是，因为出错情况很随意
            if self.lower_ratio > ratio:
                self.lower_ratio = ratio
                self.false_payload = self.payload

    # 检查Boolean注入，检查相似度
    def check_ratio(self):
        if self.upper_ratio - self.lower_ratio > CHECK_RATIO:
            self.result_list.append({'type': 'boolean', 'dbms': 'unknown', 'true payload': self.true_payload, 'false payload': self.false_payload, 'upper_ratio': str(self.upper_ratio), 'lower_ratio': str(self.lower_ratio)})
            self.out_result()
            self.upper_ratio = UPPER_RATIO
            self.lower_ratio = LOWER_RATIO


    # 发送请求包，并判断注入
    def send_request(self,req_info,type):
        if req_info['method'] == 'POST':
            try:
                # 显示参数和poc
                print(req_info[type])
                #这里allow_redirects禁止跟随是因为有些网站他会跳转到http://about:blank不是域名的地方导致异常
                rsp = requests.post(req_info['url'], data=req_info['data'], headers=req_info['headers'], proxies=g_proxy, timeout=TIMEOUT,verify=False, allow_redirects=False)
                self.html = rsp.content
                self.check_dbms_error()
                self.check_boolean_inject()
            except requests.exceptions.Timeout:
                #这里没有使用print(req_info[type]+'存在sql注入')是因为req_info[type]类型不确定，可能是字典或者字符串
                self.result_list.append({'type': 'time', 'dbms': self.payload_dbms, 'payload': self.payload, 'position': type, 'poc': req_info[type]})
                self.out_result()
                exit()
        if req_info['method'] == 'GET':
            try:
                # 显示参数和poc
                print(req_info[type])
                rsp = requests.get(req_info['url'], headers=req_info['headers'], proxies=g_proxy, timeout=TIMEOUT, verify=False,allow_redirects=False)
                self.html = rsp.content
                self.check_dbms_error()
                self.check_boolean_inject()
            except requests.exceptions.Timeout:
                self.result_list.append({'type': 'time', 'dbms': self.payload_dbms, 'payload': self.payload,'position':type,'poc':req_info[type]})
                self.out_result()
                exit()

    # 对注入标记进行处理，判断注入
    def check_mark_sql(self,req_info):
        # print(req_info['headers'])

        # 这里兼容get和post，所以可能有些是none
        req_info['data'] = req_info['data'] if req_info['data'] != None else ""
        req_info['cookie'] = req_info['cookie'] if req_info['cookie'] != None else ""

        if SQLMARK in req_info['url'] or SQLMARK in str(req_info['headers']) or SQLMARK in req_info['data']:
            self.mark_flag = True
            if SQLMARK in req_info['url']:
                for dbms in self.payload_dict:
                    for payload in self.payload_dict[dbms]:
                        # 深拷贝
                        req_poc_info = req_info.copy()
                        self.payload = payload
                        self.payload_dbms = dbms

                        if self.dbms != '' and self.dbms != dbms:
                            # 通用的payload不管dbms是什么都一定跑完，因为其他的payload都有敏感字符，遇到waf就gg了
                            if self.payload_dbms != 'All':
                                continue

                        req_poc_info['url'] = req_info['url'].replace(SQLMARK, payload)
                        self.send_request(req_poc_info, 'url')
                self.check_ratio()
            if SQLMARK in req_info['data']:
                for dbms in self.payload_dict:
                    for payload in self.payload_dict[dbms]:
                        # 深拷贝
                        req_poc_info = req_info.copy()
                        self.payload = payload
                        self.payload_dbms = dbms

                        if self.dbms != '' and self.dbms != dbms:
                            if self.payload_dbms != 'All':
                                continue

                        req_poc_info['data'] = req_info['data'].replace(SQLMARK, payload)
                        self.send_request(req_poc_info, 'data')
                self.check_ratio()
            if SQLMARK in str(req_info['headers']):
                for dbms in self.payload_dict:
                    for payload in self.payload_dict[dbms]:
                        # 深拷贝
                        req_poc_info = req_info.copy()
                        self.payload = payload
                        self.payload_dbms = dbms
                        # header头是不会url解码的，所以对于headers进行解码
                        payload = urllib.unquote(payload)
                        if self.dbms != '' and self.dbms != dbms:
                            if self.payload_dbms != 'All':
                                continue

                        # 因为payload中有双引号，而因为再header头中，所以不能进行url编码会导致json.dumps爆出异常
                        # req_poc_info['headers'] = json.loads(json.dumps(req_info['headers']).replace(SQLMARK, payload))

                        # 这进行初始化是为了防止req_poc_info['headers'] 和 req_info['headers'] 变成同一个地址的东西，称呼不同
                        req_poc_info['headers'] = {}
                        for header in req_info['headers']:
                            req_poc_info['headers'][header] = (req_info['headers'][header]).replace(SQLMARK, payload)

                            self.send_request(req_poc_info, 'headers')
                self.check_ratio()