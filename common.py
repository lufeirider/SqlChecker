# encoding=utf8
import urlparse
import urllib
import xml.sax
from xml.dom.minidom import parse
import xml.dom.minidom
import re
from setting import *
import requests
from difflib import *
import sys

#设置utf8编码
reload(sys)
sys.setdefaultencoding('utf8')

#read file
def read_file(filename):
    with open(filename,'r') as f:
        result = list()
        for line in f.readlines():
            line = line.strip()
            if not len(line) or not line.startswith('##'):
                result.append(line)
        return result

# print read_file('payload.txt')


# 从xml中读取payload字典当中
def read_xml_payloads():
    global g_payload_dict
    DOMTree = xml.dom.minidom.parse(PAYLOADS_XML)
    collection = DOMTree.documentElement

    dbms_collection = collection.getElementsByTagName("dbms")
    for dbms_node in dbms_collection:
        dbms = str(dbms_node.getAttribute("value"))
        g_payload_dict[dbms] = []
        payloads = dbms_node.getElementsByTagName('payload')
        for payload in payloads:
            payload = payload.getAttribute("value")
            g_payload_dict[dbms].append(payload)


# 解析data参数
def parse_data(data):

    #解析data,id=1&name=lufei&password=123456
    param_list = urlparse.parse_qsl(data, keep_blank_values=True)

    #parse_qsl函数会自动unquote,导致一些url %BE%AD%B7%BD变成字符串，搞乱了原来的编码，所以这里需要quote复原一下
    quote_param_list = []
    for parm in param_list:
        quote_param_list.append(((urllib.unquote(parm[0])),(urllib.unquote(parm[1]))))

    return quote_param_list

# 解析json
def parse_json(poc_param_list,param_index,param_name,para_json_value,payload):
    json_param_tuple = re.finditer(r'("(?P<name>[^"]+)"\s*:\s*".*?)"(?<!\\")', para_json_value)
    for json_param in json_param_tuple:
        poc_json_param = para_json_value[:json_param.regs[1][0]] + json_param.group(1) + payload + para_json_value[json_param.regs[1][1]:]
        # payload构造
        if param_index == 0:
            poc_param_list = [(param_name, poc_json_param)] + poc_param_list[param_index + 1:]
        else:
            poc_param_list = poc_param_list[0:param_index] + [(param_name, poc_json_param)] + poc_param_list[param_index + 1:]

        def link(param):
            return param[0] + '=' + param[1]

        data = '&'.join(map(link, poc_param_list))
        return data



# 检测报错日志报错信息
def check_dbms_error(html):
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
                if re.search(regexp,html):
                    if g_sql_info['dbms'] == '':
                        g_sql_info['dbms'] = self.dbms
                        g_sql_info['result'].append({'type':'error','dbms':self.dbms,'payload':g_sql_info['payload']})
                        print("##############################################################dbms:"+self.dbms + "##############################################################")

    # 创建一个 XMLReader
    parser = xml.sax.make_parser()
    # turn off namepsaces
    parser.setFeature(xml.sax.handler.feature_namespaces, 0)

    # 重写 ContextHandler
    handler = ErrorDbmsHandler()
    parser.setContentHandler(handler)

    parser.parse(ERROR_DBMS_XML)


# 检查Boolean注入，检查相似度
def check_ratio():
    global g_sql_info
    if g_sql_info['upper_ratio'] - g_sql_info['lower_ratio'] > CHECK_RATIO:
        g_sql_info['result'].append({'type': 'boolean', 'dbms': 'unknown', 'true payload': g_sql_info['true_payload'],'false payload': g_sql_info['false_payload'],'upper_ratio':str(g_sql_info['upper_ratio']),'lower_ratio':str(g_sql_info['lower_ratio'])})
        out_result()
    g_sql_info['upper_ratio'] = UPPER_RATIO
    g_sql_info['lower_ratio'] = LOWER_RATIO

# 检测
def check_boolean_inject(rsp):
    global g_sql_info
    if g_sql_info['payload_dbms'] == 'All' or g_sql_info['payload_dbms'] == 'Test':
        s = SequenceMatcher(None, rsp.content.replace(urllib.unquote(g_sql_info['payload']).encode(),''), g_sql_info['true_content'])
        ratio = s.ratio()
        #这里使用or等于的情况是页面都是false情况下，数字型判断name=lufei*1还是返回正确，如果存在注入肯定是后面的'%20'这个payload
        if g_sql_info['upper_ratio'] < ratio or g_sql_info['upper_ratio'] == ratio:
            g_sql_info['upper_ratio'] = ratio
            g_sql_info['true_payload'] = g_sql_info['payload']
        # 这里没有使用or等于的情况是，因为出错情况很随意
        if g_sql_info['lower_ratio'] > ratio:
            g_sql_info['lower_ratio'] = ratio
            g_sql_info['false_payload'] = g_sql_info['payload']

# 检测https
def check_https(req_info):
    try:
        if req_info['method'] == 'POST':
            req_right_info = req_info.copy()
            req_right_info['url'] = req_right_info['url'].replace(SQLMARK,"")
            req_right_info['data'] = req_right_info['data'].replace(SQLMARK, "")
            #req_right_info['headers'] = {}
            for header in req_info['headers']:
                req_right_info['headers'][header] = (req_info['headers'][header]).replace(SQLMARK, "")
            # 允许allow_redirects，会报https超过最大连接次数
            rsp = requests.post(req_right_info['url'], data=req_right_info['data'], headers=req_right_info['headers'], proxies=g_proxy, timeout=TIMEOUT,verify=True, allow_redirects=True)
        if req_info['method'] == 'GET':
            req_right_info = req_info.copy()
            req_right_info['url'] = req_right_info['url'].replace(SQLMARK,"")
            #req_right_info['headers'] = {}
            # 允许allow_redirects，会报https超过最大连接次数
            rsp = requests.get(req_right_info['url'], headers=req_right_info['headers'], proxies=g_proxy, timeout=TIMEOUT, verify=True,allow_redirects=True)
    except requests.exceptions.SSLError,err:
        print(err)
        return True

def get_right_resp(req_info):
    global g_sql_info
    if req_info['method'] == 'POST':
        try:
            req_right_info = req_info.copy()
            req_right_info['url'] = req_right_info['url'].replace(SQLMARK,"")
            req_right_info['data'] = req_right_info['data'].replace(SQLMARK, "")
            req_right_info['headers'] = {}
            for header in req_info['headers']:
                req_right_info['headers'][header] = (req_info['headers'][header]).replace(SQLMARK, "")

            rsp = requests.post(req_right_info['url'], data=req_right_info['data'], headers=req_right_info['headers'], proxies=g_proxy, timeout=TIMEOUT,verify=False, allow_redirects=False)
            g_sql_info['true_content'] = rsp.content
        except Exception, err:
            print(err)
    if req_info['method'] == 'GET':
        try:
            req_right_info = req_info.copy()
            req_right_info['url'] = req_right_info['url'].replace(SQLMARK,"")
            req_right_info['headers'] = {}
            for header in req_info['headers']:
                req_right_info['headers'][header] = (req_info['headers'][header]).replace(SQLMARK, "")
            rsp = requests.get(req_right_info['url'], headers=req_right_info['headers'], proxies=g_proxy, timeout=TIMEOUT, verify=False,allow_redirects=False)
            g_sql_info['true_content'] = rsp.content
        except Exception,err:
            print(err)


# 发送请求包，并判断注入
def send_request(req_info,type):
    if req_info['method'] == 'POST':
        try:
            # 显示参数和poc
            print(req_info[type])
            #这里allow_redirects禁止跟随是因为有些网站他会跳转到http://about:blank不是域名的地方导致异常
            rsp = requests.post(req_info['url'], data=req_info['data'], headers=req_info['headers'], proxies=g_proxy, timeout=TIMEOUT,verify=False, allow_redirects=False)
            check_dbms_error(rsp.content)
            check_boolean_inject(rsp)
        except requests.exceptions.Timeout:
            #这里没有使用print(req_info[type]+'存在sql注入')是因为req_info[type]类型不确定，可能是字典或者字符串
            g_sql_info['result'].append({'type': 'time', 'dbms': g_sql_info['payload_dbms'], 'payload': g_sql_info['payload'], 'position': type, 'poc': req_info[type]})
            out_result()
            exit()
    if req_info['method'] == 'GET':
        try:
            # 显示参数和poc
            print(req_info[type])
            rsp = requests.get(req_info['url'], headers=req_info['headers'], proxies=g_proxy, timeout=TIMEOUT, verify=False,allow_redirects=False)
            check_dbms_error(rsp.content)
            check_boolean_inject(rsp)
        except requests.exceptions.Timeout:
            g_sql_info['result'].append({'type': 'time', 'dbms': g_sql_info['payload_dbms'], 'payload': g_sql_info['payload'],'position':type,'poc':req_info[type]})
            out_result()
            exit()

# 对注入标记进行处理，判断注入
def check_mark_sql(req_info,payload_dict):
    global g_sql_info

    #print(req_info['headers'])

    #这里兼容get和post，所以可能有些是none
    req_info['data'] = req_info['data'] if req_info['data']!=None else ""
    req_info['cookie'] = req_info['cookie'] if req_info['cookie']!=None else ""

    if SQLMARK in req_info['url'] or SQLMARK in str(req_info['headers']) or SQLMARK in req_info['data']:
        g_sql_info['sql_mark'] = True
        if SQLMARK in req_info['url']:
            for dbms in payload_dict:
                for payload in payload_dict[dbms]:
                    # 深拷贝
                    req_poc_info = req_info.copy()
                    g_sql_info['payload'] = payload
                    g_sql_info['payload_dbms'] = dbms

                    if g_sql_info['dbms'] != '' and  g_sql_info['dbms'] != dbms:
                        #通用的payload不管dbms是什么都一定跑完，因为其他的payload都有敏感字符，遇到waf就gg了
                        if g_sql_info['payload_dbms'] != 'All':
                            continue

                    req_poc_info['url'] = req_info['url'].replace(SQLMARK,payload)
                    send_request(req_poc_info,'url')
            check_ratio()
        if SQLMARK in req_info['data']:
            for dbms in payload_dict:
                for payload in payload_dict[dbms]:
                    # 深拷贝
                    req_poc_info = req_info.copy()
                    g_sql_info['payload'] = payload
                    g_sql_info['payload_dbms'] = dbms

                    if g_sql_info['dbms'] != '' and g_sql_info['dbms'] != dbms:
                        if g_sql_info['payload_dbms'] != 'All':
                            continue

                    req_poc_info['data'] = req_info['data'].replace(SQLMARK, payload)
                    send_request(req_poc_info,'data')
            check_ratio()
        if SQLMARK in str(req_info['headers']):
            for dbms in payload_dict:
                for payload in payload_dict[dbms]:
                    # 深拷贝
                    req_poc_info = req_info.copy()
                    g_sql_info['payload'] = payload
                    g_sql_info['payload_dbms'] = dbms
                    #header头是不会url解码的，所以对于headers进行解码
                    payload = urllib.unquote(payload)
                    if g_sql_info['dbms'] != '' and g_sql_info['dbms'] != dbms:
                        if g_sql_info['payload_dbms'] != 'All':
                            continue

                    # 因为payload中有双引号，而因为再header头中，所以不能进行url编码会导致json.dumps爆出异常
                    #req_poc_info['headers'] = json.loads(json.dumps(req_info['headers']).replace(SQLMARK, payload))

                    #这进行初始化是为了防止req_poc_info['headers'] 和 req_info['headers'] 变成同一个地址的东西，称呼不同
                    req_poc_info['headers'] = {}
                    for header in req_info['headers']:
                        req_poc_info['headers'][header] = (req_info['headers'][header]).replace(SQLMARK, payload)

                    send_request(req_poc_info, 'headers')
            check_ratio()

def out_result():
    for result in g_sql_info['result']:
        if(result['type'] == 'time'):
            #g_sql_info['result'].append({'type': 'time', 'dbms': g_sql_info['payload_dbms'], 'payload': g_sql_info['payload'], 'position': type, 'poc': req_info[type]})
            print('##############type:' + result['type'] + '##############dbms:' + result['dbms'] + '##############payload:' + result['payload'] + '##############position:' + result['position'])
            print(result['poc'])
        elif(result['type'] == 'error'):
            # g_sql_info['result'].append({'type': 'error', 'dbms': self.dbms, 'payload': g_sql_info['payload']})
            print('##############type:' + result['type'] + '##############dbms:' + result['dbms'] + '##############payload:' + result['payload'])
        elif(result['type'] == 'boolean'):
            #g_sql_info['result'].append({'type': 'boolean', 'dbms': 'unknown', 'true payload': g_sql_info['true_payload'], 'false payload': g_sql_info['false_payload'], 'upper_ratio': str(g_sql_info['upper_ratio']), 'lower_ratio': str(g_sql_info['lower_ratio'])})
            print('##############type:' + result['type'] + '##############dbms:' + result['dbms'] + '##############true_payload:' + g_sql_info['true_payload'] + '##############false_payload:'+ g_sql_info['false_payload'])