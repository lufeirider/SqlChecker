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
    global g_sql_info
    DOMTree = xml.dom.minidom.parse(PAYLOADS_XML)
    collection = DOMTree.documentElement

    dbms_collection = collection.getElementsByTagName("dbms")
    for dbms_node in dbms_collection:
        dbms = str(dbms_node.getAttribute("value"))
        g_sql_info.payload_dict[dbms] = []
        payloads = dbms_node.getElementsByTagName('payload')
        for payload in payloads:
            payload = payload.getAttribute("value")
            g_sql_info.payload_dict[dbms].append(payload)


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
            g_sql_info.true_content = rsp.text
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
            g_sql_info.true_content = rsp.text
        except Exception,err:
            print(err)