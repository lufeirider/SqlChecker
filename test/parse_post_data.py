# encoding=utf8
import re


# 为静态
import re
import urlparse

# 解析参数
req = "age=11&id=2&name=lufei"

#字符串型
#[('age', '11', '&'), ('id', '2', '&'), ('name', 'lufei', '')]
param_tuple = re.finditer(r'(.*?)=(.*?)(&|$)', req)
for param in param_tuple:
    print(param.group(1)) #age
    print(param.group(2)) #11
    print(req[:param.regs[2][0]] + param.group(2) + '##' + req[param.regs[2][1]:])



# 伪静态
url = 'http://www.freebuf.com/articles/web/74324.html'
#url = 'https://security.tencent.com/index.php/blog/msg/12'
#url = 'http://www.csdn.net/article/2014-07-11/2820615-14-world-best-programmers'

parse_url = urlparse.urlparse(url)
if parse_url.query == '':
    for digit in re.finditer(r'\d+',url):
        #print(digit.group(0))
        mark_url = url[:digit.regs[0][0]] + digit.group(0) + "*" + url[digit.regs[0][1]:]
        print(mark_url)

# xml
import re
req = """
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"  xmlns:xsd="http://www.w3.org/1999/xmlSchema"  xmlns:xsi="http://www.w3.org/1999/xmlSchema-instance"  xmlns:m0="http://tempuri.org/"  xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:urn="http://tempuri.org/">
     <SOAP-ENV:Header/>
     <SOAP-ENV:Body>
        <urn:GetArrangementByTeacherAndStudent_CurrentDay>
           <urn:TeacherName>rqalfxgu</urn:TeacherName>
           <urn:StudentName>rqalfxgu</urn:StudentName>
        </urn:GetArrangementByTeacherAndStudent_CurrentDay>
     </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""


param_tuple = re.finditer(r"(<(?P<name>[^>]+)( [^<]*)?>)([^<]+)(</\2)",req)
for param in param_tuple:
    print(param.group(2))
    print(req[:param.regs[4][0]] + param.group(4) + "##" + req[param.regs[4][1]:])



# json
import re
req = """
POST /guest/edit.php HTTP/1.1
Host: 127.0.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Content-type: application/json
Content-Length: 67

{"age":11,"name":"lufei","id":2,"admin":true,"group":[1,"2",3,1,5]}
"""

req = """{"age":11,"name":"lufei","nick":"","id":2,"admin":true,"group":[1,"2",3,1,5]}
"""

# 字符串型
# .+? 更改为 .*? ，主要是防止nick这种空
param_tuple = re.finditer(r'"(?P<name>[^"]+)"\s*:\s*"(.*?)"(?<!\\")', req)
for param in param_tuple:
    print(param.group(1))   #name
    print(param.group(2))   #lufei
    print(req[:param.regs[2][0]] + param.group(2) + '##' + req[param.regs[2][1]:])

#数字型
param_tuple = re.finditer(r'"(?P<name>[^"]+)"\s*:\s*(-?\d[\d\.]*)\b', req)
for param in param_tuple:
    print(param.group(1)) #age
    print(param.group(2)) #11
    print(req[:param.regs[2][0]] + '"' + param.group(2) + '##' + '"' + req[param.regs[2][1]:])

#数组类型
match = re.search(r'(?P<name>[^"]+)"\s*:\s*\[([^\]]+)\]', req)
if match:
    print(match.group(1))
    list_str = match.group(2)
    #列表中的字符型
    param_tuple = re.finditer(r'("[^"]+)"', list_str)
    for param in param_tuple:
        print(req.replace(list_str,list_str[:param.regs[1][0]] + param.group(1) + '##' + list_str[param.regs[1][1]:]))

    #列表中的数字型
    param_tuple = re.finditer(r'(\A|,|\s+)(-?\d[\d\.]*\b)', list_str)
    for param in param_tuple:
        print(req.replace(list_str, list_str[:param.regs[2][0]] + '"' + param.group(2) + '##' + '"' + list_str[param.regs[2][1]:]))


# multipart
import re
req = """
POST /guest/edit.php HTTP/1.1
Host: 127.0.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Content-Type: multipart/form-data; boundary=--------1898913199
Content-Length: 240

----------1898913199
Content-Disposition: form-data; name="id"


----------1898913199
Content-Disposition: form-data; name="age"

2
----------1898913199
Content-Disposition: form-data; name="user"

lufei
----------1898913199--
"""

# 正则分两部分，上下两部分
# 上部分
# Content-Disposition: form-data; name="id"
# \n

# 下部分
# xxxxx
# \n
# --

param_tuple = re.finditer(r"(?si)((Content-Disposition[^\n]+?name\s*=\s*[\"']?(?P<name>[^\"'\r\n]+)[\"']?).+?\r?\n?)(((\r)?\n)+--)",req)
for param in param_tuple:
    print(param.group(3))
    print(req[:param.regs[1][0]] + param.group(1) + "##" + req[param.regs[1][1]:])
