# encoding=utf8
import re


# 为静态
import re
import urlparse

# 解析key-value参数
req = "age=11&id=2&name=lufei"

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
           <urn:TeacherName>11111111111</urn:TeacherName>
           <urn:StudentName>2222222222</urn:StudentName>
        </urn:GetArrangementByTeacherAndStudent_CurrentDay>
     </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""

param_tuple = re.finditer(r"(<(?P<name>[^>]+)( [^<]*)?>)([^<]+)(</\2)",req)
for param in param_tuple:
    print(param.group(2)) #urn:TeacherName
    print(param.group(4)) #11111111111
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

111111111111
----------1898913199
Content-Disposition: form-data; name="user"

lufei
----------1898913199--
"""

# 正则分两部分，上下两部分
# 上部分
# Content-Disposition: form-data; name="age"\n
# \n
# 111111111111

# 下部分
# \n--

param_tuple = re.finditer(r"(?si)((Content-Disposition[^\n]+?name\s*=\s*[\"']?(?P<name>[^\"'\r\n]+)[\"']?)((\r)?\n){2}(.*?))(((\r)?\n)+--)",req)
for param in param_tuple:
    print(param.group(3)) #age
    print(param.group(6)) # 11111111
    print(req[:param.regs[6][0]] + param.group(6) + "##" + req[param.regs[6][1]:])



#url
import re
import urlparse

req = """
http://127.0.0.1/edit.php?id=ASD我==&name=aaaaaaaaaa
"""

parse_url = urlparse.urlparse(req)
offset = req.index(parse_url.query)
param_tuple = re.finditer(r'(.*?)=(.*?)(&|$)', parse_url.query)
for param in param_tuple:
    print(param.group(1)) #name
    print(param.group(2)) #aaaaaaaaaa

    #添加偏移
    temp_param = (offset + param.regs[1][0],offset + param.regs[1][1])
    temp_value = (offset + param.regs[2][0],offset + param.regs[2][1])

    print(req[:temp_value[0]] + param.group(2) + "##" + req[temp_value[1]:])


#cookie
import re

req = """
GET /guest/edit.php?id=2 HTTP/1.1
Host: 127.0.0.1
Connection: close
Accept-Encoding: gzip, deflate
Accept: */*
Cookie: name=11111-2222222; age=1111111111; Name=lufei-xxxxx
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
"""

req = """
name=1111111111111-1111111111111-222222222; shshshfpb=20e287ea124fa4cf892abb8d3ad1d75185bfd1f490bb8387935de60477; TrackID=1z9BisvpQGAJbdPdtLvAbQJjZcFo-Qim-skQOU05VRVuJ5Eg4oim8nICoxH9lL1RmBpbaTLsYmEVlJs37QekKuzgIMELDlvOGCv3bdqNAlXM; __jdu=15433137290541176350556; __jdc=122270672; __jdv=122270672|direct|-|none|-|1553318548451; areaId=1; ipLoc-djd=1-72-0; PCSYCityID=1; user-key=8d648a00-7a22-45e7-a48c-3ed424440039; cn=0; __jda=122270672.15433137290541176350556.1543313729.1553318548.1553323258.11; __jdb=122270672.2.15433137290541176350556|11.1553323258; shshshfp=4fefe3cd78ffe0ec09b92fa9518ba8c9; shshshsID=a8ea895a2bb7902b6a6506b61ec5b4ed_2_1553323262437
"""

param_tuple = re.finditer(r'(\S*?)=(\S*?)(;|$)', req)
for param in param_tuple:
    print(param.group(1)) #name
    print(param.group(2)) #1111111111111-1111111111111-222222222
    print(req[:param.regs[2][0]] + param.group(2) + '##' + req[param.regs[2][1]:])