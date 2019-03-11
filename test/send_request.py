# encoding=utf8

import requests
import json
from parse import *
g_proxy = {'http':'http://127.0.0.1:4321','https':'https://127.0.0.1:4321'}

req = '''
POST /member.php?infloat=yes&lostpwsubmit=yes&mod=lostpasswd HTTP/1.1
Content-Length: 99
Content-Type: application/x-www-form-urlencoded
Referer: http://dthrb.com
Cookie: sfgZ_2132_saltkey=tGTYEuQT; sfgZ_2132_lastvisit=1550429318; sfgZ_2132_sid=Lqi7dd; sfgZ_2132_lastact=1550434122%09like.php%09; sfgZ_2132_st_p=0%7C1550432956%7Cae724f48057dcf04c36fb557b395f010; sfgZ_2132_visitedfid=48D65; sfgZ_2132_viewid=tid_1678; sfgZ_2132_st_t=0%7C1550432957%7C98bb9e653e89f6d1fd917e7da4e823f5; sfgZ_2132_atarget=-1; sfgZ_2132_forum_lastvisit=D_70_1550432924D_65_1550432957; sfgZ_2132_con_request_uri=https%3A%2F%2Fdthrb.com%2Fconnect.php%3Fmod%3Dlogin%26op%3Dcallback%26referer%3Dforum.php%253Fmod%253Dviewthread%2526tid%253D1690; sfgZ_2132_sendmail=1; sfgZ_2132_home_readfeed=1550432925; sfgZ_2132_home_diymode=1; sfgZ_2132__refer=%252Fhome.php%253Fac%253Dclick%2526clickid%253D4%2526handlekey%253Dclickhandle%2526hash%253D990c1aea3df0d5641c8f726cee6f9abd%2526id%253D1597%2526idtype%253Daid%2526mod%253Dspacecp%2526op%253Dadd
Host: dthrb.com
Connection: Keep-alive
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
Accept: */*

lostpwsubmit=true&email=sample%40email.tst&formhash=8b19209f&handlekey=lostpwform&username=aa%bf@@
'''

req_info = parseRequestFile(req) if parseRequestFile(req) else parse_url(req)

rsp = requests.post(req_info['url'], data=req_info['data'], headers=req_info['headers'], proxies=g_proxy,
              timeout=5,
              verify=True, allow_redirects=False)

