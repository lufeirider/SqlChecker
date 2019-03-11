# encoding=utf8
import re
import urlparse
import requests

url = 'http://127.0.0.1/guest/edit.php?id=2'
parse_url = urlparse.urlparse(url)
url = "%s://%s:%s%s%s%s" % ("https", parse_url.hostname, "443", parse_url.path, "?" + parse_url.query if parse_url.query else "", "#" + parse_url.fragment if parse_url.fragment else "")
print(url)