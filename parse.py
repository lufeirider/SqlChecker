# -*- coding: utf-8 -*-
import re
import inspect
import logging

logger = logging.getLogger(__name__)


CRAWL_EXCLUDE_EXTENSIONS = (
"3ds", "3g2", "3gp", "7z", "DS_Store", "a", "aac", "adp", "ai", "aif", "aiff", "apk", "ar", "asf", "au", "avi", "bak",
"bin", "bk", "bmp", "btif", "bz2", "cab", "caf", "cgm", "cmx", "cpio", "cr2", "dat", "deb", "djvu", "dll", "dmg", "dmp",
"dng", "doc", "docx", "dot", "dotx", "dra", "dsk", "dts", "dtshd", "dvb", "dwg", "dxf", "ear", "ecelp4800", "ecelp7470",
"ecelp9600", "egg", "eol", "eot", "epub", "exe", "f4v", "fbs", "fh", "fla", "flac", "fli", "flv", "fpx", "fst", "fvt",
"g3", "gif", "gz", "h261", "h263", "h264", "ico", "ief", "image", "img", "ipa", "iso", "jar", "jpeg", "jpg", "jpgv",
"jpm", "jxr", "ktx", "lvp", "lz", "lzma", "lzo", "m3u", "m4a", "m4v", "mar", "mdi", "mid", "mj2", "mka", "mkv", "mmr",
"mng", "mov", "movie", "mp3", "mp4", "mp4a", "mpeg", "mpg", "mpga", "mxu", "nef", "npx", "o", "oga", "ogg", "ogv",
"otf", "pbm", "pcx", "pdf", "pea", "pgm", "pic", "png", "pnm", "ppm", "pps", "ppt", "pptx", "ps", "psd", "pya", "pyc",
"pyo", "pyv", "qt", "rar", "ras", "raw", "rgb", "rip", "rlc", "rz", "s3m", "s7z", "scm", "scpt", "sgi", "shar", "sil",
"smv", "so", "sub", "swf", "tar", "tbz2", "tga", "tgz", "tif", "tiff", "tlz", "ts", "ttf", "uvh", "uvi", "uvm", "uvp",
"uvs", "uvu", "viv", "vob", "war", "wav", "wax", "wbmp", "wdp", "weba", "webm", "webp", "whl", "wm", "wma", "wmv",
"wmx", "woff", "woff2", "wvx", "xbm", "xif", "xls", "xlsx", "xlt", "xm", "xpi", "xpm", "xwd", "xz", "z", "zip", "zipx")


class HTTPMETHOD:
    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"
    PUT = "PUT"
    DELETE = "DELETE"
    TRACE = "TRACE"
    OPTIONS = "OPTIONS"
    CONNECT = "CONNECT"
    PATCH = "PATCH"


def getPublicTypeMembers(type_, onlyValues=False):
    """
    Useful for getting members from types (e.g. in enums)

    >>> [_ for _ in getPublicTypeMembers(OS, True)]
    ['Linux', 'Windows']
    """

    retVal = []

    for name, value in inspect.getmembers(type_):
        if not name.startswith("__"):
            if not onlyValues:
                retVal.append((name, value))
            else:
                retVal.append(value)

    return retVal


def filterStringValue(value, charRegex, replacement=""):
    """
    Returns string value consisting only of chars satisfying supplied
    regular expression (note: it has to be in form [...])

    >>> filterStringValue(u'wzydeadbeef0123#', r'[0-9a-f]')
    u'deadbeef0123'
    """

    retVal = value

    if value:
        retVal = re.sub(charRegex.replace("[", "[^") if "[^" not in charRegex else charRegex.replace("[^", "["),
                        replacement, value)

    return retVal


def isListLike(value):
    """
    Returns True if the given value is a list-like instance

    >>> isListLike([1, 2, 3])
    True
    >>> isListLike(u'2')
    False
    """

    return isinstance(value, (list, tuple, set))


def getUnicode(value, encoding=None, noneToNull=False):
    """
    Return the unicode representation of the supplied value:

    >>> getUnicode(u'test')
    u'test'
    >>> getUnicode('test')
    u'test'
    >>> getUnicode(1)
    u'1'
    """

    if noneToNull and value is None:
        return None

    if isinstance(value, unicode):
        return value
    elif isinstance(value, basestring):
        while True:
            try:
                return unicode(value, encoding or ('utf8' if 'utf8' else None) or 'utf8')
            except UnicodeDecodeError, ex:
                try:
                    return unicode(value, 'utf8')
                except:
                    value = value[:ex.start] + "".join('\\x%02x' % ord(_) for _ in value[ex.start:ex.end]) + value[ex.end:]
    elif isListLike(value):
        value = list(getUnicode(_, encoding, noneToNull) for _ in value)
        return value
    else:
        try:
            return unicode(value)
        except UnicodeDecodeError:
            return unicode(str(value), errors="ignore")  # encoding ignored for non-basestring instances


def parseRequestFile(content, checkParams=True):
    request = content
    request = re.sub(r"\A[^\w]+", "", request)

    schemePort = re.search(r"(http[\w]*)\:\/\/.*?\:([\d]+).+?={10,}", request, re.I | re.S)

    if schemePort:
        scheme = schemePort.group(1)
        port = schemePort.group(2)
        request = re.sub(r"\n=+\Z", "", request.split(schemePort.group(0))[-1].lstrip())
    else:
        scheme, port = None, None

    # check format
    if not re.search(r"^[\n]*(%s).*?\sHTTP\/" % "|".join(getPublicTypeMembers(HTTPMETHOD, True)), request,re.I | re.M):
        #check POST xxxxxxxxxxx HTTP
        logger.info("request format error")
        return

    if re.search(r"^[\n]*%s.*?\.(%s)\sHTTP\/" % (HTTPMETHOD.GET, "|".join(CRAWL_EXCLUDE_EXTENSIONS)), request,re.I | re.M):
        #check jpg png static file
        logger.info("static file")
        return

    getPostReq = False
    url = None
    host = None
    method = None
    data = None
    cookie = None
    params = False
    newline = None
    lines = request.split('\n')
    headers = {}

    for index in xrange(len(lines)):
        line = lines[index]

        if not line.strip() and index == len(lines) - 1:
            break

        newline = "\r\n" if line.endswith('\r') else '\n'
        line = line.strip('\r')


        #get request method and url
        #'\\A(CONNECT|DELETE|GET|HEAD|OPTIONS|PATCH|POST|PUT|TRACE) (.+) HTTP/[\\d.]+\\Z'
        match = re.search(r"\A(%s) (.+) HTTP/[\d.]+\Z" % "|".join(getPublicTypeMembers(HTTPMETHOD, True)), line) if not method else None

        #在确定了POST头后面，如果后面有一个空行，并且没有解析到之前的data，就判断有参数
        if len(line.strip()) == 0 and method and method != HTTPMETHOD.GET and data is None:
            data = ""
            params = True

        elif match:
            method = match.group(1)
            url = match.group(2)

            if any(_ in line for _ in ('?', '=', '*')):
                params = True

            getPostReq = True

        # POST parameters
        elif data is not None and params:
            data += "%s%s" % (line, newline)

        # GET parameters
        elif "?" in line and "=" in line and ": " not in line:
            params = True

        # Headers
        elif re.search(r"\A\S+:", line):
            key, value = line.split(":", 1)
            value = value.strip().replace("\r", "").replace("\n", "")

            # Cookie and Host headers
            if key.upper() == 'cookie'.upper():
                cookie = value
            elif key.upper() == 'host'.upper():
                if '://' in value:
                    scheme, value = value.split('://')[:2]
                splitValue = value.split(":")
                host = splitValue[0]

                if len(splitValue) > 1:
                    port = filterStringValue(splitValue[1], "[0-9]")

            # Avoid to add a static content length header to
            # headers and consider the following lines as
            # POSTed data
            if key.upper() == 'length'.upper():
                params = True

            # Avoid proxy and connection type related headers
            elif key not in ('Proxy-Connection', 'Connection','Content-Length','Accept'):
                headers[getUnicode(key)] = getUnicode(value)
                headers[key] = value

    data = data.rstrip("\r\n") if data else data

    # if getPostReq and (params or cookie or not checkParams):
    #     if not port and isinstance(scheme, basestring) and scheme.lower() == "https":
    #         port = "443"
    #     elif not scheme and port == "443":
    #         scheme = "https"

        # 暂时
        # if 1==0:
        #     scheme = "https"
        #     port = port or "443"

    if not url.startswith("http"):
        url = "%s://%s:%s%s" % (scheme or "http", host, port or "80", url)
        scheme = None
        port = None

    return {'url':url, 'method':method, 'data':data, 'cookie':cookie, 'headers':headers}

def parse_url(content):
    request = content
    lines = request.split('\n')

    for index in xrange(len(lines)):
        line = lines[index]
        if not line.strip() and index == len(lines) - 1:
            break

        if re.match("(http|https)://.*",line) and 'HTTP' not in line:
            return {'url':line,'method':'GET','data':'','cookie':'','headers':{}}


if __name__=='__main__':
    req = '''
    
    
POST /guest/edit.php HTTP/1.1
Host: 127.0.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Cookie: PHPSESSID=046bc5391513ad66f8406b14d4a97f91
Content-Type application/x-www-form-urlencoded
Content-Length: 4

id=1
    '''
    req = '''
GET /guest/edit.php?age=2&name=&id=2 HTTP/1.1
Host: 127.0.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=046bc5391513ad66f8406b14d4a97f91;user=admin;password=123456
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close


    '''

    req = '''
POST /guest/edit.php HTTP/1.1
Host: 127.0.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Content-Type: multipart/form-data; boundary=--------805470139
Content-Length: 232

----------805470139
Content-Disposition: form-data; name="age"

2
----------805470139
Content-Disposition: form-data; name="name"


----------805470139
Content-Disposition: form-data; name="id"

2
----------805470139--

    '''

    print(parseRequestFile(req))

    req = '''
http://127.0.0.1:81/guest/edit.php?id=2
        '''
    print(parse_url(req))


