# 说明
现在还是半成品！！！！

这是一款检测注入的工具，SQLMAP检测时候大而全，payload多，还有一些其他的网络请求，故自己看了SQLMAP的源码后，然后借chao鉴xi了SQLMAP，自己写了一款工具。


# 优点
1、网络请求少

2、支持的数据格式多（people={"name"="lufei",age=100}、http://127.0.0.1/?id=2.html）

3、有好的payload，有些情况可绕waf

4、增加符合国情的报错匹配