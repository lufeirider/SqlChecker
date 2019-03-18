# encoding=utf8
from collections import OrderedDict


class SqlInfo:
    dbms = ''
    payload = ''
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