__author__='Polaris-L'
import json
import nmap
import openpyxl
import requests
import sys

#通过调用api接口来获取需要扫描的ip地址，并将其储存为字典r_dict
url_ip = 'http://192.168.37.182/110/asset/public/get_idc_ip'

apikey = ''
#如有apikey则填写

for i in range(1,12):
    payload_ip = {
        'apikey':apikey,
        'idc':i
    }
    ipj = requests.post(url_ip,data=payload_ip)
    ipj_dict=json.loads(ipj.text)
    #字典中key为message的值是我们需要的参数，提取出来并保存
    ip=ipj_dict['message']
    ip=ip.replace(";"," ")

ip = ip.split(" ")

#在通过另一个接口获取需要扫描的端口号，也将其储存为字典形式port_dict

#请求api地址

#请求参数
url_port='http://192.168.37.182/110/asset/public/get_danger_ports'
payload_port = {
        'apikey':apikey
    }
portj = requests.post(url_port, data=payload_port)
portj_dict=json.loads(portj.text)
#字典中key为message的值是我们需要的参数，提取出来并保存
port=portj_dict['message']

#print(ip)
#print(port)
arg='-Pn -T4'

for each in ip:
    try:
        nm = nmap.PortScannerYield()
        for result in nm.scan(hosts=each, ports=port,arguments=arg):
            ip_post=result[0]
            #ip是result[0]
            dic=result[1]['scan'][result[0]]['tcp']
            port_post = list(dic.keys())

                
            url_post = 'http://192.168.37.182/110/asset/public/danger_ip_port_add'
            apikey_post = 'ce0baa1a417a7f76f449db63895a29dd31758na5'
            payload_post = {
                'apikey':apikey_post,
                'ip':ip_post,
                'port':port_post
            }
            requests.post(url_post,data=payload_post)
    except Exception as e:
        info = {"status":-2,"payload":"","report":""+str(e)+"","poc":""}
        print(json.dumps(info))
