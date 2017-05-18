 #! -*- coding:utf-8 -*-

'''
__author__="nMask"
__Date__="2017年5月15日"
__Blog__="http://thief.one"
__version__="1.0"
__Python__="2.7.11"
'''

import requests 
# from oprethinkdb import oprethinkdb ＃数据库模块
import re

url="https://technet.microsoft.com/en-us/library/security/dn632603.aspx" 
res='title=\"MS[\d-]+\">(.*)</a>' #re
msurl="https://technet.microsoft.com/en-us/library/security/"
res2=r"<a href=\"([^>]*)\">([^<]*)<\/a>[\s\<\>spanclu \=\"\[\]\d\/]+?[^<]+?<br />(\([^\<\(\)]*\))" #re
p2=re.compile(res2,re.DOTALL)

red = '\033[1;31m'
green = '\033[1;32m'
yellow = '\033[1;33m'
white = '\033[1;37m'
reset = '\033[0m'


def getcontent(url):
	'''
	获取每年的ms漏洞号
	'''
	try:
		body=requests.get(url).content
	except:
		print "%s[INFO]Request url error %s" % (red,reset)
		result_list=[]
	else:
		p=re.compile(res)
		result_list=p.findall(body)
	'''
	result_list=['MS16-003',......]
	'''
	return result_list   

def getkb(url,ms):
	'''
	获取一个ms漏洞每个系统版本对应的kb号。
	'''
	dicts={}
	dicts["MS_ID"]=ms
	try:
		body=requests.get(url).content
	except:
		print "%s[INFO]Request url error %s" % (red,reset)
	else:
		result_list=p2.findall(body)
		print "%s[INFO]result_lens is %s %s" % (green,len(result_list),reset)
		dicts["Content"]=result_list
		print "[INFO]result is ",dicts

		'''
		将结果数据存入数据库
		'''
		# try:
		# 	cur_db.Insert(dicts,"MS_ID")
		# 	print "%s[INFO]Insert DB Success %s" % (green,reset)
		# except:
		# 	print "%s[INFO]Insert DB error %s" % (red,reset)




if __name__=="__main__":

	# cur_db=oprethinkdb("","")

	result_list=getcontent(url)

	for ms in result_list:
		msurl_new=msurl+ms.lower()+".aspx"
		print "%s[INFO]target_url is %s %s" % (white,msurl_new,reset)
		getkb(msurl_new,ms)
		# break






