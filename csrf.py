import time
import re
from libmproxy.flow import FlowWriter
from libmproxy.script import concurrent
import requests,json
#from libmproxy.protocol.http import decoded
DEBUG="EBUG2"
CSRF_FOUND_URLS=[]
XXE_FOUND_URLS=[]
SSRF_FOUND_URLS=[]
FILE_INCLUDE_FOUND_URLS=["http://b.scorecardresearch.com/b"]
JSONP_FOUND_URLS=["http://api.share.baidu.com/getnum"]
SQLI_FOUND_URLS=[]
SQLI_POST_HAVE_CHECKED_URLS=[]
SQLI_GET_HAVE_CHECKED_URLS=[]
SSRF_SITE="113.251.171.47"
######options check which######
ENABLE_CSRF=0
ENABLE_XXE=0
ENABLE_FILE_INCLUDE=0
ENABLE_SSRF=0
ENABLE_JSONP=0
ENABLE_SQLI=1
def url_exclude(url):
	filter_keywords=["js","css","gif","jpeg","png","swf","jpg","ico","http://www.google-analytics.com","http://192.168.0.1","xsxsxrxf=1","xcxsxrxf=1","http://pagead2.googlesyndication.com","http://googleads.g.doubleclick.net","http://pos.baidu.com","http://z8.cnzz.com/stat.htm"]
	for keyword in filter_keywords:
		if url.find(keyword)!=-1:
			return 1
	return 0
def url_include(url):
	filter_keywords=[]
	for keyword in filter_keywords:
		if url.find(keyword)==-1:
			return 1
	return 0
def d_print(msg,level=1):
    	if DEBUG=="DEBUG"+str(level):
		print msg
def p(keywords,content):
	for keyword in keywords:
		if keyword in content.lower():
			return 1
    	return 0
def p_re(keywords,content):
	for keyword in keywords:
		d_print(keyword+"  "+content)
		r=re.findall(keyword,content.lower())
		if len(r)>0:
			return r[0]
	return 0
def url_include_site(values):
	for value in values:
		r=p_re(["(http://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})","(http://)?([\s\S]{1,}\.cn)","(http://)?([\s\S]{1,}\.com)","(http://)?([\s\S]{1,}\.tk)","(http://)?([\s\S]{1,}\.so)","(http://)?([\s\S]{1,}\.net)","(http://)?([\s\S]{1,}\.org)"],value)
		if r:
			return r[1]
	return 0
#determine if url parameters contains filename
def php_file_include(values):
	for value in values:
		if p_re(["[\d\w-]{1,}\.php","[\d\w-]{1,}\.asp","[\d\w-]{1,}\.jsp","[\d\w-]{1,}\.do","[\d\w-]{1,}\.action","[\d\w-]{1,}\.htm"],value):
			return 1
	return 0
#determine if url parameters contains filename
def file_include(values):
	for value in values:
		if p_re(["[\d\w-]{1,}\.htm","[\d\w-]{1,}\.php","[\d\w-]{1,}\.asp","[\d\w-]{1,}\.jsp","[\d\w-]{1,}\.do","[\d\w-]{1,}\.action","[\d\w-]{1,}\.txt","[\d\w-]{1,}\.xls","[\d\w-]{1,}\.doc","[\d\w-]{1,}\.xml"],value):
			return 1
	return 0
def get_values(xxdict):
	yydict=[]
	for xx in xxdict:
		yydict.append(xx[1])
	return yydict
def chongfu(request,listname):
	base_url=request.url.split("?")[0]
	names=request.get_query().keys()
        names.sort()
	#determine tow similar url
	#such as a.com/a.php?file=a.html and a.com/a.php?file=b.html
	if base_url+str(names) not in listname:
		return 1
	return 0
	
def output(listname,request,loudongming,context):
	base_url=request.url.split("?")[0]
	names=request.get_query().keys()
        names.sort()
	#determine tow similar url
	#such as a.com/a.php?file=a.html and a.com/a.php?file=b.html
	if chongfu(request,listname):
		print("----"+loudongming+" Found-----\n"+request.method+" "+request.url)
		listname.append(base_url+str(names))
	if loudongming=="XXE":
		print request.headers
		print request.content
	d_print(listname,2)
def CSRF_check(request,context):
	#token,or some positive keywords,jianshao wubao
	TOKEN_KEYWORDS=["token","csrf","search","login","xsrf","capture","captcha","form_hash"]
	PAGE_KEYWORDS=["search","login"]
	WHITE_KEYWORDS=[""]
	request.decode()
	if p(TOKEN_KEYWORDS,request.content)==1 or p(TOKEN_KEYWORDS,request.url)==1:
		d_print("-----csrf token found----\n"+"url:"+str(request.url))
	elif p(PAGE_KEYWORDS,request.url)==1 or p(PAGE_KEYWORDS,request.content)==1:
		d_print("-----post,but it seems fuck page\n"+"url:"+str(request.url))
	else:
		if p(["update","edit","add","delete","info","message","action"],request.url+request.content):
			#request.headers['cookie']={'cookie=testfortest'}
			output(CSRF_FOUND_URLS,request,"CSRF",context)
			#https content
			if request.url.startswith("http://"):
				print(request.content)
	#		context.replay_request(f,block=True)
		else:
			#different url
			if len(request.get_query())==0:
				request.url=request.url+"?xcxsxrxf=1"
			else:
				request.url=request.url+"&xcxsxrxf=1"
				
@concurrent
def request(context, flow):
	request=flow.request
	#use request.url,not request.host
        #because http://anysice.google.com/xxx.php?url=http://test.com/aa
	if url_exclude(request.host)==0 and url_include(request.host)==0:
		#if f.request.method=="GET":
		#	f.request.headers['cookie']={'cookie=testfortest'}
		#	context.replay_request(f,block=True)
		values=get_values(request.get_query().items())
		if ENABLE_FILE_INCLUDE:
			if file_include(values):
				output(FILE_INCLUDE_FOUND_URLS,request,"File include",context)
		r=url_include_site(values)
		if r:
			#SSRF
			if ENABLE_SSRF:
				#not will be xxx.com/a.gif?wap=xxx.com
				if p(["url","domain","share","wap","link","src","source","target","3g","display","u"],str(request.get_query().keys())) and php_file_include(request.get_path_components()):
					f=context.duplicate_flow(flow)
					f.request.url=f.request.url.replace(r,SSRF_SITE)+"&xsxsxrxf=1"
					d_print(f.request.url,2)
					context.replay_request(f)
					output(SSRF_FOUND_URLS,request,"SSRF",context)
	        if request.method=="POST":
			#CSRF check
			if ENABLE_CSRF:
				if len(request.headers['user-agent'])>0 and p(["mozilla","firefox","ie"],request.headers['user-agent'][0]):
					CSRF_check(request,context)
		if ENABLE_SQLI: 
			#GET request,may not send request to php,asp,jsp,so we need to determine
			#POST request,it must be sent to a web server script
			if request.method=="GET" and chongfu(request,SQLI_GET_HAVE_CHECKED_URLS) and php_file_include(request.get_path_components()):
				#print request.headers
				#print type(request.headers)
				#add this url to SQLI_GET_HAVE_HECEKD_URLS
				names=request.get_query().keys()
				names.sort()
				#SQLI_GET_HAVE_CHECKED_URLS.append(request.url.split("?")[0]+str(names))
				#print SQLI_GET_HAVE_CHECKED_URLS
				#send to celery
				cookie=""
				referer=""
				if len(request.headers['cookie'])>0:
					cookie=request.headers['cookie'][0]
				if len(request.headers['referer'])>0:
					referer=request.headers['referer'][0]
				args = {'args': [request.url,cookie,referer,"mitm-test-for-get"]}
				resp = requests.post("http://localhost:5555/api/task/async-apply/tasks.sqlmap_dispath", data=json.dumps(args))
				#resp = tasks.sqlmap_dispath.delay(request.url,cookie,referer,"mitm-test-for-get")
				print "push ",resp
			if request.method=="POST" and chongfu(request,SQLI_POST_HAVE_CHECKED_URLS):
				#add this to SQLI_POST_HAVE_CHECKED_URLS
				names=request.get_query().keys()
				names.sort()
				SQLI_POST_HAVE_CHECKED_URLS.append(request.url.split("?")[0]+str(names))
				cookie=""
				referer=""
				if len(request.headers['cookie'])>0:
					cookie=request.headers['cookie'][0]
				if len(request.headers['referer'])>0:
					referer=request.headers['referer'][0]
				data=request.content
				args = {'args': [request.url,cookie,referer,data]}
				resp = requests.post("http://localhost:5555/api/task/async-apply/tasks.sqlmap_dispath", data=json.dumps(args))
				#resp = tasks.sqlmap_dispath.delay(request.url,cookie,referer,data)
				print "push ",resp
			
def response(context,flow):
	response=flow.response
	request=flow.request
	#use request.url,not request.host
        #because http://anysice.google.com/xxx.php?url=http://test.com/aa
	if url_exclude(request.host)==0 and url_include(request.host)==0:
		#print request.host,request.url
		if ENABLE_CSRF:
			if "xcxsxrxf=1" in flow.request.url:
				response.decode()
				d_print(flow.request.url)
				#CSRF response keywords.
				if p(["success","fail","data","msg"],response.content):
					output(CSRF_FOUND_URLS,flow.request,"CSRF response",context)
		if ENABLE_XXE:
			if "content-type" in request.headers.keys():
				if len(request.headers["content-type"])>1:
					print "two content-type founds"
				if p(["xml"],request.headers["content-type"][0]):
					output(XXE_FOUND_URLS,request,"XXE",context)
					print "XXE RESPONSE"
					print request.headers
					print response.content
		if ENABLE_JSONP:
			if "callback" in request.url:
					output(JSONP_FOUND_URLS,request,"JSONP",context)

