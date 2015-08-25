#!/usr/bin/env python
# encoding: utf-8
# tasks.py
# email: ringzero@0x557.org

'''
	Thorns Project 分布式任务控制脚本
	tasks
		-- nmap_dispath			# nmap 扫描调度函数
		-- hydra_dispath 		# hydra 暴力破解调度函数
		-- medusa_dispath 		# medusa 暴力破解调度函数

	worker run()
		--workdir=/home/thorns
'''

import subprocess
from celery import Celery, platforms 
from time import sleep
import requests,json
import MySQLdb

# 初始化芹菜对象
app = Celery()

# 允许celery以root权限启动
platforms.C_FORCE_ROOT = True

# 修改celery的全局配置
app.conf.update(
	CELERY_IMPORTS = ("tasks", ),
	BROKER_URL = 'redis://203.195.211.242:6379/0',
	CELERY_RESULT_BACKEND = 'db+mysql://thornstest:thornstest@203.195.211.242:3306/thorns',
	CELERY_TASK_SERIALIZER='json',
	CELERY_RESULT_SERIALIZER='json',
	CELERY_TIMEZONE='Asia/Shanghai',
	CELERY_ENABLE_UTC=True,
	CELERY_REDIS_MAX_CONNECTIONS=5000, # Redis 最大连接数
	BROKER_TRANSPORT_OPTIONS = {'visibility_timeout': 3600}, # 如果任务没有在 可见性超时 内确认接收，任务会被重新委派给另一个Worker并执行  默认1 hour.
	# BROKER_TRANSPORT_OPTIONS = {'fanout_prefix': True},		# 设置一个传输选项来给消息加上前缀
)
SQLMAPAPI_URL="http://127.0.0.1:9999"
TASK_NEW_URL=SQLMAPAPI_URL+"/task/new"
class Database:
    host = '203.195.211.242'
    user = 'sqlmap'
    password = 'sqlmapx123'
    db = 'sqlmap'
    charset = 'utf8'

    def __init__(self):
        self.connection = MySQLdb.connect(self.host, self.user, self.password, self.db,charset=self.charset)
        self.cursor = self.connection.cursor()

    def insert(self, query):
        try:
            self.cursor.execute(query)
            self.connection.commit()
        except:
            self.connection.rollback()

    def query(self, query):
        cursor = self.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(query)
        return cursor.fetchall()

    def __del__(self):
        self.connection.close()

@app.task
def sqlmap_dispath(url,cookie,referer,data):
	task_new=requests.get(TASK_NEW_URL)
	task_id=task_new.json()["taskid"]
	if data!="mitm-for-test":
		requests.post(SQLMAPAPI_URL+"/scan/"+task_id+"/start",data=json.dumps({'url':url,"cookie":cookie,"referer":referer,"data":data}),headers={"content-type":"application/json"})
	else:
		requests.post(SQLMAPAPI_URL+"/scan/"+task_id+"/start",data=json.dumps({'url':url,"cookie":cookie,"referer":referer}),headers={"content-type":"application/json"})
	task_status=requests.get(SQLMAPAPI_URL+"/scan/"+task_id+"/status")
	count=1
	while(task_status.json()["status"]!="terminated"):
		task_status=requests.get(SQLMAPAPI_URL+"/scan/"+task_id+"/status")
		sleep(count)
		count=count*2
	task_result=requests.get(SQLMAPAPI_URL+"/scan/"+task_id+"/data")
	if task_result.json()['data']!="":
		mysql=Database()
		mysql.insert("insert into sqlmap_result(taskid,result,url,cookie,referer,data) values('%s','%s','%s','%s','%s','%s')"%("NULL",task_result.json()['data'],url,cookie,referer,data))
		return task_result.json()['data']
	else:
		return "nothing"

# 失败任务重启休眠时间300秒，最大重试次数5次
# @app.task(bind=True, default_retry_delay=300, max_retries=5)

@app.task
def nmap_dispath(targets, taskid=None):
	# nmap环境参数配置
	run_script_path = '/home/thorns'
	if taskid == None:
		cmdline = 'python wyportmap.py %s' % targets
	else: 
		cmdline = 'python wyportmap.py %s %s' % (targets, taskid)
	nmap_proc = subprocess.Popen(cmdline,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	process_output = nmap_proc.stdout.readlines()
	return process_output

@app.task
def hydra_dispath(targets, protocol, userdic, passdic, taskid=None):
	# 命令执行环境参数配置
	run_script_path = '/home/thorns/script/hydra'
	run_env = '{"LD_LIBRARY_PATH": "/home/thorns/libs/"}'

	if taskid == None:
		cmdline = 'python hydra.py %s %s %s %s' % (target, protocol, userdic, passdic)
	else:
		cmdline = 'python hydra.py %s %s %s %s %s' % (target, protocol, userdic, passdic, taskid)

	nmap_proc = subprocess.Popen(cmdline,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=run_script_path,env=run_env)

	process_output = nmap_proc.stdout.readlines()
	return process_output

@app.task
def medusa_dispath(targets, protocol, userdic, passdic, taskid=None):
	# 命令执行环境参数配置
	run_script_path = '/home/thorns/script/medusa'
	run_env = '{"LD_LIBRARY_PATH": "/home/thorns/libs/"}'

	if taskid == None:
		cmdline = 'python medusa.py %s %s %s %s' % (target, protocol, userdic, passdic)
	else:
		cmdline = 'python medusa.py %s %s %s %s %s' % (target, protocol, userdic, passdic, taskid)

	nmap_proc = subprocess.Popen(cmdline,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=run_script_path,env=run_env)

	process_output = nmap_proc.stdout.readlines()
	return process_output
@app.task
def subbrute_dispath(targets, taskid=None):
	# 命令执行环境参数配置
	import os
	run_script_path = '/home/ubuntu/thorns/subbrute/'
	run_env = '{"LD_LIBRARY_PATH": "/home/ubuntu/thorns/libs/"}'

	if taskid == None:
		cmdline = 'python  /home/ubuntu/thorns/subbrute/subbrute.py %s' % (targets)
	else:
		cmdline = 'python  /home/ubuntu/thorns/subbrute/subbrute.py %s %s' % (targets,taskid)

	nmap_proc = subprocess.Popen(cmdline,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

	process_output = nmap_proc.stdout.readlines()
	return process_output

