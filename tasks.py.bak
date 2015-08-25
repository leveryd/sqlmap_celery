from celery import Celery
from time import sleep
import requests,json
app = Celery()

app.conf.update(
        CELERY_IMPORTS = ("tasks", ),
        BROKER_URL = 'redis://203.195.211.242:6379/0',
        CELERY_RESULT_BACKEND = 'db+mysql://thornstest:thornstest@203.195.211.242:3306/thorns',
        CELERY_TASK_SERIALIZER='json',
        CELERY_RESULT_SERIALIZER='json',
        CELERY_TIMEZONE='Asia/Shanghai',
        CELERY_ENABLE_UTC=True,
        CELERY_REDIS_MAX_CONNECTIONS=5000,
)

celery = Celery('tasks', broker='redis://localhost:6379/0')
SQLMAPAPI_URL="http://127.0.0.1:9999"
TASK_NEW_URL=SQLMAPAPI_URL+"/task/new"
@celery.task
def sqlmap_dispath(url,cookie,referer,data):
	task_new=requests.get(TASK_NEW_URL)
	task_id=task_new.json()["taskid"]
	if data=="mitm-test-for-get":
		requests.post(SQLMAPAPI_URL+"/scan/"+task_id+"/start",data=json.dumps({'url':url,'cookie':cookie,"referer":referer}),headers={"content-type":"application/json"})
	else:
		requests.post(SQLMAPAPI_URL+"/scan/"+task_id+"/start",data=json.dumps({'url':url,'cookie':cookie,"referer":referer,"data":data}),headers={"content-type":"application/json"})
	task_status=requests.get(SQLMAPAPI_URL+"/scan/"+task_id+"/status")
	count=1
	while(task_status.json()["status"]!="terminated"):
		task_status=requests.get(SQLMAPAPI_URL+"/scan/"+task_id+"/status")
		sleep(count)
		count=count*2
	task_result=requests.get(SQLMAPAPI_URL+"/scan/"+task_id+"/data")
	print task_result
	return task_result.json()
