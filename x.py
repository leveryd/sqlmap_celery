import requests,json
r=requests.get("http://127.0.0.1:9999/task/new")
taskid=r.json()["taskid"]
rr=requests.post("http://127.0.0.1:9999/scan/"+taskid+"/start",data=json.dumps({'url':"http://127.0.0.1/sql.php?sql=root"}),headers={'content-type':'application/json'})
print rr.json()
