sudo /etc/init.d/tomcat7 stop
cd ~/sqlmap
python ~/sqlmap/sqlmapapi.py -s -p 9999&
cd ~/celery
celery worker -A tasks -E --autoscale 10,3& 
celery flower -A tasks&
mitmdump -s csrf.py&
