##### 本地测试目录

启动  
`docker compose up`

后台启动    
`docker compose up -d`

停止  
`docker compose stop`

test case   
`curl http://127.0.0.1:10000/get -H 'x-real-ip: 1.1.1.1'`
