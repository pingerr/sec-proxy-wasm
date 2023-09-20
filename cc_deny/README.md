### cc deny

##### 目录说明
* ratelimit 
  * cc deny 实现
* local
  * 本地测试目录

##### 编译
tinygo version = 0.25   

`tinygo build -o ./local/main.wasm -scheduler=none -target=wasi ./main.go`

编译到 local/main.wasm
