打wasm包
tinygo build -o ./local/main.wasm -scheduler=none -target=wasi ./main.go

拷贝
cp local/main.wasm /opt/lzp/project/app-sec-wasm/image/build/cc_deny.wasm
cd /opt/lzp/project/app-sec-wasm/image/build/
