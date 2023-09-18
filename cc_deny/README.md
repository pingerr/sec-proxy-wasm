打wasm包
tinygo build -o ./local/main.wasm -scheduler=none -target=wasi ./main.go

打wasm包(nottinygc)
tinygo build -o ./local/main.wasm -scheduler=none -gc=custom -tags='custommalloc nottinygc_finalizer' -target=wasi ./main.go