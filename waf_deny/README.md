### waf deny

#### 目录说明
* wasmplugin 
  * waf 插件
* pingerPlugins
  * 自定义的功能（operator 或 transformation）
* local
  * 本地测试目录

#### 编译
tinygo version = 0.27

`go run mage.go build`

编译到 local/main.wasm

#### 解题思路概述
* 只启用误报率低的规则
* 针对 gotestwaf 使用的 encoder，在规则中增加或实现对应的 decoder
* 针对 gotestwaf 使用的 placeholder，在规则中增加对应参数的检测

具体配置和实现见 local/envoy.yaml, 所有PINGER-8*.conf的规则为自定义规则

