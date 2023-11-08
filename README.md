## 2023云原生编程挑战赛赛道2-面向应用安全防护领域设计Wasm插件 4th 方案

竞赛官网：https://tianchi.aliyun.com/competition/entrance/532104

参赛团队：CETC CST

### 赛题简介

基于 Alibaba 开源的下一代云原生网关 [Higress](https://github.com/alibaba/higress?spm=a2c22.12281978.0.0.42376745sRKLLz) 实现 3 个 WebAssembly 插件：

1. **IP 黑名单**：插件要求配置海量 IP 黑名单的 CIDR，并通过 x-real-ip 请求头判断是否命中规则.
```
{
  "ip_blacklist": [
    "1.1.1.1",
    "10.2.0.0/16"
    ......
  ] 
}
```

2. **CC 防护**：针对大流量高频 CC 攻击，通过限制请求频率进行防护.

```
{
  "cc_rules": [
	  {
      // 从特定 header 识别调用方
      "header": "user-agent",
      // 每个调用方每秒最多 10 次
      "qps": 10,
      // 每个调用方每分钟最多 100 次
      "qpm": 100,
      // 每个调用方每天最多 1000 次
      "qpd": 1000,
      // 超过限制后将该调用方屏蔽 300 秒，不可访问
      "block_seconds": 300 
    },
    {
      // 从特定 cookie 识别每个调用方
      "cookie": "uid",
      "qpm": 100,
      // 只屏蔽超出部分的请求，下个统计周期即可恢复访问
    }
  ] 
}
```

3. **WAF 规则防护**: 要求防护常见的 OWASP Top 10（涵盖 SQL 注入，XSS 攻击，SHELL 注入等）。

评分标准：**功能** + **性能**

![Alt text](asset\image.png)



### 解题思路

##### IP 黑名单

##### CC 防护

##### WAF 规则防护

### 参赛感想


