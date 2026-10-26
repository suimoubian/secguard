# SecGuard vs OWASP CRS:对比环境

这里放的是"和工业基线比"的工具。产物是
[../../docs/评测数据/CRS对比.md](../../docs/评测数据/CRS对比.md)。

## 为什么要有这个对比

自建评测集最大的软肋是**尺子自己造的、自己用的**。再漂亮的 6.1% 在没有
外部基线时都只是一个自说自话的数字。OWASP CRS 是工业默认答案(nginx/Apache
前面装 WAF,九成装的是它),拿它当基线,才知道自己站在哪。

## 环境怎么搭

```bash
# 1) 拉官方镜像(带 nginx 连接器 + CRS v4)
docker pull owasp/modsecurity-crs:nginx-alpine

# 2) 一个专用网络 + 一个静态后端(只需要能返回 200/404,不参与判定)
docker network create crs-test
docker run -d --name crs-backend --network crs-test nginx:1.27-alpine

# 3) 起 CRS,只监听本机 8089(不要暴露到公网)
docker run -d --name crs --network crs-test \
    -p 127.0.0.1:8089:8080 \
    -e BACKEND=http://crs-backend:80 \
    -e SERVER_NAME=example.com \
    -e MODSEC_RULE_ENGINE=on \
    owasp/modsecurity-crs:nginx-alpine

# 4) 冒烟测试:编码空格应该被拦(403)
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8089/?id=1%20or%201=1--'
```

本仓库跑过的一版:**OWASP CRS 4.30.0 + ModSecurity 3.0.17 + nginx**,
默认配置(PL1、入站异常阈值 5),**没有调参**。

## 怎么跑对比

```bash
# 先保证 build-eval/waf_eval 已经编好
cmake --build build-eval --target waf_eval

python3 tools/crs_compare/compare.py \
    --crs-url http://127.0.0.1:8089 \
    --out docs/评测数据/CRS对比.md
```

## 方法上容易做错的三件事(都踩过)

1. **必须喂同一份线上报文。** 语料里的载荷是"语义载荷",空格是裸的;真实
   HTTP 里空格要编码成 `%20`,否则 nginx 直接 400 —— 那测出来的是"请求非法",
   不是"检测能力"。脚本会把 query/path 类的空格和 `#` 编码后再发。
2. **path 类样本不可比。** nginx 在 ModSecurity 之前就会把 `..` 归一化或
   直接拒绝(`curl --path-as-is .../../../etc/passwd` 返回 400),CRS 根本没
   看到那条路径。所以脚本把 22 条 path 样本排除在统计之外 —— 把 400 算成
   CRS 漏报是不成立的。
3. **中文 body 要 UTF-8。** `http.client` 对 str 类型的 body 用 latin-1 编码,
   中文会直接抛异常(4 条样本因此丢失过)。

## 清理

```bash
docker rm -f crs crs-backend && docker network rm crs-test
```
