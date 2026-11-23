授权码拦截重放的问题还没解决，改成 PKCE 之后客户端仍然能跳过校验：第一个缺陷是 verifier 只用时间戳派生，可预测；第二个缺陷是 verifier 长度不校验，短到八位也能通过；第三个缺陷是 challenge 只用明文方法计算，安全方法退化成明文；第四个缺陷是方法参数被忽略，永远按明文计算；第五个缺陷是校验挑战时不比较方法，跨方法也能通过；第六个缺陷是完成授权不校验状态参数，跨会话注入；第七个缺陷是状态参数不做过期，旧状态可长期使用；第八个缺陷是一次性校验缺失，同一 verifier 可重复换取令牌；第九个缺陷是策略校验不检查是否允许明文方法；第十个缺陷是批量处理复用待处理状态，后一个流程命中前一个流程的 verifier。pkce/flow.py 是核心，tests/test_flow.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式：在仓库根执行 pytest tests -q，预期恰好 15 failed 且没有 error。flow.py 恰好 8 个桩，全部 raise NotImplementedError，docstring 写清 verifier 长度、challenge 方法、比较容差 0。

字段表：方向 安全；类型 漏洞检测与攻防；任务 Bugfix；语言与测试 Python 3, pytest；外部依赖 无外部依赖。

tests 目录不可修改，测试就是验收标准。本仓库采用 src 布局：包源码在 src/pkce，测试在 tests，conftest.py 把仓库根的 src 插入 sys.path。
## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

