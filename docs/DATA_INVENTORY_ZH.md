# 开源副本中实际包含的数据

当前副本**不是完全不带数据的纯代码包**。本清单区分实验输入、从实验提取的数值样本和完整原始结果；名称整理没有删除或改写数据。

| 内容 | 文件/位置 | 来源和用途 |
|---|---|---|
| 自建任务输入 | `experiments/data/rq3_20261108_instances.json` | 三场景各 25 个正式实例、3 个开发实例，共 84 个任务输入；包含业务事实和约束，不是模型作答日志 |
| 自建分配需求与顺序 | `experiments/allocation_policy_v2/formal_instances.json`、`development_instances.json` | 预先生成的实例、随机种子及三策略运行计划；不是性能测量结果 |
| 离线测试专用可行性夹具 | `docs/rq3-retest/FEASIBILITY_TEST_ONLY.json` | 既有实例可行性检查及测试方案，仅由 RQ3 离线回归读取；正式模型运行不会读取或据此补答案 |
| **我们实验产生的时长数据** | `experiments/data/rq4_rq3_wait_v2.json` | 从已有 RQ3 日志提取的 3,686 条 API 时长和 1,555 条业务间隔记录；含实例标识、状态/模型标识、部分时间边界与来源哈希；供 RQ4 冻结采样使用。不能称为“没有我们的实验数据” |
| **已有证明检查输出** | `proofs/state/RESULTS.json`、`WITNESSES.json` | 317 项状态证明检查记录及 11 个 witness/反例检查记录，部分包含 solver 用时；不是新一轮验证 |
| 公开外部 RTT 数据及质量检查 | `studies/rq2_rtt/data/samples.json`、`QUALITY.json` | RIPE Atlas 公开测量的冻结样本及我们整理的质量检查元数据，非本系统跨地域实测 |
| 第三方示例输入 | `experiments/rq2_v2/author_source.zip` 内 `experiments/data/` | SAGA 官方归档中的合成日历、邮件、文档数据 |
| 证明证书和参考测试夹具 | `proofs/symbolic/*.proof.spthy` 及测试源文件 | 用于复核证明和确定性测试，不是业务运行日志 |

**没有放入**：完整 RQ2–RQ4性能结果目录、逐次完整请求/响应轨迹、LLM 对话内容、token明细、完整运行数据库、运行生成的私钥/证书、服务器监控原始日志和结果备份压缩包。源码与包装校验清单仍包含必要的版本/哈希信息。

若之后决定公开纯代码而不公开上述实测时长，需要同时调整 RQ4 的输入供应方式并明确其复现限制；不能直接删掉文件后仍宣称当前冻结采样实验可以原样运行。本轮只盘点数据，没有执行这种删改。
