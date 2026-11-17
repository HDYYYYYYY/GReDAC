# 方法与代码的对应关系

本文档帮助读者找到当前 GReDAC 的执行路径。系统名称为 GReDAC，受限派生结构为 RDF；实现版本 0.5.3 与论文修订号分开。论文安全结论仍应依据论文及有明确模型范围的证明，不能由一次测试通过代替。

| 论文阶段 | 当前实际代码路径 | 边界 |
|---|---|---|
| I 授权设置 | `gredac.endpoint.SetupAuthority`、`initial_certificate`；`network_actor.Node.dispatch` 的初始配置/授权操作 | Authority 签发初始授权；冻结后运行时子委派不向 Authority 重新登记。测试 PKI/身份供应属于前置设施，不等于生产身份系统 |
| II 成员委派与额度转移 | `gredac.offline.authorize/transfer/receive_delegation`，`capabilities`、`crypto`；父/子 Node 通过 RPC 交付 | 父方本地持有状态选范围，派生 RDF 材料并签署描述；子方校验。材料交付不冒充接收端已持久确认转移 |
| III 联系建立与请求接纳 | `network_actor.Node.discover/reserve/submit`，`gredac.roles.ACTCallerContact/ACTServiceRole`，`endpoint.Endpoint.session_act/charge/deliver` | 固定接收端 G 提供当前服务信息；双方重新建联和 ACT 绑定；新请求认证、授权检查、持久核销后交给服务成员。服务发现不是授权 |
| IV 撤销与恢复 | `endpoint.Endpoint` 的撤销/返还处理，`network_client.Client.recovery/recontact`；父方持有状态和已验证回执 | 接收端持久提交撤销后阻止相关新准入，未确认用量不能作为可用额度。返还给合法祖先；服务方接替不自动重发调用方额度 |

真实多进程运行由 `experiments.network_client.Mesh` 启动，参与方入口为 `network_actor.process_main`。每个 Agent 在自身进程维护状态和历史；`gredac.rpc` 提供 TCP/TLS 通信，`gredac.storage` 保持 SQLite WAL/FULL。A/B 的共享 Authority 进程仍按合作隔离签发状态、密钥和持久记录。实验控制器配置负载并收集审计证据，不应被理解为能代替 Agent 读取对方私有状态决策。

`local_client`、`gredac_fixture` 和 `python -m gredac demo/self-test` 是局部功能夹具或历史确定性演示，部分使用 MemoryBIO/逻辑时钟。它们不能作为当前 TCP/TLS 性能证据。当前网络路径使用 `SetupAuthority` 与 `Endpoint`；`authority`、`guard` 中也保留被继承或被历史演示使用的基础代码。最新论文用 G 表示固定接收端；早期讨论或实验中的 B 是同一角色的旧符号。

密码学结构约束可以生成证明的动作—额度组合；重复核销防护、撤销生效和安全返还依赖接收端的可信状态与持久检查。代码和说明不把这些程序检查说成 RDF 单独保证。服务操作完成后响应丢失可留下未决业务结果，本原型不声称任意外部服务的 exactly-once 执行。

RQ3 正式入口保留模型真实决策及有上限的纠错，独立检查流程与协议证据。离线回归使用明确的测试模型/可行性夹具，真实运行不会读取测试答案；离线通过不等于真实 LLM 完成率得到重新验证。独立 A2A 扩展为受控 SDK 桥接，不声称完整公共 A2A 服务兼容性。
