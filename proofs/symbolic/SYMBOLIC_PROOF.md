> 开源副本范围说明：下文保留原 GReDAC 证明论述及历史证据说明。其中 inputs/paper/review、历史日志和生成型 SMT 文件指原完整归档，未全部随本最小副本分发。可重现步骤和本包实际内容以本目录 README.md 为准；不得把原记录理解为本轮重新证明的结果。

# GReDAC 的符号证明投影与证据

日期：2026-11-08。输入规格为本证明包 `../inputs/` 中冻结的 GReDAC 文稿。本目录没有改动方法论文、旧证明或状态证明。

本组模型证明**控制签名来源、双侧递归链的结构来源、ACT 与完整请求的绑定、动态泄漏后的条件真实性，以及 RDF 理想派生图中的知识因果**。它们是同一方法的保守投影；它们不把 `CryptoVerified` 当作授权、业务接纳或扣账成功，也不构成整套实际协议的单一端到端机械证明。P1 的计算归约和共同状态系统/P5 的接口组合仍是完整安全论证的必要部分。

## 1. 实际结果与重现

最终结果以 [`results/RESULTS.json`](results/RESULTS.json) 为准。模型、保存的证明树、自动生成日志、重放日志和解析后规范化模型均保留。

| 模型 | all-traces 安全性质 | exists-trace 可达性质 | 用途 |
|---|---:|---:|---|
| `control_authentication.spthy` | 4 | 1 | 保护密钥、普通 Agent 密钥、控制签名来源 |
| `bilateral_delegation.spthy` | 2 | 1 | 任意委派深度、双侧结构来源 |
| `credential_authentication.spthy` | 7 | 4 | 完整请求、ACT、身份与会话泄漏、同会话多请求 |
| `pcdf_knowledge.spthy` | 8 | 3 | 理想派生图的知识来源与 sibling 分离 |
| `request_binding.spthy` | 1 | 1 | 完整消息绑定的独立正对照 |
| `negative_payload_only.spthy` | **1 条预期 falsified** | 1 | 删除完整消息绑定后的反例 |

即 22 条安全性质验证、11 条可达性验证、1 条预期负对照被攻破，共 34 条结果。五个正模型共 32 条验证；负模型另有一个可达性验证和一个反例。可达性和负对照不计为安全定理。

工具为实际运行的 Tamarin 1.12.0 / Maude 3.5.1，位于 WSL Ubuntu：

- `tamarin-prover`，SHA256 `9d3fcbaa65aeea244cff5b8074338d129427161cc8b02e5aee72d30ee072acc9`。
- `maude`，SHA256 `3c025100f0f5b858279945b94e99c734a722ebd3cd6314bb586dda7c04d8e725`。
- Tamarin 自报 revision `82780bbaf3328a45f624ddb41e51bf75425f851c`，并标记 `with uncommited changes`；因此不能只用 release 名称代表二进制身份，以上哈希及 JSON 中完整版本输出是本次证据。

根审计补充：`../review/TOOLCHAIN_AUDIT.json` 已逐字节核对实际 Tamarin 与归档
1.12.0 发行资产内的文件一致，压缩包摘要与归档 GitHub release 元数据一致。
上述 Maude 路径是设置 `MAUDE_LIB` 后执行真实程序的 3 行 shell 包装；实际
Maude 二进制 SHA256 为 `9dd4044e693944aae97ad72086bc70275fa34bf635f9b377a5b2100bf3ed8655`，
同样与归档 3.5.1 发行资产内文件一致。此核对是工具来源/完整性证据，不是工具
实现的源码正确性审计；未把工具的版本字符串当作唯一标识。

在本目录内执行：

```bash
python3 replay.py
```

默认只逐步重放现有证明树，不使用 `--prove`。完整重新搜索并重放：

```bash
python3 replay.py --regenerate
```

独立审计可使用另一个输出子目录，避免并发覆盖：

```bash
GREDAC_SYMBOLIC_RESULTS=results-independent python3 replay.py
```

运行器限制每个 Tamarin 进程为 `+RTS -N2 -RTS`，启用 `--quit-on-warning`。每个当前源文件与其证明证书分别经 Tamarin 解析；比较全部函数/方程、规则、restriction、引理属性与公式。只消去已枚举的冗余 `Any` 类型标记、已展开成相同函数/方程的 `signing` 标记、注释和空白；不删除任何用户规则、restriction 或公式。运行前后检查源文件及证明证书哈希，发现并发修改会失败。然后不带 `--prove` 重放证书并检查每一项结果，负对照必须实际报告 `falsified`。

`attempts/` 保存早期搜索/建模诊断，不属于最终证明集合。最终证明没有使用 proof-depth bound、固定会话数、固定委派深度或搜索 oracle。

## 2. 控制签名：来源不等于资格

`control_authentication` 对任意完整消息字节提供签名查询与验证。用户/Authority 的签名密钥由 `ProtectedIssuer` 生成且不提供泄漏规则；普通 Agent 身份密钥可随时通过 `CompromiseAgent` 泄漏并永久被攻击者保留。验证规则只使用公钥。

四条安全公式分别是：

1. 保护密钥不会成为网络攻击者知识。
2. 普通 Agent 私钥成为攻击者知识之前，存在该身份的失陷事件。
3. 保护签名验证成功，必有同一 issuer、role、完整 message 的先前签发事件。
4. 普通 Agent 签名验证成功，必有同一 signer、完整 message 的先前签发，或该 signer 的先前失陷。

签名查询接受任意消息，因此这不是“签名者一定只批准合规委派”的假设。应用到用户批准、Authority 对象或 DC 时，必须把该对象的**完整规范编码**作为 message；其策略合法性、权限单调性、当前撤销状态仍由共同状态规则决定。失陷 service 签出 ACT 或失陷父节点签出新 DC，不是本证明意义下的伪造。

可达性引理明确展示：失陷签名者能够产生没有诚实签发事件的新有效签名。这防止把条件真实性误写成无条件真实性。

各协议签名对象须有无歧义、类型分离的规范编码。ACT 模型用 `'act'` 类型标记、请求用 `'request'` 类型标记表达这一编码条件；它们不是新增的业务权限字段。若同一身份密钥还用于签署其他种类消息，组合时必须维持该类型分离，否则不能直接搬用“ACT 来源一定是 IssueACT”这一公式。

## 3. 双侧递归结构：删除门槛的保守上界

`bilateral_delegation` 的 `Right(d,root,chi,G,side,holder,pk)` 表示本地可用且结构认证过的链前缀这一 **ghost**，不表示栈已经激活了 DC、转移了额度或接纳业务。它可先于 Sync 存在，因此不排除协议允许的离线递归委派。

为了分离与验证结构结论，模型删除了签名与策略门槛：任何现有结构父节点都可扩展任意 child、holder 和 policy。这样增加了执行，不会把“父节点必须诚实”偷放入假设。真实签名门槛通过上一模型的逐对象来源性质组合；策略、剩余深度、撤销、当前资格和栈登记通过共同状态系统组合。

机械证明的两条公式是：

- 任意深度的 `RightRegistered(d,root,chi,G,side,holder)` 都有更早、同一 `root/chi/G/side` 的根批准事件。
- 每条 `DelegationRegistered(child,parent,root,chi,G,side,holder)` 都有更早、同一 `parent/root/chi/G/side` 的父链结构注册事件。

第一条使用归纳，没有把委派深度限制为示例中的两级。第二条证明侧别和协作上下文沿父边保持，不是“两个独立的单侧身份验证”。`both_sides_recursive_delegation_exists` 另外找到同一协作内 caller 和 service 两侧各两级委派的有限见证；这一见证只用于非空真检查，不能代替全称定理。

不同 `chi` 可复用同一公开 endpoint `G`；模型没有强制每个协作使用全新的入口。

## 4. 请求投影：绑定同一个 M，允许独立 session 泄漏

完整消息按当前规范投影为：

```text
M = <request, rho, chi, sid, A, R, dA, dR, action, payload, vector>
ACT-body = <act, A, R, dA, dR, chi, sid, expiry>
```

`vector` 是完整、规范化的来源/位置/capability/ownership 引用向量，在此模型中作为任意透明项参与认证。入口 `G` **不额外加入 M 或 ACT 的签名字节**，仅作为由注册上下文继承的 ghost 参数。

模型把 ACT、信道、标签验证分别记为 `VerifiedACT`、`VerifiedChannel`、`VerifiedTag`，再由 `VerifyRequest` 在同一个 M 和匹配的 ACT 字段上合并。三个验证事实只表示不随时间改变的密码学命题；它们不缓存 Live、余额、ownership、expiry 合规或授权资格。真实一次原子检查可投影为这三个检查及其紧接着的汇合；允许更多排序/复用只增加了投影中的执行。

由 Tamarin 证明：

- ACT 验证成功，存在同一 service 的完全相同 ACT-body 签发，或该 service 身份密钥此前失陷。
- 完整请求通过信道检查，存在该 caller 对完全相同 M 的发送，或 caller 身份密钥此前失陷，或同一 `(A,R,chi,sid)` 的会话秘密此前暴露。
- 标签验证成功，存在同一 keyid/caller 对完全相同 M 的先前标签生成，或该 leaf-secret 已暴露。
- 汇合事件确实有 caller 与 service 两个侧别的对应注册接口。
- 汇合事件确实有对同一个完整 M 的信道检查和标签检查，以及对其中双方身份、授权、chi、sid 匹配的 ACT 检查。

信道是理想认证信道接口，不是 TLS 或密钥交换协议实现。`SessionExposed(A,R,chi,sid)` 可独立于身份密钥泄漏发生；可达性引理明确展示单独 session 泄漏即可伪造该信道来源。因此没有把“身份私钥没丢”当成“会话必然安全”。如果实际一个信道秘密被多个 ACT/session 共用，其泄漏须映射到每个受影响的 `(A,R,chi,sid)`，不能只标记其中一个。模型主动公开 M，不主张业务内容保密。

`RequestKeyRevealed` 是知识接口：直接分享 leaf-secret、祖先 cap 泄漏后推导、失陷节点后续接收的凭据，都应映射为相应 leaf 的这一 ghost 事件。它不只表示 caller 自己的身份密钥泄漏。P1 的 `Reach`/曝光闭包决定哪些实际 leaf 可以产生该事件；本模型不独立证明这些 leaf 的不可派生性。

普通 Agent 身份通过独立密钥生成建模。组合时，泄漏同一实际密钥所覆盖的所有身份都必须视为失陷；不能把已共享或已泄漏的同一身份密钥下另一别名称作“未失陷身份”。

三个请求类可达性见证分别体现：无身份、会话或 leaf 暴露时不同 caller/service 的请求可验证；caller 失陷后验证仍可能成立；同一 ACT/session 可验证两个不同 M 和两份不同 leaf-secret 接口。最后一项是**密码学接口可达性**，不是两次合法扣账的证明；单位可花、Req 向量正确和恰好一次扣账由状态模型负责。

### 与双侧图、RDF、状态的接口

`ImportRegisteredRight` 是已检查链的保守导入。与双侧图共享的是擦除 root 后的：

```text
(d, chi, G, side, holder, holderpk)
```

core 内部 `root=d` 只是未使用的占位符，不能据此声称它和任意深度图共享完整七元组。实际执行中的同一对象 ID、身份、侧别及上下文必须映射为同一个上述投影，不能事后挑选另一条执行补证据。对象 ID 唯一性、不可变注册及当前可用性是状态接口条件。

`RequestKey(keyid,A,z)` 对应实际选定 leaf 的业务认证秘密。对多来源请求，本模型的标签公式应对每个被选定来源实例化，然后在同一执行、同一规范 M 下合取。它没有机械展开任意长度 Req 列表，也不能代替状态模型关于 exact-Req、unit、ownership、capability 和原子扣账的公式。

## 5. RDF 知识因果与当前回收语义

`pcdf_knowledge` 是注册派生骨架上的理想随机表，不是 SHA-256 或 HMAC 实现模型。`Split`、`Grant`、`Spend` 创建不可预测的理想表项；`EdgeQuery` 要求先知道父 secret；`AuthQuery` 要求先知道相应 secret。攻击者可泄漏任意已有 Node 或 Spend-secret，保留所有知识并自适应查询。

`grant_label(gid)` 中的 gid 映射实际 `Grant(k,gamma)` 的不可变 capability ID `gamma`；模型没有往实际哈希输入中增加完整记录字段。ID 对完整能力记录的绑定由签名和不可变 registry 保证，不能归功于 Grant 哈希本身。模型允许任意 gid 值；范围、当前 ownership 与链依赖仍在其他证明中检查。`Grant` 保留几何前缀、`Split` 扩展前缀，只证明了这些构造事实。

主要公式为：

- Authority source master 保密。
- 任意已创建 seed 进入攻击者知识，要么被直接泄漏，要么由一次先知道父 seed 的派生查询得到。
- 任何派生查询确有更早的父 seed 知识。
- 标签可验证，要么有同消息的诚实签发，要么有使用已知 secret 的查询。
- 理想 seed 出生唯一；同父不同 capability ID 的理想输出不同。
- 新 grant 输出若被知晓，必有该输出直接暴露或父 secret 更早被知晓。

`UniqueEdge` 是本模型唯一非等式 restriction：同一 `(parent,label)` 的表项一致。它表达确定性函数的 memoization，不表达额度唯一使用、撤销或不可串谋的安全结论。模型只首次创建表项，重复求值通过 `EdgeQuery` 重用；不会每次重复 derive 都生成独立 key。

该投影只显式查询已经进入注册派生骨架的边；注册前对任意字符串的预查询、随机碰撞概率、猜中未知 secret、实际编码和随机预言机模拟的自适应性由 P1 的计算论证承担。这里不能把“fresh 输出必不同”当成实际散列零碰撞定理。

当前回收不调用 `Anchor` 重发一个全新 anchor。`Anchor` 在此仅表示初始发行。新的 sibling 见证保留同一 parent：先泄漏 old child，再用新的 capability ID 建立 new child；`leaked_parent_can_derive_child` 同时展示父秘密泄漏后子秘密可被推导。因而新 sibling 的秘密性必须以其父 secret 不在联盟知识闭包内为条件，不能承诺“回收天然清除旧祖先的密码学知识”。

`ell_ret`、恢复同一 parent capability、同一永久 unit、旧 ownership 失效和防重花不在这张知识图中。它们由共同状态证明保证；旧 child 持有者的旧 key 不因该状态更新而被“删除”。

## 6. 负对照与排除的误读

`request_binding` 与 `negative_payload_only` 使用相同的消息元组、Issue/Accept 规则和同一个“接受必有完全相同消息签发”的公式。唯一关键差别是后者把认证输入从完整 M 改为 payload。

Tamarin 对正确版本给出全称证明；对 payload-only 版本找到反例：攻击者拿到一个合法 payload-tag 后，改变消息中的其他字段并复用标签，接收者仍通过验证，而不存在变更后完整消息的签发。证明树保存该反例。它是认证层的必要性探针，不被宣传为已经攻破了包含其他状态检查的整个突变系统。

本目录不证明：额度守恒/可花性、Req 列表完整性、每个单位仅消费一次、相同 rho 的精确重试、不同 M 的 rho 冲突拒绝、当前撤销/expiry、ownership 回收、替代见证存在、崩溃一致性、真实时钟界、协议握手安全、业务保密或实现二进制正确性。前三组场景的完整结论必须组合 P0–P5 的相应前提与结果，不能仅引用这里的“tag 不可伪造”或“root provenance”。

## 7. 可用于论文的准确表述

> We mechanically verify unbounded symbolic projections for control-message provenance, bilateral delegation ancestry, complete-request and ACT binding, and knowledge causality in an ideal RDF derivation graph. Identity, session, and capability-secret exposure are modeled explicitly; authenticity claims are conditional on the relevant exposure history. Reachability checks include recursive delegation on both sides and multiple requests in one session, and a payload-only authentication mutation yields a counterexample. These symbolic results are composed with the computational RDF argument and the common state invariants through explicit interfaces; they are not a single end-to-end mechanized proof of the implementation.

具体引用时还应同时指向共同执行模型、P1 计算边界及 P5 的接口匹配证明，避免把多个局部工具结果的数目当成整体安全结论。
