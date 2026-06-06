# AST 遮蔽升级状态说明

这份文档用于说明当前 `ast-mask-tree-sitter-upgrade` 分支中，AST 遮蔽与迁移流水线升级已经完成了哪些内容，还需要测试什么，以及下一步计划如何继续升级。

## 升级目标

我们这次的整体目标是把当前偏轻量的实现：

```text
regex / brace matching / role-aware rules
```

逐步升级为：

```text
真实 AST backend + family-aware selection + dependency-aware mask units
```

同时继续保持现有输出兼容：

```text
ast_mask_report.yaml
selected_mask_units.yaml
```

当前策略是：

- `lite` backend 仍然作为默认兼容路径；
- `tree-sitter` backend 作为可选 backend 并行生成；
- 下游工具可以显式选择读取 lite 或 tree-sitter 的 selected mask units；
- 暂时不强行替换默认 lite 输出，避免破坏已有流水线。

## 当前分支与提交

```text
branch: ast-mask-tree-sitter-upgrade
commit: 4d9258468d3ec357893b894372568485c565ef78
```

## 主要改动

### 1. AST 遮蔽 backend

相关文件：

```text
template_maker/ast_mask.py
template_maker/ast_mask_lite.py
template_maker/ast_mask_tree_sitter.py
template_maker/ast_mask_select.py
config/harness_family_ast_rules.yaml
docs/ast_mask_backend.md
```

已经实现：

- 新增统一 AST mask CLI：

```bash
python3 -m template_maker.ast_mask --root <template_root> --backend lite
python3 -m template_maker.ast_mask --root <template_root> --backend tree-sitter
```

- 新增可选的 `tree-sitter` C AST backend。
- 保留 `lite` backend 作为默认兼容 backend。
- 新增 family-aware AST selection 配置：

```text
config/harness_family_ast_rules.yaml
```

- `ast_mask_select.py` 支持读取不同 AST report，并输出不同 selected-unit 文件：

```bash
python3 -m template_maker.ast_mask_select \
  --root <template_root> \
  --ast-report-name ast_mask_report.tree_sitter.yaml \
  --output-name selected_mask_units.tree_sitter.yaml
```

新增或增强的 mask unit 字段包括：

```text
node_type
line_start
line_end
column_start
column_end
enclosing_function
called_function
identifiers_read
identifiers_written
placeholder_dependencies
control_context
```

这些字段的目的，是让后续 `adapter_filler.py`、validator 和 renderer 更容易知道：

```text
trigger call 依赖哪些变量
oracle 观察哪些变量
cleanup 释放哪些对象
mutation placeholder 影响哪些语句
```

### 2. family-aware AST selection

现在 AST selection 不再只依赖一组全局硬编码关键词，而是可以根据 `harness_family` 读取配置。

相关配置文件：

```text
config/harness_family_ast_rules.yaml
```

目前覆盖或支持的 family 包括：

```text
der_pointer_consumption
null_deref_dispatch
return_code_outlen_semantic
x509_asn1_inner_boundary
buffer_canary_boundary
object_state_lifecycle
crash_sanitizer_oracle
invalid_parameter_setup_oracle
```

例如 `MBEDTLS-POC-0020` 使用的是：

```text
harness_family: der_pointer_consumption
oracle_type: pointer_consumption_semantic_oracle
```

因此它更需要 DER 语义相关关键词，例如：

```text
DER
ASN1
SEQUENCE
trailing
der_len
consumed_len
p
end
len
parse_key
d2i
```

这比继续使用偏 bignum/canary 的上下文规则更贴合 `0020` 的场景。

### 3. migration 工具链

相关文件：

```text
migration/candidate_mapper.py
migration/evidence_collector.py
migration/adapter_filler.py
migration/adapter_validate.py
```

已经实现：

- `candidate_mapper.py`、`evidence_collector.py`、`adapter_filler.py` 支持显式传入 selected mask units：

```bash
--selected-mask-units selected_mask_units.tree_sitter.yaml
```

- 这样下游可以选择读取：

```text
selected_mask_units.yaml
selected_mask_units.tree_sitter.yaml
```

- `adapter_filler.py` 会把实际读取的 selected-unit 文件记录到 `adapter_meta.yaml` 和 adapter 的 `ast_mask_selection` 信息中。
- `evidence_collector.py` 增强了 fallback evidence 逻辑，用于 RAG evidence 较弱但候选 API 仍然可评估的场景。
- `adapter_validate.py` 增强了 recipe-driven adapter 的语义校验。

### 4. recipe-driven cross generation

相关文件：

```text
template_maker/cross_generator_from_adapters.py
adapter_recipes/openssl/EVP_DigestVerify.null_deref_dispatch.yaml
adapter_recipes/openssl/d2i_PrivateKey.der_pointer_consumption.yaml
```

已经实现：

- 新增 OpenSSL recipe：

```text
EVP_DigestVerify / null_deref_dispatch
```

- 新增 OpenSSL recipe：

```text
d2i_PrivateKey / der_pointer_consumption
```

其中 `d2i_PrivateKey` recipe 用于支撑 `MBEDTLS-POC-0020` 的 DER trailing garbage 迁移。

`d2i_PrivateKey` 的核心 oracle 是：

```text
ret == 0 and consumed_len < der_len
  => target 成功解析了前缀 DER，但没有消费 trailing garbage
  => migrated bug candidate

ret == 0 and consumed_len == der_len
  => target 成功解析并完整消费输入
  => safe full consumption

ret != 0
  => target 拒绝 malformed/trailing-garbage input
  => safe rejection
```

### 5. render / runner / analysis

相关文件：

```text
template_maker/render_cases.py
runner/compile_run.py
runner/analyze_results.py
runner/analyze_cross_results.py
```

已经实现：

- `render_cases.py` 改进了 placeholder 检查，避免把一些 oracle 日志标签误判为未渲染 placeholder。
- `compile_run.py` 增强了 dry-run 支持和元数据传播。
- `analyze_results.py` 增强了单 case verdict 分类。
- `analyze_cross_results.py` 增强了跨库 pair verdict 分类。
- 这些改动是为了让新的 family / oracle / recipe 路径能被 dry-run 和真实 compile/run 统一分析。

### 6. dry-run smoke 脚本

新增文件：

```text
scripts/run_pk_null_deref_dry_pipeline.sh
```

用途：

- 对 `pk_verify_ext_null_deref` 跑一条不依赖 clean sources 的 dry-run 流水线；
- 覆盖 candidate mapping、evidence collection、adapter filling、adapter validation、cross template generation、render cases、placeholder check、dry-run compile result、single-case analysis、cross analysis；
- 方便在没有本地 OpenSSL / mbedTLS clean source 的机器上做基础回归检查。

示例命令：

```bash
SELECTED_MASK_UNITS=normalized_templates/pk/pk_verify_ext_null_deref/selected_mask_units.tree_sitter.yaml \
SMOKE_ROOT=/tmp/cipherlens_precommit_pk_tree_smoke \
MAX_CASES=2 \
scripts/run_pk_null_deref_dry_pipeline.sh
```

已经观察到的 dry-run 结果：

```text
total_cases: 4
raw_status_counts: dry_run=4
verdict_counts: not_executed=4
total_pairs: 2
migration_verdict_counts: migration_not_executed=2
placeholder issues: 0
```

## 生成或更新的 template artifacts

本次提交中包含了一些 normalized template 产物更新：

```text
normalized_templates/rsa/rsa_der_trailing_garbage/
  ast_mask_report.yaml
  selected_mask_units.yaml
  ast_mask_report.tree_sitter.yaml
  selected_mask_units.tree_sitter.yaml

normalized_templates/pk/pk_verify_ext_null_deref/
  ast_mask_report.yaml
  selected_mask_units.yaml
  ast_mask_report.tree_sitter.yaml
  selected_mask_units.tree_sitter.yaml

normalized_templates/bignum/mpi_sub_abs/
normalized_templates/bignum/mpi_write_string/
```

当前解释：

- `ast_mask_report.yaml` 和 `selected_mask_units.yaml` 仍然是默认兼容产物；
- `ast_mask_report.tree_sitter.yaml` 和 `selected_mask_units.tree_sitter.yaml` 是并行对照产物；
- tree-sitter backend 在 `0020` 和 `pk_verify_ext_null_deref` 上能选出更精准的 trigger call；
- 当前还没有把 tree-sitter 设为默认 backend。

## 已经本地验证的内容

提交前已做过 Python 编译检查：

```bash
python3 -m py_compile \
  template_maker/ast_mask.py \
  template_maker/ast_mask_tree_sitter.py \
  template_maker/ast_mask_lite.py \
  template_maker/ast_mask_select.py \
  template_maker/mask_report.py \
  template_maker/validate_template.py \
  template_maker/render_cases.py \
  template_maker/cross_generator_from_adapters.py \
  migration/candidate_mapper.py \
  migration/evidence_collector.py \
  migration/adapter_filler.py \
  migration/adapter_validate.py \
  runner/compile_run.py \
  runner/analyze_results.py \
  runner/analyze_cross_results.py
```

还检查过：

```text
diff 中没有发现明显 API key。
config / runner / template_maker / migration / scripts / docs 中没有发现硬编码 /home/wen/work/clean_sources。
```

已经做过 dry-run smoke：

```text
pk_verify_ext_null_deref -> OpenSSL EVP_DigestVerify
```

`MBEDTLS-POC-0020 -> OpenSSL d2i_PrivateKey` recipe 路径也做过 render 和 dry-run 检查：

```text
adapter generated
adapter validated
cross template generated
cases rendered
placeholder check passed
compile_run dry-run passed
analyze_results / analyze_cross_results produced not_executed dry-run verdicts
```

## 还需要真实测试的内容

真实 compile/run 需要本地准备：

```text
clean_sources/
  mbedtls-4.1.0/
  openssl-3.5.5/
```

推荐让有 clean sources 的队友优先测试以下内容。

### 1. MBEDTLS-POC-0020 DER pointer consumption

测试对象：

```text
normalized_templates/rsa/rsa_der_trailing_garbage
target APIs:
  OpenSSL d2i_PrivateKey
  OpenSSL d2i_RSAPrivateKey
  OpenSSL d2i_RSA_PUBKEY
```

重点确认：

- rendered C 文件没有未解析 placeholder；
- mbedTLS source cases 能编译运行；
- OpenSSL target cases 能编译运行；
- `consumed_len` 和 `der_len` 被正确记录；
- cross analysis 能区分：

```text
migrated_bug_candidate
migrated_safe
migration_needs_triage
```

### 2. pk_verify_ext_null_deref

测试对象：

```text
normalized_templates/pk/pk_verify_ext_null_deref
target API:
  OpenSSL EVP_DigestVerify
```

重点确认：

- generated harness 能编译；
- incompatible key dispatch path 能被触发；
- safe rejection 不应被误判成 crash；
- 只有存在 ASAN / UBSAN / SEGV 等明确证据时才报告 crash verdict。

### 3. lite 和 tree-sitter selection 对比

建议对重要 template 分别生成：

```bash
python3 -m template_maker.ast_mask_select \
  --root <template_root>

python3 -m template_maker.ast_mask_select \
  --root <template_root> \
  --ast-report-name ast_mask_report.tree_sitter.yaml \
  --output-name selected_mask_units.tree_sitter.yaml
```

对比：

```text
selected trigger calls
oracle units
mutation points
placeholder dependencies
identifiers_read / identifiers_written
```

## 当前限制

- tree-sitter backend 仍是可选 backend，还不是默认 backend。
- tree-sitter backend 能提供真实 C 语法结构，但还不是完整编译语义分析。
- `identifiers_read` / `identifiers_written` 目前仍是轻量推断。
- dependency-aware mask units 目前是启发式，不是完整数据流分析。
- 真实 verdict 仍依赖本地 clean source 编译运行。
- 当前远端分支与 `main` 可能存在 merge conflict，建议等队友测试后再统一解决。

## 下一步计划

建议后续按这个顺序继续：

1. 让有 clean sources 的队友跑真实 compile/run smoke。
2. 优先验证 `MBEDTLS-POC-0020 -> d2i_PrivateKey / d2i_RSAPrivateKey / d2i_RSA_PUBKEY`。
3. 验证 `pk_verify_ext_null_deref -> EVP_DigestVerify` 是否能稳定得到 safe rejection 或 crash evidence。
4. 比较 lite 和 tree-sitter selected units 的实际下游效果。
5. 如果真实测试稳定，可以考虑让 adapter generation 默认优先读取 tree-sitter selected units，但保留 lite fallback。
6. 继续增强 dependency-aware selection：

```text
trigger call dependencies
oracle-observed variables
cleanup-owned objects
input-construction variables
mutation placeholder propagation
```

7. 后续新增 harness family 时，优先通过：

```text
config/harness_family_ast_rules.yaml
adapter_recipes/
structured adapter.yaml
```

而不是继续在 Python 中增加单个 PoC 的硬编码逻辑。

