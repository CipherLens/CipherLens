# GLM Environment Setup Guide

本项目的 GLM/LLM 调用依赖 shell 环境变量，不应把真实 API key 写入仓库、脚本、日志或 artifacts。

## 推荐的一次性 shell 配置

```bash
export ZHIPUAI_API_KEY="用户自己的真实key"
export GLM_API_KEY="$ZHIPUAI_API_KEY"
export GLM_MODEL="glm-4-flash-250414"
export GLM_BASE_URL="https://open.bigmodel.cn/api/paas/v4"
```

说明：

- 同时设置 `ZHIPUAI_API_KEY` 和 `GLM_API_KEY`，用于兼容不同脚本。
- `GLM_MODEL` 建议先使用 `glm-4-flash-250414`。
- `GLM_BASE_URL` 使用智谱通用 API endpoint。
- 不要把真实 key 写入项目目录。

## 推荐的长期配置方式

建议把 key 放在仓库外：

```text
~/.config/crypto-pattern-fuzz/glm.env
```

模板内容：

```bash
export ZHIPUAI_API_KEY="replace-with-your-real-key"
export GLM_API_KEY="$ZHIPUAI_API_KEY"
export GLM_MODEL="glm-4-flash-250414"
export GLM_BASE_URL="https://open.bigmodel.cn/api/paas/v4"
```

权限建议：

```bash
chmod 600 ~/.config/crypto-pattern-fuzz/glm.env
```

然后在 `~/.bashrc` 中加入：

```bash
source ~/.config/crypto-pattern-fuzz/glm.env
```

打开 VS Code / Codex 前，建议从已经加载环境变量的 WSL 终端进入仓库并启动：

```bash
cd ~/work/crypto-pattern-fuzz
source .venv/bin/activate
code .
```

如果 DNS 解析 `open.bigmodel.cn` 失败，请检查 WSL DNS、Windows 代理是否正确转发到 WSL，以及是否需要调整或取消 `HTTP_PROXY` / `HTTPS_PROXY`。
