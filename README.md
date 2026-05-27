# 100% Skill Vetter

OpenClaw install preflight guard for skills and plugins. It writes a skill-vetter style report before activation/use, blocks critical findings, and blocks agent tool calls that try to install skills/plugins without going through the vetting path.

## What It Covers

- `before_install`: scans extracted/local skill and plugin install sources before OpenClaw activates or uses them.
- `before_tool_call`: blocks agent tool calls that invoke `openclaw plugins install`, `openclaw skills install`, or obvious internal install tools.
- Reports: writes Markdown reports to `~/.openclaw/skill-vetter-reports/`.
- Critical findings: blocks install before activation/use.
- Warning findings: allows install but returns warnings and points to the report.

## Important Limit

This plugin alone cannot intercept a human running `openclaw plugins install ...` in a terminal if that OpenClaw command path does not preload plugins. On OpenClaw 2026.5.20, this is the remaining gap I verified locally.

To make the name literally true, pair this plugin with an OpenClaw core policy change that preloads plugins for:

- `openclaw plugins install`
- `openclaw plugins update`
- `openclaw skills install`
- `openclaw skills update`

See [docs/COVERAGE.md](docs/COVERAGE.md).

## Install

```bash
openclaw plugins install /path/to/100-percent-skill-vetter
openclaw plugins enable 100-percent-skill-vetter
```

After installing, restart the OpenClaw gateway so runtime hooks load.

## 中文说明

`100% Skill Vetter` 是一个 OpenClaw 技能/插件安装前审查插件。它会在 skill/plugin 真正激活或使用前生成审查报告；发现 critical 风险时直接阻断安装；同时通过 `before_tool_call` 拦截 agent 试图调用安装命令或内部安装工具的行为。

报告位置：

```bash
~/.openclaw/skill-vetter-reports/
```

### 重要限制

仅靠插件本身，无法拦截用户在终端直接运行的 `openclaw plugins install ...`，前提是当前 OpenClaw 版本没有在该 CLI 路径预加载插件。我在 OpenClaw 2026.5.20 上验证过，这是当前真实缺口。

如果要做到字面意义上的“100% 全路径覆盖”，需要同时改 OpenClaw 核心命令策略，让安装/更新命令加载插件 hook。详见 [docs/COVERAGE.md](docs/COVERAGE.md)。

## License

MIT
