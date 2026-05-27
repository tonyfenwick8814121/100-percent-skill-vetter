# Coverage Notes

## Verified Behavior

Tested locally on OpenClaw 2026.5.20.

Works:

- Direct `before_install` hook simulation blocks critical findings.
- Direct `before_tool_call` hook simulation blocks `openclaw plugins install ...`.
- Reports are written before returning the install decision.

Gap:

- A direct terminal run of `openclaw plugins install /tmp/bad-plugin` installed the fixture because the CLI command path did not preload runtime plugins before executing install logic.

## Why Downloaded-but-unused Files Are Usually Lower Risk

A skill sitting on disk is generally inert until an agent reads/uses it or an install recipe runs. The main risks before use are parser/extractor bugs, package-manager lifecycle scripts, or other host behavior that executes code while downloading/unpacking/installing.

OpenClaw's npm plugin installer uses `--ignore-scripts`, which reduces package lifecycle script risk. Still, plugin code executes once the plugin is loaded, so pre-activation scanning matters.

## Required Core Policy for Literal 100% Coverage

OpenClaw should preload runtime plugins for install/update command paths, so `before_install` hooks are active during terminal installs:

```js
{
  commandPath: ["plugins", "install"],
  exact: true,
  policy: { loadPlugins: "always" }
},
{
  commandPath: ["plugins", "update"],
  exact: true,
  policy: { hideBanner: true, loadPlugins: "always" }
},
{
  commandPath: ["skills", "install"],
  exact: true,
  policy: { loadPlugins: "always" }
},
{
  commandPath: ["skills", "update"],
  exact: true,
  policy: { loadPlugins: "always" }
}
```

The plugin should not silently claim this coverage without that host behavior.

## 中文覆盖说明

已验证：

- `before_install` 逻辑本身可以阻断 critical 风险。
- `before_tool_call` 逻辑本身可以阻断 agent 调用安装命令。
- 审查报告会在 hook 返回安装决策前写入本地。

未覆盖：

- 如果用户直接在终端执行 `openclaw plugins install ...`，且 OpenClaw 对该命令没有预加载插件，那么任何插件都无法拦截这条路径。

结论：

- 插件可以覆盖 OpenClaw runtime hook 路径。
- 真正 100% 需要 OpenClaw 核心 CLI 策略配合。
