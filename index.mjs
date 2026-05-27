/**
 * 100% Skill Vetter (local compatibility id: skill-preflight)
 *
 * Guards OpenClaw-mediated skill/plugin installs with a skill-vetter style
 * preflight scan, and blocks agent tool calls that try to install skills or
 * plugins outside the install hook path.
 */
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { dirname, extname, join } from "node:path";
import os from "node:os";

const REPORT_DIR = join(os.homedir(), ".openclaw", "skill-vetter-reports");
const MAX_FILE_BYTES = 512 * 1024;
const MAX_REPORT_FINDINGS = 80;

const RED_FLAGS = [
  { pattern: /\bcurl\b[\s\S]{0,200}(?:\|\s*(?:bash|sh|zsh)|(?:-o|--output|-O|--remote-name|-s|--silent|-f|--fail|-L|--location))/i, name: "remote curl download or pipe", severity: "critical" },
  { pattern: /\bwget\b[\s\S]{0,200}(?:\|\s*(?:bash|sh|zsh)|(?:-O|--output-document|-q|--quiet|-c|--continue))/i, name: "remote wget download", severity: "critical" },
  { pattern: /\b(?:Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)\b/i, name: "PowerShell remote request", severity: "critical" },
  { pattern: /[~$]\/\.(?:ssh|aws|kube|gcloud|azure|docker)\b/, name: "credential directory access", severity: "critical" },
  { pattern: /[~$]\/\.config\b/, name: "broad user config access", severity: "warn" },
  { pattern: /\bid_(?:rsa|ed25519|ecdsa|dsa)\b/, name: "SSH private key reference", severity: "critical" },
  { pattern: /(?:Chrome|Edge|Firefox|Brave|Chromium)[^a-zA-Z]{0,20}(?:Login\s*Data|Cookies|Local\s*State|Default)/i, name: "browser credential store access", severity: "critical" },
  { pattern: /\bpasswords?\b.{0,60}(?:export|upload|send|exfiltrat|dump|steal)/i, name: "password export or theft wording", severity: "critical" },
  { pattern: /\b(MEMORY|USER|SOUL|IDENTITY|HEARTBEAT|BOOTSTRAP)\.[mM][dD]\b/, name: "agent memory or identity file access", severity: "critical" },
  { pattern: /\b(?:base64|FromBase64String)\b.{0,60}(?:-d|--decode|-D|\.decode)/i, name: "base64 decode", severity: "critical" },
  { pattern: /\b(?:eval|exec)\s*\(/, name: "dynamic code execution", severity: "critical" },
  { pattern: /\bFunction\s*\(/, name: "Function constructor execution", severity: "critical" },
  { pattern: /\b(?:child_process|spawn|execFile|execSync)\b/, name: "Node command execution API", severity: "warn" },
  { pattern: /\bsudo\s+(?:-\S*\s+)?(?:bash|sh|zsh|python|node|curl|wget|rm)/i, name: "sudo shell or downloader execution", severity: "critical" },
  { pattern: /chmod\s+\+?s\b|\bSUID\b/i, name: "SUID privilege change", severity: "critical" },
  { pattern: /\brm\s+-(?:r[^"']{0,3}|f[^"']{0,3}|rf|fr)\s+(?:\/|\\|\/[a-zA-Z])/, name: "dangerous recursive deletion", severity: "critical" },
  { pattern: /\bchmod\s+0?777\b/, name: "world-writable permission change", severity: "warn" },
  { pattern: /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:[\s"')]|$)/, name: "direct IP network endpoint", severity: "critical" },
  { pattern: /(?:\\x[0-9a-fA-F]{2}){6,}/, name: "hex escaped obfuscation", severity: "warn" },
  { pattern: /\b(?:API_?KEY|SECRET_?KEY|ACCESS_?KEY|TOKEN)\s*=\s*['"][A-Za-z0-9_\-]{20,}['"]/i, name: "hard-coded API secret", severity: "critical" },
  { pattern: /\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{20,}/, name: "hard-coded GitHub token", severity: "critical" },
  { pattern: /AKIA[0-9A-Z]{16}/, name: "hard-coded AWS access key", severity: "critical" },
  { pattern: /\/(?:upload|collect|track|beacon|pixel)[^.]*\.[a-z]{2,}(?:\?.*)?\b/i, name: "possible data exfiltration endpoint", severity: "critical" },
  { pattern: /\b(?:ncat|nc\.exe|powercat|ngrok)\b|\/dev\/tcp\//i, name: "reverse shell or tunnel utility", severity: "critical" },
];

const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2",
  ".ttf", ".eot", ".mp3", ".mp4", ".wav", ".ogg", ".zip", ".tar", ".gz",
  ".bz2", ".xz", ".dll", ".exe", ".so", ".dylib", ".pdf",
]);

const INSTALL_COMMAND_RE = /\bopenclaw\s+(?:plugins|skills)\s+install\b/i;
const INSTALL_TOOL_NAME_RE = /(?:^|[_.:-])(?:plugin|plugins|skill|skills)[_.:-]?(?:install|add|create)(?:$|[_.:-])/i;

function isoStamp() {
  return new Date().toISOString();
}

function sanitizeFileName(value) {
  return String(value || "target").replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "target";
}

function stableHash(value) {
  return createHash("sha256").update(String(value)).digest("hex").slice(0, 12);
}

async function scanDirectory(dirPath) {
  const files = [];
  try {
    for (const entry of await readdir(dirPath, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === ".git" || entry.name === ".openclaw-vetter") continue;
      const fullPath = join(dirPath, entry.name);
      if (entry.isDirectory()) {
        files.push(...await scanDirectory(fullPath));
        continue;
      }
      if (!entry.isFile()) continue;
      const ext = extname(entry.name).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) continue;
      try {
        const st = await stat(fullPath);
        if (st.size > MAX_FILE_BYTES) continue;
        files.push({ path: fullPath, name: entry.name, content: await readFile(fullPath, "utf8") });
      } catch {}
    }
  } catch {}
  return files;
}

async function scanSourcePath(sourcePath) {
  try {
    const st = await stat(sourcePath);
    if (st.isDirectory()) return scanDirectory(sourcePath);
    if (!st.isFile() || st.size > MAX_FILE_BYTES || BINARY_EXTENSIONS.has(extname(sourcePath).toLowerCase())) return [];
    return [{ path: sourcePath, name: sourcePath.split("/").pop() || sourcePath, content: await readFile(sourcePath, "utf8") }];
  } catch {
    return [];
  }
}

function checkRedFlags(files) {
  const findings = [];
  for (const file of files) {
    for (const rule of RED_FLAGS) {
      const match = file.content.match(rule.pattern);
      if (!match) continue;
      const beforeMatch = file.content.slice(0, match.index);
      findings.push({
        file: file.path,
        line: (beforeMatch.match(/\n/g) || []).length + 1,
        rule: rule.name,
        severity: rule.severity,
        snippet: match[0].slice(0, 160).replace(/\s+/g, " "),
      });
      break;
    }
  }
  return findings;
}

function normalizeBuiltinFindings(builtinScan) {
  return (builtinScan?.findings || []).map((finding) => ({
    file: finding.file || "unknown",
    line: finding.line || 1,
    rule: finding.message || finding.rule || "OpenClaw built-in scanner finding",
    severity: finding.severity || "warn",
    snippet: finding.snippet || "",
  }));
}

function classifyRisk(findings) {
  if (findings.some((finding) => finding.severity === "critical")) return "EXTREME";
  if (findings.some((finding) => finding.severity === "warn")) return "MEDIUM";
  return "LOW";
}

function buildMarkdownReport({ event, files, findings, builtinFindings, verdict, risk }) {
  const allFindings = [...builtinFindings, ...findings].slice(0, MAX_REPORT_FINDINGS);
  const target = `${event.targetType}:${event.targetName}`;
  const source = event.origin || event.request?.requestedSpecifier || "local";
  const lines = [
    "# Skill Vetting Report",
    "",
    `- Target: ${target}`,
    `- Source: ${source}`,
    `- Request: ${event.request?.kind || "unknown"} / ${event.request?.mode || "install"}`,
    `- Generated: ${isoStamp()}`,
    `- Files reviewed: ${files.length}`,
    `- Risk level: ${risk}`,
    `- Verdict: ${verdict}`,
    "",
    "## Findings",
    "",
  ];
  if (allFindings.length === 0) {
    lines.push("No critical or warning findings were detected by the configured scanners.");
  } else {
    for (const finding of allFindings) {
      lines.push(`- ${finding.severity.toUpperCase()}: ${finding.rule} (${finding.file}:${finding.line})`);
      if (finding.snippet) lines.push(`  - Snippet: \`${finding.snippet.replace(/`/g, "'")}\``);
    }
  }
  lines.push("", "## Coverage Note", "");
  lines.push("This report covers the extracted or local install source available to OpenClaw before activation/use. It cannot prove that arbitrary future network payloads are safe.");
  return lines.join("\n");
}

async function writeReport(event, report) {
  await mkdir(REPORT_DIR, { recursive: true });
  const fileName = `${new Date().toISOString().replace(/[:.]/g, "-")}-${sanitizeFileName(event.targetType)}-${sanitizeFileName(event.targetName)}-${stableHash(event.sourcePath || event.targetName)}.md`;
  const path = join(REPORT_DIR, fileName);
  await writeFile(path, report, "utf8");
  return path;
}

function stringifyParams(params) {
  if (!params || typeof params !== "object") return String(params ?? "");
  try {
    return JSON.stringify(params);
  } catch {
    return String(params);
  }
}

function toolCallLooksLikeInstall(event) {
  const toolName = String(event.toolName || "");
  const text = `${toolName}\n${stringifyParams(event.params)}`;
  return INSTALL_TOOL_NAME_RE.test(toolName) || INSTALL_COMMAND_RE.test(text);
}

function blockReasonForToolCall(event) {
  return [
    "100% Skill Vetter blocked an agent-initiated skill/plugin install attempt.",
    `Tool: ${event.toolName}`,
    "Run an explicit vetting flow first, or perform the install manually after reviewing the source and report.",
  ].join("\n");
}

export default {
  id: "100-percent-skill-vetter",
  name: "100% Skill Vetter",
  description: "Skill-vetter preflight reports and install-path enforcement for OpenClaw skills/plugins.",
  version: "2.0.0",
  register(api) {
    api.on("before_tool_call", async (event) => {
      if (!toolCallLooksLikeInstall(event)) return;
      return {
        block: true,
        blockReason: blockReasonForToolCall(event),
      };
    }, { priority: 1000 });

    api.on("before_install", async (event) => {
      const builtinFindings = normalizeBuiltinFindings(event.builtinScan);
      const files = event.sourcePath ? await scanSourcePath(event.sourcePath) : [];
      const findings = checkRedFlags(files);
      const allFindings = [...builtinFindings, ...findings];
      const criticalFindings = allFindings.filter((finding) => finding.severity === "critical");
      const warnFindings = allFindings.filter((finding) => finding.severity === "warn");
      const risk = classifyRisk(allFindings);
      const verdict = criticalFindings.length > 0 ? "DO NOT INSTALL" : warnFindings.length > 0 ? "INSTALL WITH CAUTION" : "SAFE TO INSTALL";
      const reportPath = await writeReport(event, buildMarkdownReport({
        event,
        files,
        findings,
        builtinFindings,
        verdict,
        risk,
      }));

      api.logger?.info?.(`[100% skill-vetter] report written: ${reportPath}`);

      if (criticalFindings.length > 0) {
        const detail = criticalFindings.slice(0, 10)
          .map((finding) => `[${finding.file}:${finding.line}] ${finding.rule}`)
          .join("; ");
        return {
          block: true,
          blockReason: `100% Skill Vetter blocked installation before activation/use.\nReport: ${reportPath}\nCritical findings: ${detail}`,
        };
      }

      if (warnFindings.length > 0) {
        return {
          findings: warnFindings.map((finding) => ({
            severity: "warn",
            file: finding.file,
            line: finding.line,
            message: `${finding.rule}; report: ${reportPath}`,
          })),
        };
      }

      return {
        findings: [{
          severity: "info",
          file: event.sourcePath || "unknown",
          line: 1,
          message: `100% Skill Vetter report written: ${reportPath}`,
        }],
      };
    }, { priority: 1000 });
  },
};
