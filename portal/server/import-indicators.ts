const LANGUAGES = new Set(["php", "python", "perl", "ruby", "node", "bash", "powershell", "unknown"]);
const TOKENS = new Set(["network_api", "process_api", "loop_text", "delay_api", "restricted_operator", "encoded_marker", "device_tcp", "shell_flag"]);
const VERBS = new Set(["whoami", "id", "uname", "hostname", "pwd", "ls", "cat", "ps", "ss", "netstat", "php", "which", "touch", "mkdir", "rm", "exit"]);
type RecordValue = Record<string, unknown>;
function object(value: unknown): RecordValue | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as RecordValue : null;
}

/** Labels are customer-supplied text observations; nothing is run or decoded. */
export function selectedTextIndicators(report: RecordValue) {
  const field = ["events", "timeline", "decoy_events"].find(key => Array.isArray(report[key]));
  const entries = field ? (report[field] as unknown[]).slice(0, 256) : [];
  const indicators: Array<Record<string, string | number | boolean | null | string[]>> = [];
  for (let index = 0; index < entries.length; index++) {
    const item = object(entries[index]);
    if (!item) continue;
    const language = typeof item.language_indicator === "string" && LANGUAGES.has(item.language_indicator) ? item.language_indicator : null;
    const verb = typeof item.verb === "string" && VERBS.has(item.verb) ? item.verb : null;
    const tokens = Array.isArray(item.token_indicators)
      ? [...new Set(item.token_indicators.filter((value): value is string => typeof value === "string" && TOKENS.has(value)))].slice(0, 8)
      : [];
    if (!language && !verb && tokens.length === 0) continue;
    const commandDigest = typeof item.command_sha256 === "string" && /^[0-9a-f]{64}$/i.test(item.command_sha256) ? item.command_sha256 : null;
    indicators.push({
      source_field: field ?? "unknown",
      source_index: index,
      language_indicator: language,
      verb,
      token_indicators: tokens,
      report_declared_simulation: item.simulation === true || item.synthetic === true,
      supplied_command_sha256: commandDigest,
      interpretation: "Unverified imported labels or text patterns, not execution, competence, identity or real access.",
    });
  }
  return indicators;
}
