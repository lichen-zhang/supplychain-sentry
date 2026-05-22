export const EVAL_REGEX = /(?:^|[^a-zA-Z0-9_$])eval\s*\(/;
export const NEW_FUNCTION_REGEX = /(?:^|[^a-zA-Z0-9_$])new\s+Function\s*\(/;
export const TIMER_STRING_REGEX = /\b(setTimeout|setInterval)\s*\(\s*["'`]/;
export const EXEC_REGEX = /\b(?:exec|execSync|execFile|execFileSync)\s*\(/;
export const SPAWN_REGEX = /\b(?:spawn|spawnSync)\s*\(/;
export const CHILD_PROCESS_REQUIRE = /require\s*\(\s*['"]child_process['"]\s*\)/;
export const FETCH_REGEX = /\bfetch\s*\(/;
export const HTTP_GET_REGEX = /\b(?:http|https)\.(?:get|request)\s*\(/;
export const CURL_REGEX = /\bcurl\s+/;
export const AXIOS_REGEX = /\baxios\.(?:get|post|request)\s*\(/;
export const SENSITIVE_FILE_REGEX =
  /(?:\/etc\/passwd|~\/\.npmrc|~\/\.aws\/credentials|~\/\.ssh|\.env(?:\.|$)|process\.env)/;
export const ENV_EXPORT_REGEX = /process\.env(?:\[|\.)|Object\.assign\s*\(\s*process\.env/;
export const BASE64_REGEX = /["']([A-Za-z0-9+/]{50,}={0,2})["']/g;
