export interface FrontendContract {
  manifest?: Record<string, unknown>;
  news?: Record<string, unknown>;
  capability?: Record<string, unknown>;
  threat?: Record<string, unknown>;
  vuln?: Record<string, unknown>;
  ops?: Record<string, unknown>;
}
