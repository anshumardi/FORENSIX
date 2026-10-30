import type { Severity } from "./types";

export function formatDate(value?: string | null, withTime = true) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    year: "numeric",
    ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
  }).format(date);
}

export function formatBytes(value?: number | null) {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) { size /= 1024; index += 1; }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[index]}`;
}

export function labelize(value?: string | null) {
  if (!value) return "Unknown";
  return value.replace(/[_-]/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function severityTone(severity?: Severity | null) {
  const value = severity?.toLowerCase();
  if (value === "critical") return "critical";
  if (value === "high") return "high";
  if (value === "medium") return "medium";
  if (value === "low") return "low";
  return "neutral";
}

export function statusTone(status?: string | null) {
  const value = status?.toLowerCase();
  if (["open", "in_progress", "processing", "pending", "queued", "running"].includes(value || "")) return "accent";
  if (["closed", "resolved", "verified", "ready", "confirmed", "available", "succeeded"].includes(value || "")) return "success";
  if (["failed", "dismissed", "unavailable"].includes(value || "")) return "danger";
  return "neutral";
}

export function safeId(value: unknown) {
  return value === null || value === undefined ? "—" : String(value);
}

export function formatConfidence(value?: number | null) {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  const percentage = value <= 1 ? value * 100 : value;
  return `${Math.round(percentage)}%`;
}
