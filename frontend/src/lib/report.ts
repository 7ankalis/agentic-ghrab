/** Client-side file download helpers for the per-page and full-platform reports. */

function triggerDownload(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function downloadMarkdown(filename: string, content: string) {
  triggerDownload(filename, content, "text/markdown;charset=utf-8");
}

export function downloadCSV(filename: string, content: string) {
  triggerDownload(filename, content, "text/csv;charset=utf-8");
}

export function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
}
