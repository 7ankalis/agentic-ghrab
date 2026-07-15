import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  AppWindow, Archive, Banknote, Cloud, Database, Fingerprint, Gem, Globe,
  HardDrive, KeyRound, Landmark, Monitor, Network, Radio, Router, Server,
  TerminalSquare,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

/** Infer a meaningful glyph from an asset's role/hostname so every node reads
 *  as *what it is* — a domain controller, a database, a SWIFT gateway — instead
 *  of an anonymous box. Order matters: most specific match wins. */
export function roleIcon(role = "", hostname = "", kind = "asset"): LucideIcon {
  if (kind === "internet") return Globe;
  const s = `${role} ${hostname}`.toLowerCase();
  const has = (...k: string[]) => k.some((w) => s.includes(w));

  if (has("swift", "settlement", "trading core", "payment")) return Landmark;
  if (has("domain controller", "active directory", "entra", "dc0", "dc-")) return Network;
  if (has("iam", "identity")) return Fingerprint;
  if (has("backup", "veeam", "replication")) return Archive;
  if (has("database", "oracle", "rds", "postgres", "sql", "db-", "db0")) return Database;
  if (has("file server", "share", "nas", "storage", "s3", "bucket", "filesrv")) return HardDrive;
  if (has("jump", "bastion", "vcenter", "vmware")) return TerminalSquare;
  if (has("firewall", "fortigate", "vpn", "gateway", "router", "-gw", "-rtr")) return Router;
  if (has("load balancer", "reverse proxy", "lb0")) return Router;
  if (has("workstation", "wks", "desktop", "laptop")) return Monitor;
  if (has("web", "portal")) return Globe;
  if (has("app", "crm", "application")) return AppWindow;
  if (has("cloud", "aws", "azure")) return Cloud;
  if (has("settlement", "finance", "trade", "bank")) return Banknote;
  return Server;
}

export { Gem, Radio, KeyRound, Server };

/** Rasterizes a lucide icon to an SVG data-URI, tinted `color`, for use as a
 *  Cytoscape node `background-image` — canvas nodes can't host React elements,
 *  so the glyph has to be baked into a bitmap-ish source once and cached. */
const iconUriCache = new Map<string, string>();

export function iconDataUri(Icon: LucideIcon, color: string): string {
  const key = `${Icon.displayName ?? Icon.name}__${color}`;
  const cached = iconUriCache.get(key);
  if (cached) return cached;
  const markup = renderToStaticMarkup(createElement(Icon, { color, strokeWidth: 2, size: 24 }));
  const uri = `data:image/svg+xml;utf8,${encodeURIComponent(markup)}`;
  iconUriCache.set(key, uri);
  return uri;
}
