import {
  AppWindow, Archive, Banknote, Cloud, Database, Fingerprint, Globe,
  HardDrive, Landmark, Monitor, Network, Router, Server, TerminalSquare,
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
