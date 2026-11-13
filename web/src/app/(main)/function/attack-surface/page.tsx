"use client";
"use no memo";

import * as React from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  type Edge as RFEdge,
  Handle,
  MarkerType,
  MiniMap,
  type Node as RFNode,
  type NodeProps,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { Loader2Icon, RefreshCwIcon, WaypointsIcon, ShieldAlertIcon, CrosshairIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import type { Asset } from "@/lib/types";
import { Button } from "@/components/ui/button";

// Asset type → attack-surface tier (column) + color. root domains on the left,
// endpoints on the right, so edges read left-to-right as reachability chains.
const TIER: Record<string, number> = { root_domain: 0, subdomain: 1, ip: 2, service: 3, endpoint: 4, app: 2 };
const COLOR: Record<string, string> = {
  root_domain: "#10b981",
  subdomain: "#3b82f6",
  ip: "#8b5cf6",
  service: "#f59e0b",
  endpoint: "#06b6d4",
  app: "#64748b",
};

type ASNodeData = { label: string; sub: string; type: string; score: number; reasons: string[]; entry: boolean };
type ASNode = RFNode<ASNodeData>;

// host extracts the hostname from a URL (or returns the raw string on failure).
function host(u?: string): string {
  if (!u) return "";
  try {
    return new URL(u).hostname;
  } catch {
    return u.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  }
}

// riskColor maps an attack-path risk score (0-100) to a tint.
function riskColor(score: number): string {
  if (score >= 50) return "#ef4444"; // red — entry point / critical exposure
  if (score >= 25) return "#f59e0b"; // amber — notable exposure
  if (score > 0) return "#eab308"; // yellow — minor
  return "";
}

// RISKY_PORTS are commonly-exploitable services worth flagging when open.
const RISKY_PORTS: Record<number, string> = {
  21: "ftp", 23: "telnet", 445: "smb", 3389: "rdp", 3306: "mysql", 5432: "postgres",
  6379: "redis", 9200: "elasticsearch", 27017: "mongodb", 2375: "docker", 11211: "memcached", 5900: "vnc",
};

// scoreAsset computes an attack-path risk score + reasons from the asset's own
// fields (no CVE/breach persistence needed): exposed credentials, risky open
// ports, sensitive tech/endpoints. Higher = closer to a usable entry point.
function scoreAsset(a: Asset): { score: number; reasons: string[] } {
  let s = 0;
  const r: string[] = [];
  const creds = Array.isArray(a.auth) && a.auth.length > 0;
  if (a.type === "service") {
    if (creds) {
      s += 50;
      r.push("exposed credentials");
    }
    if (typeof a.status_code === "number" && a.status_code < 400) {
      s += 8;
      r.push("live service");
    }
    const tech = (a.technologies ?? []).join(" ").toLowerCase();
    for (const k of ["jenkins", "gitlab", "phpmyadmin", "wordpress", "struts", "weblogic", "shiro", "swagger", "actuator", "grafana", "kibana"]) {
      if (tech.includes(k)) {
        s += 15;
        r.push("sensitive tech: " + k);
        break;
      }
    }
  }
  if (a.type === "ip") {
    const risky = (a.open_ports ?? []).map((p) => p.port).filter((p) => p in RISKY_PORTS);
    if (risky.length) {
      s += 25;
      r.push("risky ports: " + risky.map((p) => RISKY_PORTS[p]).join(", "));
    }
  }
  if (a.type === "endpoint") {
    if (/admin|debug|actuator|\.env|config|backup|swagger|\.git|phpinfo/i.test(a.url ?? "")) {
      s += 20;
      r.push("sensitive endpoint");
    }
    if ((a.params?.length ?? 0) > 0) s += 5;
  }
  return { score: Math.min(100, s), reasons: r };
}

// AssetNode is the custom React Flow node: a compact card tinted by asset type,
// with a red ring when the asset is a likely entry point (exposed creds/service).
function AssetNode({ data }: NodeProps<ASNode>) {
  const c = COLOR[data.type] ?? "#64748b";
  const rc = riskColor(data.score);
  return (
    <div
      className={cn("min-w-[150px] max-w-[220px] rounded-md border bg-card px-2.5 py-1.5 shadow-sm")}
      style={rc ? { borderColor: rc, boxShadow: `0 0 0 1.5px ${rc}55` } : { borderColor: c }}
      title={data.reasons.join(" · ")}
    >
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0" style={{ background: c }} />
      <div className="flex items-center gap-1.5">
        <span className="size-2 shrink-0 rounded-full" style={{ background: c }} />
        <span className="text-[9px] font-medium uppercase tracking-wide text-muted-foreground">{data.type.replace("_", " ")}</span>
        {data.score >= 50 ? (
          <ShieldAlertIcon className="ml-auto size-3 text-red-400" />
        ) : data.score > 0 ? (
          <span className="ml-auto rounded px-1 text-[8px] font-semibold tabular-nums" style={{ background: rc + "22", color: rc }}>{data.score}</span>
        ) : null}
      </div>
      <div className="mt-0.5 truncate font-mono text-[11px] font-medium" title={data.label}>{data.label}</div>
      {data.sub && <div className="truncate text-[9px] text-muted-foreground" title={data.sub}>{data.sub}</div>}
      <Handle type="source" position={Position.Right} className="!size-1.5 !border-0" style={{ background: c }} />
    </div>
  );
}

const nodeTypes = { asset: AssetNode };

function buildGraph(assets: Asset[]): { nodes: ASNode[]; edges: RFEdge[] } {
  const byDomain = new Map<string, Asset>(); // domain → root_domain/subdomain asset
  const byIP = new Map<string, Asset>();
  for (const a of assets) {
    if (a.domain) byDomain.set(a.domain.toLowerCase(), a);
    if (a.type === "ip" && a.ip) byIP.set(a.ip, a);
  }
  // first service per host, so endpoints can attach to their service.
  const svcByHost = new Map<string, Asset>();
  for (const a of assets) {
    if (a.type === "service") {
      const h = (host(a.url) || a.domain || a.ip || "").toLowerCase();
      if (h && !svcByHost.has(h)) svcByHost.set(h, a);
    }
  }

  const nid = (a: Asset) => `a-${a.id}`;
  const edges: RFEdge[] = [];
  const addEdge = (s: string, d: string, rel: string, color: string) => {
    edges.push({
      id: `${s}->${d}:${rel}`,
      source: s,
      target: d,
      label: rel,
      type: "default",
      animated: false,
      style: { stroke: color, strokeWidth: 1.2 },
      labelStyle: { fontSize: 8, fill: "#9ca3af" },
      labelBgStyle: { fill: "transparent" },
      markerEnd: { type: MarkerType.ArrowClosed, color, width: 12, height: 12 },
    });
  };

  for (const a of assets) {
    if (a.type === "subdomain") {
      const root = a.root_domain && byDomain.get(a.root_domain.toLowerCase());
      if (root && root.id !== a.id) addEdge(nid(root), nid(a), "has_subdomain", COLOR.root_domain);
      const rv = Array.isArray(a.record_value) ? a.record_value : a.record_value ? [a.record_value] : [];
      for (const v of rv) {
        const ipA = byIP.get(v);
        if (ipA) addEdge(nid(a), nid(ipA), "resolves", COLOR.ip);
      }
    }
    if (a.type === "service") {
      const h = (host(a.url) || a.domain || "").toLowerCase();
      const hostA = h && byDomain.get(h);
      const ipA = a.ip && byIP.get(a.ip);
      if (hostA) addEdge(nid(hostA), nid(a), "exposes", COLOR.service);
      else if (ipA) addEdge(nid(ipA), nid(a), "exposes", COLOR.service);
    }
    if (a.type === "endpoint") {
      const svc = svcByHost.get(host(a.url).toLowerCase());
      if (svc && svc.id !== a.id) addEdge(nid(svc), nid(a), "has_endpoint", COLOR.endpoint);
    }
    if (a.type === "ip") {
      for (const d of a.bound_domains ?? []) {
        const dA = byDomain.get(d.toLowerCase());
        if (dA) addEdge(nid(dA), nid(a), "resolves", COLOR.ip);
      }
    }
  }

  // layout: column per tier, stacked vertically.
  const perTier: Record<number, number> = {};
  const nodes: ASNode[] = assets.map((a) => {
    const tier = TIER[a.type] ?? 2;
    const row = (perTier[tier] = (perTier[tier] ?? 0) + 1) - 1;
    const { score, reasons } = scoreAsset(a);
    const entry = score >= 50;
    const label =
      a.domain || a.ip || (a.url ? host(a.url) + (new URL(a.url, "http://x").pathname || "") : "") || a.service_name || a.app_name || `#${a.id}`;
    const sub =
      a.type === "service"
        ? [a.page_title, a.status_code ? `HTTP ${a.status_code}` : "", (a.technologies ?? []).slice(0, 2).join(", ")].filter(Boolean).join(" · ")
        : a.type === "ip"
          ? (a.open_ports ?? []).map((p) => p.port).slice(0, 6).join(", ")
          : a.type === "subdomain"
            ? (Array.isArray(a.record_value) ? a.record_value : [a.record_value]).filter(Boolean).slice(0, 2).join(", ")
            : a.type === "endpoint"
              ? a.method ?? ""
              : "";
    return {
      id: `a-${a.id}`,
      type: "asset",
      position: { x: tier * 300 + 40, y: row * 78 + 40 },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      data: { label: String(label), sub: String(sub), type: a.type, score, reasons, entry },
    };
  });

  return { nodes, edges };
}

function AttackSurfaceInner() {
  const { t } = useTranslation();
  const router = useRouter();
  const [assets, setAssets] = React.useState<Asset[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [launching, setLaunching] = React.useState(false);
  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<ASNode>([]);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<RFEdge>([]);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const types = ["root_domain", "subdomain", "ip", "service", "endpoint", "app"];
      const results = await Promise.all(types.map((ty) => api.assets(ty, 500, 0).catch(() => ({ assets: [], total: 0 }))));
      setAssets(results.flatMap((r) => r.assets));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const { nodes, edges } = React.useMemo(() => buildGraph(assets), [assets]);

  // push the computed graph into React Flow's state (matches the Exploration
  // Graph pattern; rendering from static props left the canvas blank).
  React.useEffect(() => {
    setRfNodes(nodes);
    setRfEdges(edges);
  }, [nodes, edges, setRfNodes, setRfEdges]);

  const counts = React.useMemo(() => {
    const c: Record<string, number> = {};
    for (const a of assets) c[a.type] = (c[a.type] ?? 0) + 1;
    return c;
  }, [assets]);
  const entryPoints = nodes.filter((n) => n.data.entry).length;
  const topRisks = React.useMemo(
    () => nodes.filter((n) => n.data.score > 0).sort((a, b) => b.data.score - a.data.score).slice(0, 6),
    [nodes],
  );

  // launch a pentest task; target = a specific asset (node click) or the whole
  // discovered surface (header button). Navigates to the new task on success.
  const launchTask = React.useCallback(
    async (target: string, name: string) => {
      if (launching) return;
      const ok = window.confirm(t("attackSurface.launchConfirm", { target }));
      if (!ok) return;
      setLaunching(true);
      try {
        const task = await api.createTask(
          name,
          `Pentest the target(s) discovered by attack-surface recon: ${target}. Authorized scope only.`,
          "Following OWASP Top 10 2025, find and confirm vulnerabilities; prioritize entry points (exposed credentials/services). Provide PoCs.",
        );
        toast.success(t("attackSurface.launched"));
        router.push(`/function/tasks/detail?id=${task.id}`);
      } catch (e) {
        toast.error((e as Error).message);
      } finally {
        setLaunching(false);
      }
    },
    [launching, router, t],
  );

  const onNodeClick = React.useCallback(
    (_: React.MouseEvent, node: ASNode) => {
      const target = node.data.label;
      if (!target) return;
      void launchTask(target, `Pentest ${target}`);
    },
    [launchTask],
  );

  // the whole surface: root domains + the riskiest hosts, as one target string.
  const surfaceTarget = React.useMemo(() => {
    const roots = assets.filter((a) => a.type === "root_domain").map((a) => a.domain).filter(Boolean);
    const svc = topRisks.map((n) => n.data.label);
    return [...new Set([...roots, ...svc])].slice(0, 12).join(", ");
  }, [assets, topRisks]);

  return (
    <div className="flex flex-1 flex-col gap-3 pb-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
            <WaypointsIcon className="size-4" /> {t("attackSurface.title")}
          </h1>
          <p className="text-xs text-muted-foreground">{t("attackSurface.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            onClick={() => void launchTask(surfaceTarget, "Attack Surface pentest")}
            disabled={loading || launching || !surfaceTarget}
          >
            {launching ? <Loader2Icon className="size-3.5 animate-spin" /> : <CrosshairIcon className="size-3.5" />}
            {t("attackSurface.launch")}
          </Button>
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            {loading ? <Loader2Icon className="size-3.5 animate-spin" /> : <RefreshCwIcon className="size-3.5" />}
            {t("common.refresh")}
          </Button>
        </div>
      </div>

      {/* legend + counts */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
        {Object.entries(COLOR).map(([ty, c]) => (
          <span key={ty} className="flex items-center gap-1.5">
            <span className="size-2 rounded-full" style={{ background: c }} />
            {ty.replace("_", " ")} <span className="tabular-nums">{counts[ty] ?? 0}</span>
          </span>
        ))}
        {entryPoints > 0 && (
          <span className="flex items-center gap-1 font-medium text-red-400">
            <ShieldAlertIcon className="size-3" /> {t("attackSurface.entryPoints", { count: entryPoints })}
          </span>
        )}
      </div>

      <div className="h-[calc(100vh-13rem)] w-full overflow-hidden rounded-lg border bg-card">
        {loading ? (
          <div className="flex h-full items-center justify-center gap-2 text-sm text-muted-foreground">
            <Loader2Icon className="size-4 animate-spin" /> {t("common.loading")}
          </div>
        ) : nodes.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 text-center text-sm text-muted-foreground">
            <WaypointsIcon className="size-8 opacity-40" />
            <p>{t("attackSurface.empty")}</p>
          </div>
        ) : (
          <ReactFlow
            nodes={rfNodes}
            edges={rfEdges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.05}
            proOptions={{ hideAttribution: true }}
          >
            <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
            <Controls showInteractive={false} />
            <MiniMap pannable zoomable nodeColor={(n) => riskColor((n.data as ASNodeData)?.score ?? 0) || (COLOR[(n.data as ASNodeData)?.type] ?? "#64748b")} />
            {topRisks.length > 0 && (
              <Panel position="top-right" className="!m-2 w-64 rounded-lg border bg-card/95 p-2.5 shadow-md backdrop-blur">
                <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold">
                  <ShieldAlertIcon className="size-3.5 text-red-400" /> {t("attackSurface.topRisks")}
                </div>
                <div className="flex flex-col gap-1.5">
                  {topRisks.map((n) => (
                    <div key={n.id} className="text-[10px]">
                      <div className="flex items-center gap-1.5">
                        <span className="rounded px-1 font-semibold tabular-nums" style={{ background: (riskColor(n.data.score) || "#64748b") + "22", color: riskColor(n.data.score) || "#64748b" }}>{n.data.score}</span>
                        <span className="truncate font-mono" title={n.data.label}>{n.data.label}</span>
                      </div>
                      <div className="truncate pl-1 text-[9px] text-muted-foreground" title={n.data.reasons.join(" · ")}>{n.data.reasons.join(" · ")}</div>
                    </div>
                  ))}
                </div>
              </Panel>
            )}
          </ReactFlow>
        )}
      </div>
    </div>
  );
}

export default function AttackSurfacePage() {
  return (
    <ReactFlowProvider>
      <AttackSurfaceInner />
    </ReactFlowProvider>
  );
}
