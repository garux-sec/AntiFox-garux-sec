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
  Position,
  ReactFlow,
  ReactFlowProvider,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useTranslation } from "react-i18next";
import { Loader2Icon, RefreshCwIcon, WaypointsIcon, ShieldAlertIcon } from "lucide-react";
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

type ASNodeData = { label: string; sub: string; type: string; risky: boolean; entry: boolean };
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

function isIP(s: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(":");
}

// AssetNode is the custom React Flow node: a compact card tinted by asset type,
// with a red ring when the asset is a likely entry point (exposed creds/service).
function AssetNode({ data }: NodeProps<ASNode>) {
  const c = COLOR[data.type] ?? "#64748b";
  return (
    <div
      className={cn(
        "min-w-[150px] max-w-[220px] rounded-md border bg-card px-2.5 py-1.5 shadow-sm",
        data.entry && "ring-2 ring-red-500/60",
      )}
      style={{ borderColor: c }}
    >
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0" style={{ background: c }} />
      <div className="flex items-center gap-1.5">
        <span className="size-2 shrink-0 rounded-full" style={{ background: c }} />
        <span className="text-[9px] font-medium uppercase tracking-wide text-muted-foreground">{data.type.replace("_", " ")}</span>
        {data.risky && <ShieldAlertIcon className="ml-auto size-3 text-red-400" />}
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
    const hasCreds = Array.isArray(a.auth) && a.auth.length > 0;
    const risky = a.type === "service" && (hasCreds || (a.open_ports?.length ?? 0) > 0);
    const entry = a.type === "service" && hasCreds;
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
      data: { label: String(label), sub: String(sub), type: a.type, risky, entry },
    };
  });

  return { nodes, edges };
}

function AttackSurfaceInner() {
  const { t } = useTranslation();
  const [assets, setAssets] = React.useState<Asset[]>([]);
  const [loading, setLoading] = React.useState(true);

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

  const counts = React.useMemo(() => {
    const c: Record<string, number> = {};
    for (const a of assets) c[a.type] = (c[a.type] ?? 0) + 1;
    return c;
  }, [assets]);
  const entryPoints = nodes.filter((n) => n.data.entry).length;

  return (
    <div className="flex flex-1 flex-col gap-3 pb-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
            <WaypointsIcon className="size-4" /> {t("attackSurface.title")}
          </h1>
          <p className="text-xs text-muted-foreground">{t("attackSurface.subtitle")}</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          {loading ? <Loader2Icon className="size-3.5 animate-spin" /> : <RefreshCwIcon className="size-3.5" />}
          {t("common.refresh")}
        </Button>
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

      <div className="min-h-0 flex-1 overflow-hidden rounded-lg border bg-card" style={{ height: "calc(100vh - 13rem)" }}>
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
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.1}
            proOptions={{ hideAttribution: true }}
          >
            <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
            <Controls showInteractive={false} />
            <MiniMap pannable zoomable nodeColor={(n) => COLOR[(n.data as ASNodeData)?.type] ?? "#64748b"} />
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
