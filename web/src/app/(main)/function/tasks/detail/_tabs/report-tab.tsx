"use client";

import * as React from "react";

import { CheckIcon, CopyIcon, DownloadIcon, FileTextIcon, FileUpIcon, Loader2Icon, SparklesIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { api } from "@/lib/api";
import type { ReportJob } from "@/lib/types";

type AIReportProject = { id: string; name: string; client_name: string };

export function ReportTab({ taskId }: { taskId: string }) {
  const { t } = useTranslation();
  const [report, setReport] = React.useState<string>("");
  const [loading, setLoading] = React.useState(true);
  const [copied, setCopied] = React.useState(false);
  const [job, setJob] = React.useState<ReportJob>({ status: "idle" });
  const [pushing, setPushing] = React.useState(false);
  const [projects, setProjects] = React.useState<AIReportProject[] | null>(null);
  const [projErr, setProjErr] = React.useState<string>("");
  const pollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  // load the Markdown quick-view + any existing docx job state
  React.useEffect(() => {
    let active = true;
    setLoading(true);
    api
      .report(taskId)
      .then((text) => active && setReport(text))
      .catch(() => active && setReport(""))
      .finally(() => active && setLoading(false));
    api
      .reportStatus(taskId)
      .then((j) => active && setJob(j))
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [taskId]);

  // poll while a docx generation is in flight (every 5s, ~5min cap)
  React.useEffect(() => {
    if (job.status !== "generating") {
      if (pollRef.current) clearInterval(pollRef.current);
      return;
    }
    let ticks = 0;
    pollRef.current = setInterval(() => {
      ticks += 1;
      if (ticks > 60) {
        if (pollRef.current) clearInterval(pollRef.current);
        return;
      }
      api
        .reportStatus(taskId)
        .then((j) => {
          setJob(j);
          if (j.status === "failed") toast.error(t("taskDetail.report.genFailed", { msg: j.error ?? "" }));
        })
        .catch(() => {});
    }, 5000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [job.status, taskId, t]);

  function copy() {
    if (!report) return;
    navigator.clipboard?.writeText(report);
    setCopied(true);
    toast.success(t("taskDetail.report.copyToast"));
    setTimeout(() => setCopied(false), 1500);
  }

  function generate() {
    setJob({ status: "generating" });
    api
      .reportGenerate(taskId)
      .then((j) => {
        setJob(j);
        toast.success(t("taskDetail.report.genStarted"));
      })
      .catch((e) => {
        setJob({ status: "failed", error: (e as Error)?.message });
        toast.error(t("taskDetail.report.genFailed", { msg: (e as Error)?.message ?? "" }));
      });
  }

  function loadProjects() {
    if (projects) return; // cache for the session
    setProjErr("");
    api
      .aiReportProjects()
      .then((p) => setProjects(p))
      .catch((e) => setProjErr((e as Error)?.message ?? "error"));
  }

  function sendToAIReport(projectId?: string) {
    setPushing(true);
    api
      .pushAIReport(taskId, projectId)
      .then((r) => toast.success(t("taskDetail.report.aireportSent", { n: r.findings })))
      .catch((e) => toast.error(t("taskDetail.report.aireportFailed", { msg: (e as Error)?.message ?? "" })))
      .finally(() => setPushing(false));
  }

  const generating = job.status === "generating";

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-sm">
          <FileTextIcon className="size-4" /> {t("taskDetail.report.title")}
        </CardTitle>
        <div className="flex flex-wrap gap-2">
          {job.status === "done" ? (
            <Button size="sm" variant="outline" asChild>
              <a href={api.reportDownloadUrl(taskId)}>
                <DownloadIcon /> {t("taskDetail.report.download")}
              </a>
            </Button>
          ) : null}
          <Button size="sm" onClick={generate} disabled={generating}>
            {generating ? <Loader2Icon className="animate-spin" /> : <SparklesIcon />}
            {generating
              ? t("taskDetail.report.generating")
              : job.status === "done"
                ? t("taskDetail.report.regenerate")
                : t("taskDetail.report.generate")}
          </Button>
          {report && (
            <Button size="sm" variant="outline" onClick={copy}>
              {copied ? <CheckIcon /> : <CopyIcon />} {t("taskDetail.copy")}
            </Button>
          )}
          <DropdownMenu onOpenChange={(open) => open && loadProjects()}>
            <DropdownMenuTrigger asChild>
              <Button size="sm" variant="outline" disabled={pushing}>
                {pushing ? <Loader2Icon className="animate-spin" /> : <FileUpIcon />}
                {pushing ? t("taskDetail.report.aireportSending") : t("taskDetail.report.aireport")}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="max-h-80 w-64 overflow-auto">
              <DropdownMenuLabel>{t("taskDetail.report.aireportPick")}</DropdownMenuLabel>
              {projErr ? (
                <div className="text-destructive px-2 py-1.5 text-xs">{projErr}</div>
              ) : projects === null ? (
                <div className="text-muted-foreground px-2 py-1.5 text-xs">{t("common.loading")}</div>
              ) : projects.length === 0 ? (
                <div className="text-muted-foreground px-2 py-1.5 text-xs">{t("taskDetail.report.aireportNoProjects")}</div>
              ) : (
                projects.map((p) => (
                  <DropdownMenuItem key={p.id} onSelect={() => sendToAIReport(p.id)}>
                    <span className="flex flex-col">
                      <span className="text-sm">{p.name}</span>
                      {p.client_name && p.client_name !== p.name && (
                        <span className="text-muted-foreground text-xs">{p.client_name}</span>
                      )}
                    </span>
                  </DropdownMenuItem>
                ))
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => sendToAIReport()}>
                {t("taskDetail.report.aireportNoProject")}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-muted-foreground text-xs">{t("taskDetail.report.docxHint")}</p>
        {loading ? (
          <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-sm text-muted-foreground">
            <FileTextIcon className="size-8 opacity-40" />
            {t("common.loading")}
          </div>
        ) : report ? (
          <pre className="max-h-[60vh] overflow-auto rounded-md border bg-muted/40 p-4 font-mono text-xs whitespace-pre-wrap">
            {report}
          </pre>
        ) : (
          <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-sm text-muted-foreground">
            <FileTextIcon className="size-8 opacity-40" />
            {t("taskDetail.report.empty")}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
