"use client";

import { useEffect, useRef, useState } from "react";
import { inspectTarget } from "@/lib/api";
import ReportSummary from "./components/ReportSummary";
import Findings from "./components/Findings";
import ChainTree from "./components/ChainTree";

// badssl.com hosts deliberately broken setups; good for seeing every kind of warning.
const EXAMPLES = [
  "github.com",
  "expired.badssl.com",
  "self-signed.badssl.com",
  "wrong.host.badssl.com",
  "untrusted-root.badssl.com",
  "tls-v1-0.badssl.com:1010",
];

export default function Home() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const pending = useRef(null);

  async function run(value) {
    const trimmed = value.trim();
    if (!trimmed) return;

    // A new request cancels the previous one, so a slow old answer can't overwrite a newer one.
    pending.current?.abort();
    const controller = new AbortController();
    pending.current = controller;

    setTarget(trimmed);
    // Keep the target in the URL so a result can be bookmarked or shared.
    window.history.replaceState(null, "", `?target=${encodeURIComponent(trimmed)}`);
    setLoading(true);
    setError(null);
    try {
      setReport(await inspectTarget(trimmed, controller.signal));
    } catch (e) {
      if (e.name === "AbortError") return;
      setReport(null);
      setError(e.message);
    }
    setLoading(false);
  }

  useEffect(() => {
    const initial = new URLSearchParams(window.location.search).get("target");
    if (initial) run(initial);
  }, []);

  return (
    <main className="page">
      <header className="hero">
        <h1>SSL Inspector</h1>
        <p className="muted">
          Check a server&apos;s certificate chain, protocol and cipher, and get an A+ to F grade.
        </p>
      </header>

      <form
        className="search"
        onSubmit={(e) => {
          e.preventDefault();
          run(target);
        }}
      >
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="example.com, host:port or https://…"
          aria-label="Domain to inspect"
          autoFocus
          spellCheck={false}
          autoCapitalize="off"
          maxLength={300}
        />
        <button type="submit" disabled={loading || !target.trim()}>
          {loading ? "Inspecting…" : "Inspect"}
        </button>
      </form>

      <div className="examples">
        <span className="muted">Try:</span>
        {EXAMPLES.map((ex) => (
          <button key={ex} type="button" className="chip" onClick={() => run(ex)} disabled={loading}>
            {ex}
          </button>
        ))}
      </div>

      <div className={`results ${loading ? "results-loading" : ""}`} aria-live="polite" aria-busy={loading}>
        {error && <div className="error card">{error}</div>}
        {report && (
          <>
            <ReportSummary report={report} />
            <Findings findings={report.findings} />
            <ChainTree report={report} />
          </>
        )}
      </div>
    </main>
  );
}
