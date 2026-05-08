import { useState } from "react";
import { FileCheck, Download } from "lucide-react";
import { exportReport } from "@/api/reporting";

interface FrameworkCard {
  id: "soc2" | "pci" | "nist";
  name: string;
  summary: string;
}

const FRAMEWORKS: FrameworkCard[] = [
  {
    id: "soc2",
    name: "SOC 2 Type II",
    summary:
      "CC6 (Logical Access), CC7 (System Operations), CC8 (Change Management). Evidence drawn from auth records, attack-state counts, and detection version history.",
  },
  {
    id: "pci",
    name: "PCI-DSS",
    summary:
      "Req 10 (Audit Logs) and Req 11 (Security Testing). Aggregated transition counts and detection coverage score.",
  },
  {
    id: "nist",
    name: "NIST CSF",
    summary:
      "Identify, Protect, Detect, Respond, Recover. Coverage by tactic, MTTR, and playbook completion rates.",
  },
];

export function CompliancePage() {
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastGenerated, setLastGenerated] = useState<Record<string, string>>({});

  async function generate(id: FrameworkCard["id"]) {
    setPending(id);
    setError(null);
    try {
      await exportReport(id, 30);
      setLastGenerated((cur) => ({ ...cur, [id]: new Date().toLocaleString() }));
    } catch (e) {
      setError(`Failed to generate ${id.toUpperCase()} report: ${(e as Error).message}`);
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="px-6 py-6 max-w-[1400px] mx-auto">
      <div className="mb-5 flex items-center gap-2">
        <FileCheck size={18} className="text-fg-muted" />
        <h1 className="text-xl font-mono text-fg">Compliance</h1>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-6">
        {FRAMEWORKS.map((f) => (
          <div key={f.id} className="vigil-card p-4 flex flex-col">
            <div className="font-mono text-fg text-sm mb-2">{f.name}</div>
            <div className="text-[12px] font-mono text-fg-muted mb-4 flex-1">
              {f.summary}
            </div>
            <div className="text-[11px] font-mono text-fg-faint mb-3">
              Last generated: {lastGenerated[f.id] ?? "—"}
            </div>
            <button
              onClick={() => generate(f.id)}
              disabled={pending === f.id}
              className="px-3 py-1.5 text-[12px] font-mono border border-accent/40 bg-accent/10 text-accent rounded-sm hover:bg-accent/20 disabled:opacity-50 flex items-center justify-center gap-2"
            >
              <Download size={11} />
              {pending === f.id ? "Generating…" : "Generate report"}
            </button>
          </div>
        ))}
      </div>

      {error && (
        <div className="vigil-card p-3 mb-4 text-accent font-mono text-sm">
          {error}
        </div>
      )}

      <div className="vigil-card p-5 max-w-3xl">
        <div className="font-mono text-fg text-sm mb-2">Initiating a SOC 2 Type II audit</div>
        <div className="font-mono text-[12px] text-fg-muted leading-6 space-y-2">
          <p>
            VIGIL's evidence pack covers the access, operations, and change-management
            criteria most commonly cited in a SOC 2 Type II audit. It is not a
            substitute for the audit itself.
          </p>
          <p>
            To proceed, engage a licensed CPA firm. Expect a typical timeline of
            6–12 months from engagement to attestation. The auditor will request:
          </p>
          <ul className="list-disc ml-5 space-y-1">
            <li>An auditable evidence-collection window of at least 6 months</li>
            <li>Documented policies (access control, change management, incident response)</li>
            <li>Continuous monitoring evidence — VIGIL's exports satisfy the SIEM portion</li>
            <li>Pen-test results from a separate firm</li>
          </ul>
          <p>
            Use the SOC 2 export above as the system-monitoring evidence pack.
            Pair it with your HR onboarding records, vendor management, and
            risk register for a complete submission.
          </p>
        </div>
      </div>
    </div>
  );
}
