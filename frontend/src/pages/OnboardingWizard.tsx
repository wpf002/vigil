import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { Check, Loader2, ChevronRight, ChevronLeft } from "lucide-react";
import {
  checkConnection,
  markOnboardingComplete,
  seedDemo,
  type ConnectionParams,
  type ConnectionResult,
  type SIEMType,
} from "@/api/onboarding";

const SIEM_OPTIONS: { id: SIEMType; name: string; tag: string; eta: string }[] = [
  { id: "splunk_es", name: "Splunk ES", tag: "SPLUNK", eta: "~5 minutes" },
  { id: "splunk_core", name: "Splunk Core", tag: "SPLUNK", eta: "~5 minutes" },
  { id: "sentinel", name: "Microsoft Sentinel", tag: "AZURE", eta: "~5 minutes" },
  { id: "elastic", name: "Elastic", tag: "ELASTIC", eta: "~5 minutes" },
];

const PLATFORM_DETECTIONS = [
  { id: "D1", name: "Brute force credential access", tactic: "Credential Access" },
  { id: "D2", name: "Credential dumping (LSASS)", tactic: "Credential Access" },
  { id: "D3", name: "SMB lateral movement", tactic: "Lateral Movement" },
  { id: "D4", name: "Pass-the-hash detection", tactic: "Lateral Movement" },
];

export function OnboardingWizard() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [siem, setSiem] = useState<SIEMType | null>(null);
  const [params, setParams] = useState<ConnectionParams>({ siem_type: "splunk_es" });
  const [test, setTest] = useState<ConnectionResult | null>(null);

  const testMut = useMutation<ConnectionResult, Error, void>({
    mutationFn: () => checkConnection({ ...params, siem_type: siem! }),
    onSuccess: setTest,
  });
  const seedMut = useMutation({ mutationFn: seedDemo });
  const completeMut = useMutation({
    mutationFn: markOnboardingComplete,
    onSuccess: () => navigate("/dashboard"),
  });

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center p-6">
      <div className="w-full max-w-3xl">
        <div className="mb-6 flex items-center gap-2">
          <span className="inline-block w-2 h-2 rounded-sm bg-accent" />
          <span className="font-mono text-[13px] tracking-[0.3em] text-fg">VIGIL</span>
          <span className="ml-3 text-[12px] font-mono text-fg-faint">
            Onboarding · Step {step} of 4
          </span>
        </div>

        <div className="vigil-card p-6">
          {step === 1 && (
            <Step1
              selected={siem}
              onSelect={(s) => {
                setSiem(s);
                setParams({ siem_type: s });
                setTest(null);
              }}
            />
          )}
          {step === 2 && (
            <Step2
              siem={siem!}
              params={params}
              setParams={setParams}
              test={test}
              testing={testMut.isPending}
              onTest={() => testMut.mutate()}
            />
          )}
          {step === 3 && <Step3 />}
          {step === 4 && (
            <Step4
              seedPending={seedMut.isPending}
              seedDone={seedMut.isSuccess}
              onSeed={() => seedMut.mutate()}
              completePending={completeMut.isPending}
              onComplete={() => completeMut.mutate()}
            />
          )}

          <div className="mt-6 flex items-center justify-between">
            <button
              onClick={() => setStep((s) => Math.max(1, s - 1))}
              disabled={step === 1}
              className="px-3 py-1.5 border border-border bg-surface-2 text-fg-muted hover:text-fg rounded-sm font-mono text-sm flex items-center gap-2 disabled:opacity-30"
            >
              <ChevronLeft size={12} />
              Back
            </button>
            {step < 4 && (
              <button
                onClick={() => setStep((s) => s + 1)}
                disabled={
                  (step === 1 && !siem) ||
                  (step === 2 && !test?.connected)
                }
                className="px-3 py-1.5 border border-accent/40 bg-accent/10 text-accent rounded-sm font-mono text-sm flex items-center gap-2 disabled:opacity-30"
              >
                Next
                <ChevronRight size={12} />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Step1({
  selected,
  onSelect,
}: {
  selected: SIEMType | null;
  onSelect: (s: SIEMType) => void;
}) {
  return (
    <div>
      <h2 className="font-mono text-fg text-lg mb-2">Connect your SIEM in 3 steps.</h2>
      <p className="font-mono text-[12px] text-fg-muted mb-5">
        VIGIL ingests, normalizes, and correlates alerts from your existing SIEM.
        Pick the one your team uses.
      </p>
      <div className="grid grid-cols-2 gap-3">
        {SIEM_OPTIONS.map((o) => (
          <button
            key={o.id}
            onClick={() => onSelect(o.id)}
            className={`text-left p-4 border rounded-sm transition-colors ${
              selected === o.id
                ? "border-accent/60 bg-accent/5"
                : "border-border bg-surface-2 hover:border-fg-muted"
            }`}
          >
            <div className="flex items-center gap-2 mb-2">
              <div className="w-8 h-8 bg-surface rounded-sm flex items-center justify-center font-mono text-[10px] text-fg-faint">
                {o.tag}
              </div>
              <div className="font-mono text-sm text-fg">{o.name}</div>
            </div>
            <div className="text-[11px] font-mono text-fg-faint">{o.eta}</div>
          </button>
        ))}
      </div>
    </div>
  );
}

function Step2({
  siem,
  params,
  setParams,
  test,
  testing,
  onTest,
}: {
  siem: SIEMType;
  params: ConnectionParams;
  setParams: (p: ConnectionParams) => void;
  test: ConnectionResult | null;
  testing: boolean;
  onTest: () => void;
}) {
  function set<K extends keyof ConnectionParams>(k: K, v: ConnectionParams[K]) {
    setParams({ ...params, [k]: v });
  }

  return (
    <div>
      <h2 className="font-mono text-fg text-lg mb-3">Connection details</h2>

      {(siem === "splunk_es" || siem === "splunk_core") && (
        <div className="space-y-3">
          <Field label="Host URL" value={params.host} onChange={(v) => set("host", v)}
                 placeholder="https://splunk.example.com:8089" />
          <Field label="Username" value={params.username} onChange={(v) => set("username", v)} />
          <Field label="Password or token" type="password"
                 value={params.password} onChange={(v) => set("password", v)} />
        </div>
      )}

      {siem === "sentinel" && (
        <div className="space-y-3">
          <Field label="Tenant ID" value={params.tenant_id} onChange={(v) => set("tenant_id", v)} />
          <Field label="Client ID" value={params.client_id} onChange={(v) => set("client_id", v)} />
          <Field label="Client secret" type="password"
                 value={params.client_secret} onChange={(v) => set("client_secret", v)} />
          <Field label="Subscription ID" value={params.subscription_id} onChange={(v) => set("subscription_id", v)} />
          <Field label="Resource group" value={params.resource_group} onChange={(v) => set("resource_group", v)} />
          <Field label="Workspace name" value={params.workspace_name} onChange={(v) => set("workspace_name", v)} />
        </div>
      )}

      {siem === "elastic" && (
        <div className="space-y-3">
          <Field label="Elasticsearch URL" value={params.elastic_url} onChange={(v) => set("elastic_url", v)}
                 placeholder="https://es.example:9200" />
          <Field label="API key ID" value={params.api_key_id} onChange={(v) => set("api_key_id", v)} />
          <Field label="API key secret" type="password"
                 value={params.api_key_secret} onChange={(v) => set("api_key_secret", v)} />
        </div>
      )}

      <button
        onClick={onTest}
        disabled={testing}
        className="mt-4 px-3 py-1.5 border border-accent/40 bg-accent/10 text-accent rounded-sm font-mono text-sm flex items-center gap-2"
      >
        {testing && <Loader2 size={12} className="animate-spin" />}
        Test connection
      </button>

      {test && (
        <div
          className={`mt-3 p-3 rounded-sm font-mono text-[12px] ${
            test.connected
              ? "border border-success/40 bg-success/10 text-success"
              : "border border-accent/40 bg-accent/10 text-accent"
          }`}
        >
          {test.connected ? (
            <span className="flex items-center gap-1">
              <Check size={11} />
              Connected{test.version ? ` to v${test.version}` : ""}
            </span>
          ) : (
            <>{test.error ?? "Connection failed"}</>
          )}
        </div>
      )}
    </div>
  );
}

function Step3() {
  return (
    <div>
      <h2 className="font-mono text-fg text-lg mb-3">Detections</h2>
      <p className="font-mono text-[12px] text-fg-muted mb-5">
        These detections are compiled and deployed to your SIEM automatically.
        You can add more from the Detection Marketplace at any time.
      </p>
      <div className="space-y-2">
        {PLATFORM_DETECTIONS.map((d) => (
          <div key={d.id} className="flex items-center gap-3 p-3 border border-border rounded-sm bg-surface-2">
            <div className="font-mono text-fg text-sm flex-1">{d.name}</div>
            <span className="vigil-badge border-border bg-surface text-fg-muted">
              {d.tactic}
            </span>
            <span className="vigil-badge border-success/40 bg-success/10 text-success">
              Included
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Step4({
  seedPending,
  seedDone,
  onSeed,
  completePending,
  onComplete,
}: {
  seedPending: boolean;
  seedDone: boolean;
  onSeed: () => void;
  completePending: boolean;
  onComplete: () => void;
}) {
  return (
    <div>
      <h2 className="font-mono text-fg text-lg mb-3">VIGIL is active.</h2>
      <p className="font-mono text-[12px] text-fg-muted mb-5">
        Waiting for first signal from your SIEM. You can seed demo data to see
        the full attack-state lifecycle in action.
      </p>

      <div className="space-y-3">
        <button
          onClick={onSeed}
          disabled={seedPending || seedDone}
          className="w-full px-3 py-2 border border-border bg-surface-2 text-fg hover:border-fg-muted rounded-sm font-mono text-sm disabled:opacity-50"
        >
          {seedPending ? "Publishing demo signals…" : seedDone ? "Demo data published" : "Seed demo data"}
        </button>

        <a
          href="/marketplace"
          className="block text-center px-3 py-2 border border-border bg-surface-2 text-fg-muted hover:text-fg rounded-sm font-mono text-sm"
        >
          Browse Detection Marketplace
        </a>

        <button
          onClick={onComplete}
          disabled={completePending}
          className="w-full px-3 py-2 border border-accent/40 bg-accent/10 text-accent rounded-sm font-mono text-sm disabled:opacity-50"
        >
          {completePending ? "Finishing…" : "Finish onboarding"}
        </button>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
}: {
  label: string;
  value?: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
}) {
  return (
    <div>
      <label className="block text-[11px] font-mono text-fg-muted mb-1">{label}</label>
      <input
        type={type}
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full px-3 py-1.5 bg-surface-2 border border-border text-fg font-mono text-sm rounded-sm"
      />
    </div>
  );
}
