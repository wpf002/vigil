import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { register } from "@/api/auth";
import { useAuthStore } from "@/store/authStore";

const PASSWORD_RULES = [
  "At least 12 characters",
  "One uppercase letter",
  "One number",
  "One special character",
];

export function RegisterPage() {
  const navigate = useNavigate();
  const setSession = useAuthStore((s) => s.setSession);

  const [tenant, setTenant] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const result = await register(email, password, tenant);
      setSession(result.access_token, result.refresh_token, result.user);
      navigate("/attacks", { replace: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Registration failed";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2 mb-6 justify-center">
          <ShieldAlert className="text-accent" size={20} />
          <span className="font-mono text-sm tracking-[0.3em] text-fg">VIGIL</span>
        </div>

        <form
          onSubmit={onSubmit}
          className="bg-surface border border-border rounded p-6 space-y-4"
        >
          <h1 className="font-mono text-base text-fg">Register organization</h1>

          <Field label="Organization" value={tenant} onChange={setTenant} required autoFocus />
          <Field label="Email" type="email" value={email} onChange={setEmail} required />
          <Field
            label="Password"
            type="password"
            value={password}
            onChange={setPassword}
            required
          />

          <ul className="text-[10px] font-mono text-fg-faint pl-3 space-y-0.5">
            {PASSWORD_RULES.map((r) => (
              <li key={r}>• {r}</li>
            ))}
          </ul>

          {error && (
            <p className="text-red-400 text-xs font-mono">{error}</p>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full bg-accent text-white font-mono text-sm py-2 rounded-sm
                       hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed
                       transition-colors"
          >
            {submitting ? "Creating…" : "Create organization"}
          </button>

          <p className="text-xs font-mono text-fg-muted text-center">
            Already have an account?{" "}
            <a href="/login" className="text-accent-hover hover:underline">
              Sign in
            </a>
          </p>
        </form>
      </div>
    </div>
  );
}

function Field({
  label,
  type = "text",
  value,
  onChange,
  required,
  autoFocus,
}: {
  label: string;
  type?: string;
  value: string;
  onChange: (v: string) => void;
  required?: boolean;
  autoFocus?: boolean;
}) {
  return (
    <label className="block">
      <span className="block text-[10px] uppercase tracking-[0.18em] text-fg-faint font-mono mb-1">
        {label}
      </span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required={required}
        autoFocus={autoFocus}
        className="w-full bg-[#111118] border border-[#1e1e2e] rounded-sm px-3 py-2 text-sm
                   text-white placeholder:text-fg-faint
                   focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500"
      />
    </label>
  );
}
