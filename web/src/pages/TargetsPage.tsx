import { useEffect, useState } from "react";
import { apiRequest } from "../lib/api";

type Workspace = { id: string; name: string };
type Target = {
  id: string;
  workspace_id: string;
  target_type: string;
  value: string;
  label?: string;
};

type CreatePayload = {
  type: "domain" | "email" | "username" | "ip";
  value: string;
  label?: string;
};

export default function TargetsPage() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [workspaceId, setWorkspaceId] = useState<string>("");
  const [targets, setTargets] = useState<Target[]>([]);
  const [payload, setPayload] = useState<CreatePayload>({ type: "domain", value: "" });
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiRequest<Workspace[]>("/v1/workspaces").then((data) => {
      setWorkspaces(data);
      if (!workspaceId && data.length > 0) {
        setWorkspaceId(data[0].id);
      }
    });
  }, []);

  useEffect(() => {
    if (!workspaceId) return;
    loadTargets();
  }, [workspaceId]);

  async function loadTargets() {
    setError(null);
    try {
      const data = await apiRequest<Target[]>(`/v1/workspaces/${workspaceId}/targets`);
      setTargets(data);
    } catch (err: any) {
      setError(err.message || "Failed to load targets");
    }
  }

  async function handleCreate() {
    if (!workspaceId || !payload.value.trim()) return;
    const path = `/v1/workspaces/${workspaceId}/targets/${payload.type}`;
    const body: any = { label: payload.label };
    if (payload.type === "domain") body.domain = payload.value;
    if (payload.type === "email") body.email = payload.value;
    if (payload.type === "username") body.username = payload.value;
    if (payload.type === "ip") body.ip = payload.value;

    try {
      await apiRequest(path, { method: "POST", body: JSON.stringify(body) });
      setPayload({ ...payload, value: "", label: "" });
      await loadTargets();
    } catch (err: any) {
      setError(err.message || "Failed to create target");
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-xl font-display font-semibold">Targets</h2>
        <p className="text-mist/70">Add domains, emails, usernames, or IPs.</p>
      </header>

      <div className="card p-4 space-y-3">
        <label className="text-sm text-mist/80">Workspace</label>
        <select className="input" value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)}>
          {workspaces.map((ws) => (
            <option key={ws.id} value={ws.id}>
              {ws.name}
            </option>
          ))}
        </select>

        <div className="grid grid-cols-1 md:grid-cols-[140px_1fr_1fr] gap-3">
          <select
            className="input"
            value={payload.type}
            onChange={(e) => setPayload({ ...payload, type: e.target.value as CreatePayload["type"] })}
          >
            <option value="domain">Domain</option>
            <option value="email">Email</option>
            <option value="username">Username</option>
            <option value="ip">IP</option>
          </select>
          <input
            className="input"
            value={payload.value}
            onChange={(e) => setPayload({ ...payload, value: e.target.value })}
            placeholder="example.com"
          />
          <input
            className="input"
            value={payload.label || ""}
            onChange={(e) => setPayload({ ...payload, label: e.target.value })}
            placeholder="Label (optional)"
          />
        </div>
        <button className="btn btn-primary" onClick={handleCreate}>Add target</button>
      </div>

      {error && <div className="text-ember text-sm">{error}</div>}

      <table className="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Value</th>
            <th>Label</th>
          </tr>
        </thead>
        <tbody>
          {targets.map((t) => (
            <tr key={t.id}>
              <td className="font-mono text-xs text-mist/80">{t.id}</td>
              <td>{t.target_type}</td>
              <td>{t.value}</td>
              <td>{t.label || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
