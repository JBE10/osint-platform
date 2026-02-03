import { useEffect, useState } from "react";
import { apiRequest } from "../lib/api";

type Workspace = { id: string; name: string };
type Finding = {
  id: string;
  finding_type: string;
  subject: string;
  confidence: number;
  target_id: string;
  job_id: string;
  data_json?: any;
};

export default function FindingsPage() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [workspaceId, setWorkspaceId] = useState<string>("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filters, setFilters] = useState({
    finding_type: "",
    subject: "",
    target_id: "",
    job_id: "",
    min_confidence: "0",
  });
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiRequest<Workspace[]>("/v1/workspaces").then((data) => {
      setWorkspaces(data);
      if (!workspaceId && data.length > 0) setWorkspaceId(data[0].id);
    });
  }, []);

  useEffect(() => {
    if (workspaceId) load();
  }, [workspaceId]);

  async function load() {
    setError(null);
    try {
      const params = new URLSearchParams();
      Object.entries(filters).forEach(([k, v]) => {
        if (v) params.set(k, v);
      });
      const data = await apiRequest<Finding[]>(
        `/v1/workspaces/${workspaceId}/findings?${params.toString()}`
      );
      setFindings(data);
    } catch (err: any) {
      setError(err.message || "Failed to load findings");
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-xl font-display font-semibold">Findings</h2>
        <p className="text-mist/70">Review normalized results.</p>
      </header>

      <div className="card p-4 space-y-3">
        <label className="text-sm text-mist/80">Workspace</label>
        <select className="input" value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)}>
          {workspaces.map((ws) => (
            <option key={ws.id} value={ws.id}>{ws.name}</option>
          ))}
        </select>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <input className="input" placeholder="Finding type" value={filters.finding_type}
            onChange={(e) => setFilters({ ...filters, finding_type: e.target.value })} />
          <input className="input" placeholder="Subject" value={filters.subject}
            onChange={(e) => setFilters({ ...filters, subject: e.target.value })} />
          <input className="input" placeholder="Target ID" value={filters.target_id}
            onChange={(e) => setFilters({ ...filters, target_id: e.target.value })} />
          <input className="input" placeholder="Job ID" value={filters.job_id}
            onChange={(e) => setFilters({ ...filters, job_id: e.target.value })} />
          <input className="input" placeholder="Min confidence" value={filters.min_confidence}
            onChange={(e) => setFilters({ ...filters, min_confidence: e.target.value })} />
        </div>
        <button className="btn btn-primary" onClick={load}>Apply filters</button>
      </div>

      {error && <div className="text-ember text-sm">{error}</div>}

      <table className="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Subject</th>
            <th>Confidence</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.id}>
              <td className="font-mono text-xs text-mist/80">{f.id}</td>
              <td>{f.finding_type}</td>
              <td>{f.subject}</td>
              <td>{f.confidence}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
