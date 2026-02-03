import { useEffect, useState } from "react";
import { apiRequest } from "../lib/api";

type Workspace = { id: string; name: string };
type Evidence = {
  id: string;
  job_id: string;
  storage_uri: string;
  source: string;
  captured_at: string;
  size_bytes?: number;
};

export default function EvidencePage() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [workspaceId, setWorkspaceId] = useState<string>("");
  const [items, setItems] = useState<Evidence[]>([]);
  const [filters, setFilters] = useState({ job_id: "", source: "" });
  const [content, setContent] = useState<any>(null);
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
      if (filters.job_id) params.set("job_id", filters.job_id);
      if (filters.source) params.set("source", filters.source);
      const data = await apiRequest<Evidence[]>(`/v1/workspaces/${workspaceId}/evidence?${params}`);
      setItems(data);
    } catch (err: any) {
      setError(err.message || "Failed to load evidence");
    }
  }

  async function viewContent(evidenceId: string) {
    try {
      const data = await apiRequest<{ content: any }>(`/v1/workspaces/${workspaceId}/evidence/${evidenceId}/content`);
      setContent(data.content);
    } catch (err: any) {
      setError(err.message || "Failed to load content (admin only)");
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-xl font-display font-semibold">Evidence</h2>
        <p className="text-mist/70">Immutable raw evidence store.</p>
      </header>

      <div className="card p-4 space-y-3">
        <label className="text-sm text-mist/80">Workspace</label>
        <select className="input" value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)}>
          {workspaces.map((ws) => (
            <option key={ws.id} value={ws.id}>{ws.name}</option>
          ))}
        </select>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <input className="input" placeholder="Job ID" value={filters.job_id}
            onChange={(e) => setFilters({ ...filters, job_id: e.target.value })} />
          <input className="input" placeholder="Source" value={filters.source}
            onChange={(e) => setFilters({ ...filters, source: e.target.value })} />
        </div>
        <button className="btn btn-primary" onClick={load}>Apply filters</button>
      </div>

      {error && <div className="text-ember text-sm">{error}</div>}

      <table className="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Source</th>
            <th>Captured</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.id}>
              <td className="font-mono text-xs text-mist/80">{e.id}</td>
              <td>{e.source}</td>
              <td>{new Date(e.captured_at).toLocaleString()}</td>
              <td>
                <button className="btn btn-secondary" onClick={() => viewContent(e.id)}>
                  View content
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {content && (
        <div className="card p-4">
          <h3 className="font-display mb-2">Evidence content</h3>
          <pre className="text-xs text-mist/80 overflow-auto max-h-80">
            {JSON.stringify(content, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
