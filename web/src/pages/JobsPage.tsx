import { useEffect, useState } from "react";
import { apiRequest } from "../lib/api";

type Workspace = { id: string; name: string };
type Target = { id: string; value: string; target_type: string };
type Job = {
  id: string;
  technique_code: string;
  status: string;
  created_at: string;
  target_id: string;
  error_message?: string;
};

type ApiV1 = { enabled_techniques: string[] };

export default function JobsPage() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [workspaceId, setWorkspaceId] = useState<string>("");
  const [targets, setTargets] = useState<Target[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [techniques, setTechniques] = useState<string[]>([]);
  const [targetId, setTargetId] = useState<string>("");
  const [technique, setTechnique] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiRequest<Workspace[]>("/v1/workspaces").then((data) => {
      setWorkspaces(data);
      if (!workspaceId && data.length > 0) {
        setWorkspaceId(data[0].id);
      }
    });
    apiRequest<ApiV1>("/v1").then((data) => {
      setTechniques(data.enabled_techniques || []);
      if (!technique && data.enabled_techniques?.length) {
        setTechnique(data.enabled_techniques[0]);
      }
    });
  }, []);

  useEffect(() => {
    if (!workspaceId) return;
    loadTargets();
    loadJobs();
  }, [workspaceId]);

  async function loadTargets() {
    try {
      const data = await apiRequest<Target[]>(`/v1/workspaces/${workspaceId}/targets`);
      setTargets(data);
      if (!targetId && data.length > 0) {
        setTargetId(data[0].id);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load targets");
    }
  }

  async function loadJobs() {
    try {
      const data = await apiRequest<Job[]>(`/v1/workspaces/${workspaceId}/jobs`);
      setJobs(data);
    } catch (err: any) {
      setError(err.message || "Failed to load jobs");
    }
  }

  async function handleCreate() {
    if (!workspaceId || !targetId || !technique) return;
    setError(null);
    try {
      await apiRequest(`/v1/workspaces/${workspaceId}/jobs`, {
        method: "POST",
        body: JSON.stringify({ target_id: targetId, technique_code: technique }),
      });
      await loadJobs();
    } catch (err: any) {
      setError(err.message || "Failed to create job");
    }
  }

  async function action(jobId: string, op: "enqueue" | "requeue" | "cancel") {
    try {
      await apiRequest(`/v1/workspaces/${workspaceId}/jobs/${jobId}/${op}`, { method: "POST" });
      await loadJobs();
    } catch (err: any) {
      setError(err.message || `Failed to ${op} job`);
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-xl font-display font-semibold">Jobs</h2>
        <p className="text-mist/70">Create and execute OSINT techniques.</p>
      </header>

      <div className="card p-4 space-y-3">
        <label className="text-sm text-mist/80">Workspace</label>
        <select className="input" value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)}>
          {workspaces.map((ws) => (
            <option key={ws.id} value={ws.id}>{ws.name}</option>
          ))}
        </select>

        <div className="grid grid-cols-1 md:grid-cols-[1fr_1fr_auto] gap-3">
          <select className="input" value={targetId} onChange={(e) => setTargetId(e.target.value)}>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>{t.value}</option>
            ))}
          </select>
          <select className="input" value={technique} onChange={(e) => setTechnique(e.target.value)}>
            {techniques.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <button className="btn btn-primary" onClick={handleCreate}>Create job</button>
        </div>
      </div>

      {error && <div className="text-ember text-sm">{error}</div>}

      <table className="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Technique</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((job) => (
            <tr key={job.id}>
              <td className="font-mono text-xs text-mist/80">{job.id}</td>
              <td>{job.technique_code}</td>
              <td>{job.status}</td>
              <td className="space-x-2">
                <button className="btn btn-secondary" onClick={() => action(job.id, "enqueue")}>Enqueue</button>
                <button className="btn btn-secondary" onClick={() => action(job.id, "requeue")}>Requeue</button>
                <button className="btn btn-secondary" onClick={() => action(job.id, "cancel")}>Cancel</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
