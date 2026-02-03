import { useEffect, useState } from "react";
import { apiRequest } from "../lib/api";

type Workspace = {
  id: string;
  name: string;
};

export default function WorkspacesPage() {
  const [items, setItems] = useState<Workspace[]>([]);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function load() {
    setError(null);
    try {
      const data = await apiRequest<Workspace[]>("/v1/workspaces");
      setItems(data);
    } catch (err: any) {
      setError(err.message || "Failed to load workspaces");
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleCreate() {
    if (!name.trim()) return;
    setLoading(true);
    try {
      await apiRequest<Workspace>("/v1/workspaces", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      setName("");
      await load();
    } catch (err: any) {
      setError(err.message || "Failed to create workspace");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-xl font-display font-semibold">Workspaces</h2>
        <p className="text-mist/70">Create and manage investigation spaces.</p>
      </header>

      <div className="card p-4 space-y-3">
        <label className="text-sm text-mist/80">New workspace</label>
        <div className="flex flex-col md:flex-row gap-3">
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corp" />
          <button className="btn btn-primary" onClick={handleCreate} disabled={loading}>
            {loading ? "Creating..." : "Create"}
          </button>
        </div>
      </div>

      {error && <div className="text-ember text-sm">{error}</div>}

      <table className="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
          </tr>
        </thead>
        <tbody>
          {items.map((ws) => (
            <tr key={ws.id}>
              <td className="font-mono text-xs text-mist/80">{ws.id}</td>
              <td>{ws.name}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
