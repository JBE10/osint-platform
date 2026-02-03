import { NavLink, Outlet } from "react-router-dom";

const navItems = [
  { to: "/workspaces", label: "Workspaces" },
  { to: "/targets", label: "Targets" },
  { to: "/jobs", label: "Jobs" },
  { to: "/findings", label: "Findings" },
  { to: "/evidence", label: "Evidence" },
];

export function Layout({ children, onLogout }: { children?: React.ReactNode; onLogout: () => void }) {
  return (
    <div className="min-h-screen pattern-grid">
      <div className="max-w-7xl mx-auto px-6 py-8">
        <header className="flex items-center justify-between mb-8">
          <div>
            <p className="text-mist/70 text-sm">OSINT Platform</p>
            <h1 className="text-3xl font-display font-semibold">Control Room</h1>
          </div>
          <button className="btn btn-secondary" onClick={onLogout}>Logout</button>
        </header>
        <div className="grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-6">
          <aside className="card p-4">
            <nav className="flex flex-col gap-2">
              {navItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `rounded-xl px-3 py-2 text-sm font-medium transition ${
                      isActive ? "bg-ember text-ink" : "text-sand/80 hover:bg-white/10"
                    }`
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </nav>
          </aside>
          <main className="card p-6 animate-fadeUp">
            {children ?? <Outlet />}
          </main>
        </div>
      </div>
    </div>
  );
}
