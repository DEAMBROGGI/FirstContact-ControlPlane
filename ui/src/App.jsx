import { useEffect, useState } from "react";

const API = import.meta.env.VITE_API_BASE || "http://localhost:8080";

function App() {
  const [items, setItems] = useState([]);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");

  async function refresh() {
    try {
      const response = await fetch(`${API}/api/v1/publications`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      setItems(data);
      if (selected) {
        setSelected(data.find((item) => item.publication_id === selected.publication_id) || null);
      }
      setError("");
    } catch (err) {
      setError(String(err));
    }
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, []);
  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">FIRSTCONTACT DELIVERY AUTHORITY</p>
          <h1>Control Plane</h1>
        </div>
        <button onClick={refresh}>Refresh</button>
      </header>

      {error && <div className="error">{error}</div>}

      <section className="grid">
        <div className="panel">
          <h2>Publications</h2>
          {items.length === 0 && <p className="muted">No publications yet.</p>}
          {items.map((item) => (
            <button
              className="publication"
              key={item.publication_id}
              onClick={() => setSelected(item)}
            >
              <strong>{item.repository}</strong>
              <span>Issue #{item.issue_number}</span>
              <span className="state">{item.state}</span>
            </button>
          ))}
        </div>
        <div className="panel detail">
          <h2>Deterministic state</h2>
          {!selected && <p className="muted">Select a publication.</p>}
          {selected && (
            <dl>
              <dt>Publication</dt><dd>{selected.publication_id}</dd>
              <dt>State</dt><dd>{selected.state}</dd>
              <dt>Candidate</dt><dd>{selected.current_candidate?.head_sha || "—"}</dd>
              <dt>Remote head</dt><dd>{selected.remote_head_sha || "—"}</dd>
              <dt>Issue projection</dt><dd>{selected.projection.issue}</dd>
              <dt>PR projection</dt><dd>{selected.projection.pull_request}</dd>
              <dt>Project projection</dt><dd>{selected.projection.project}</dd>
            </dl>
          )}
        </div>
      </section>
    </main>
  );
}

export default App;
