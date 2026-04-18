import { useState } from "react";

const ADMIN_USERNAME = "admin";
const ADMIN_PASSWORD = "admin123";

export default function AdminLogin({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    setError("");

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      onLogin({ username });
      return;
    }

    setError("Invalid credentials. Try admin / admin123.");
  };

  return (
    <div className="soar-container">
      <div className="card login-card">
        <h2>Admin Login</h2>
        <p className="muted">Sign in to access the SOAR dashboard.</p>

        <form onSubmit={handleSubmit}>
          <div className="form-row">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter admin username"
            />
          </div>

          <div className="form-row">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
            />
          </div>

          {error ? <p className="error-text">{error}</p> : null}
          <button type="submit">Login</button>
        </form>
      </div>
    </div>
  );
}
