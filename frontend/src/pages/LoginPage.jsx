import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, newRunId } from "../api.js";
import Card from "../Card.jsx";

export default function LoginPage({ onLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    // One denial message no matter which step actually failed, deliberately:
    // the Verifier and RP never distinguish "unknown identifier" from "wrong
    // secret" in their own responses either, and this UI shouldn't add that
    // distinction back for an attacker probing which emails are enrolled.
    const denial = "Invalid email or password.";
    try {
      const runId = newRunId();

      const authResult = await api.authenticate(runId, email, password);
      if (authResult.status !== 200 || !authResult.data?.assertion) {
        setError(denial);
        return;
      }

      const sessionResult = await api.establishSession(runId, authResult.data.assertion);
      if (sessionResult.status !== 201 || !sessionResult.data?.session) {
        setError(denial);
        return;
      }

      onLogin({
        session: sessionResult.data.session,
        runId,
        identifier: sessionResult.data.identifier,
      });
      navigate("/protected");
    } catch {
      setError("Something went wrong. Please try again in a moment.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <h1>Log in</h1>
      <p>Enter your email and password to sign in.</p>

      {error && <div className="banner error">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
          />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </div>
        <button className="btn" type="submit" disabled={busy}>
          {busy ? "Logging in..." : "Log in"}
        </button>
      </form>

      <p className="small-text" style={{ marginTop: "36px" }}>
        Need an account? <Link to="/signup">Sign up</Link>
      </p>
    </Card>
  );
}
