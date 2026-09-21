import { useState } from "react";
import { Link } from "react-router-dom";
import { api, newRunId } from "../api.js";
import Card from "../Card.jsx";

// NIST SP 800-63B-4 SS3.1.1.2: a password used as the sole authentication
// factor SHALL be at least 15 characters. The CSP enforces this server-side
// (shared/validate.py); this is just an earlier, friendlier version of the
// same rule.
const MIN_LENGTH = 15;

export default function SignupPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setResult(null);

    if (password.length < MIN_LENGTH) {
      setError(`Your password must be at least ${MIN_LENGTH} characters.`);
      return;
    }

    setBusy(true);
    try {
      const runId = newRunId();
      const { status, data } = await api.applyForAccount(runId, email, password);
      if (status === 201) {
        setResult({ email });
      } else if (status === 409) {
        setError("An account for this email already exists.");
      } else if (status === 400 && data?.error === "invalid_password") {
        setError(
          `Password must be between ${data.min_length} and ${data.max_length} characters.`,
        );
      } else {
        setError("Sign up failed. Check the email address and try again.");
      }
    } catch {
      setError("Something went wrong. Please try again in a moment.");
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    return (
      <Card>
        <h1>Check your email</h1>
        <p>
          We sent a confirmation link to <strong>{result.email}</strong>. Click it to
          finish setting up your account.
        </p>
        <p className="small-text">
          Already confirmed your account? <Link to="/login">Log in</Link>
        </p>
      </Card>
    );
  }

  return (
    <Card>
      <h1>Create your account</h1>
      <p>Sign up for SYSE 549 Drive</p>

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
            autoComplete="new-password"
          />
          <p className="hint">At least {MIN_LENGTH} characters.</p>
        </div>
        <button className="btn" type="submit" disabled={busy}>
          {busy ? "Signing up..." : "Sign up"}
        </button>
      </form>

      <p className="small-text">
        Already have an account? <Link to="/login">Log in</Link>
      </p>
    </Card>
  );
}
