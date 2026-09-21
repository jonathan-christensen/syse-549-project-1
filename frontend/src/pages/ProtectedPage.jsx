import { useEffect, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { api } from "../api.js";
import Card from "../Card.jsx";

export default function ProtectedPage({ session, onLogout }) {
  const [state, setState] = useState({ loading: true, resource: null, error: null });
  const navigate = useNavigate();

  useEffect(() => {
    if (!session) return;
    let cancelled = false;
    api
      .protectedResource(session.runId, session.session)
      .then(({ status, data }) => {
        if (cancelled) return;
        if (status === 200) {
          setState({ loading: false, resource: data, error: null });
        } else {
          // The session the RP issued is no longer good (expired, revoked,
          // or refused). Drop it locally and send the subscriber back
          // through the front door rather than showing a dead page.
          onLogout();
          navigate("/login");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setState({
            loading: false,
            resource: null,
            error: "Something went wrong. Please try again in a moment.",
          });
        }
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  if (!session) {
    return <Navigate to="/login" replace />;
  }

  async function handleLogout() {
    await api.logout(session.runId, session.session);
    onLogout();
    navigate("/");
  }

  return (
    <Card>
      <h1>Welcome back</h1>
      {state.loading && <p>Loading...</p>}
      {state.error && <div className="banner error">{state.error}</div>}
      {state.resource && (
        <>
          <p>You're signed in, so we can show you this page.</p>
          <div className="resource">
            <div>
              <strong>Signed in as:</strong> {state.resource.subscriber}
            </div>
            <div style={{ marginTop: 8 }}>{state.resource.content}</div>
            <div style={{ marginTop: 8, color: "#9ca3af" }}>
              You'll be signed out automatically at {state.resource.session_expires_at}
            </div>
          </div>
        </>
      )}
      <button className="btn" onClick={handleLogout}>
        Log out
      </button>
    </Card>
  );
}
