import { useCallback, useState } from "react";

const STORAGE_KEY = "lab1-session";

function load() {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

// Session state lives in sessionStorage, not localStorage: it should not
// outlive the tab, matching the RP's own session TTL model.
export function useSession() {
  const [session, setSessionState] = useState(load);

  const setSession = useCallback((next) => {
    setSessionState(next);
    try {
      if (next) {
        sessionStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      } else {
        sessionStorage.removeItem(STORAGE_KEY);
      }
    } catch {
      // Storage unavailable (private mode, etc). State still works for
      // this render; it just won't survive a refresh.
    }
  }, []);

  return [session, setSession];
}
