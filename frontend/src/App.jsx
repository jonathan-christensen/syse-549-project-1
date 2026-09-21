import { Route, Routes } from "react-router-dom";
import SignupPage from "./pages/SignupPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import ProtectedPage from "./pages/ProtectedPage.jsx";
import { useSession } from "./useSession.js";

export default function App() {
  const [session, setSession] = useSession();

  return (
    <Routes>
      <Route path="/" element={<LoginPage onLogin={setSession} />} />
      <Route path="/signup" element={<SignupPage />} />
      <Route path="/login" element={<LoginPage onLogin={setSession} />} />
      <Route
        path="/protected"
        element={<ProtectedPage session={session} onLogout={() => setSession(null)} />}
      />
    </Routes>
  );
}
