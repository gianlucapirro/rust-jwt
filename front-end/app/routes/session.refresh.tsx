// app/routes/auth.refresh.tsx
import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { AuthService } from "~/api/services/AuthService";

export default function AuthRefreshPage() {
  const [searchParams] = useSearchParams();
  const next = searchParams.get("next") || "/";
  const navigate = useNavigate();
  const [msg, setMsg] = useState("Refreshing session...");

  useEffect(() => {
    (async () => {
      try {
        await AuthService.refresh();
        navigate("/");
      } catch (e) {
        setMsg("Session expired. Redirecting to login...");
        navigate(`/login?next=${encodeURIComponent(next)}`, { replace: true });
      }
    })();
  }, [navigate, next]);

  return <div className="p-6 text-center">{msg}</div>;
}
