import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { AuthService } from "~/api/services/AuthService";

export function shouldRevalidate() {
  return false;
}

export default function GoogleCallbackPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const code = searchParams.get("code") ?? undefined;
    if (!code) {
      setError("Missing authorization code");
      return;
    }

    async function handleGoogleLogin() {
      try {
        // Perform the Google exchange client-side
        await AuthService.authGoogleCreate({ code });
        console.log("Auth with google");
        // Rust should respond with Set-Cookie: _auth / _refresh
        navigate("/", { replace: true });
      } catch (err: any) {
        console.error(err);
        setError("Google login failed, please try again.");
        navigate("/login", { replace: true });
      }
    }

    handleGoogleLogin();
  }, [searchParams, navigate]);

  if (error) {
    return (
      <div className="flex h-screen items-center justify-center text-red-600">
        {error}
      </div>
    );
  }

  return (
    <div className="flex h-screen items-center justify-center">
      Logging you in with Google, please wait...
    </div>
  );
}
