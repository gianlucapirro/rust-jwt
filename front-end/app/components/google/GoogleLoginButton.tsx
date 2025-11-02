const CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID;
const CALLBACK_URL = import.meta.env.VITE_GOOGLE_CALLBACK_URL;

const googleOAuthURL = `https://accounts.google.com/o/oauth2/v2/auth?redirect_uri=${encodeURIComponent(
  CALLBACK_URL,
)}&prompt=consent&response_type=code&client_id=${CLIENT_ID}&scope=openid%20email%20profile&access_type=offline`;

export function GoogleLoginButton() {
  const handleGoogleLogin = () => {
    window.location.href = googleOAuthURL;
  };

  return (
    <button
      onClick={handleGoogleLogin}
      className="flex w-full items-center justify-center gap-3 rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 ring-1 ring-gray-300 hover:bg-gray-50"
    >
      <img src="/svg/google-icon.svg" alt="Google Icon" className="h-5 w-5" />
      Google
    </button>
  );
}
