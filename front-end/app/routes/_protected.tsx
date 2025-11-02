import { Outlet } from "react-router";
import Header from "~/components/Header";
import { AuthService } from "~/api/services/AuthService";
import type { Route } from "./+types/_protected";
import { redirect } from "react-router";
import type { UserResponse } from "~/api/models/UserResponse";

export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  try {
    const user: UserResponse = await AuthService.me();
    return { user };
  } catch (err: any) {
    const url = new URL(request.url);
    const next = url.pathname + url.search;
    throw redirect(`/session/refresh?next=${encodeURIComponent(next)}`);
  }
}

export function shouldRevalidate() {
  return false;
}

export default function ProtectedLayout({ loaderData }: Route.ComponentProps) {
  const { user } = loaderData ?? {};

  return (
    <div className="max-w-4xl mx-auto">
      {user && <Header user={user} />}
      <div className="min-h-[calc(100vh-180px)]">
        <Outlet context={{ user }} />
      </div>
    </div>
  );
}

export type ProtectedOutletContext = { user?: UserResponse };
