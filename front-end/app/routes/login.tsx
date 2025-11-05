import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { AuthService } from "~/api/services/AuthService";
import { loginSchema } from "schemas/login";
import { GoogleLoginButton } from "~/components/google/GoogleLoginButton";
import type { Route } from "./+types/login";

type FormData = z.infer<typeof loginSchema>;

export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  try {
    await AuthService.verify();
    return true;
  } catch (err: any) {
    if (err?.status === 401) return null;

    console.warn("verify failed:", err);
    return null;
  }
}

export function shouldRevalidate() {
  return false;
}

export default function Login({ loaderData }: Route.ComponentProps) {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const isLoggedIn = loaderData === true;

  useEffect(() => {
    if (isLoggedIn) navigate("/", { replace: true });
  }, [isLoggedIn, navigate]);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<FormData>({
    resolver: zodResolver(loginSchema),
  });

  const onSubmit = async (data: FormData) => {
    setError(null);

    try {
      await AuthService.loginUser({
        email: data.email,
        password: data.password,
      });

      navigate("/");
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Login failed");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="flex min-h-full flex-1 flex-col justify-center py-12 sm:px-6 lg:px-8">
        <div className="sm:mx-auto sm:w-full sm:max-w-md">
          <p className="text-2xl font-bold">RUST API APP</p>
          <h2 className="mt-6 text-center text-2xl font-bold text-gray-900">
            Sign in to your account
          </h2>
        </div>

        <div className="mt-10 sm:mx-auto sm:w-full sm:max-w-[480px]">
          <div className="bg-white px-6 py-12 shadow-sm sm:rounded-lg sm:px-12">
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
              <div>
                <label
                  htmlFor="email"
                  className="block text-sm font-medium text-gray-900"
                >
                  Email address
                </label>
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  className="mt-2 block w-full rounded-md border border-gray-300 px-3 py-1.5"
                  {...register("email")}
                />
                {errors.email && (
                  <p className="text-red-500 text-sm">{errors.email.message}</p>
                )}
              </div>

              <div>
                <label
                  htmlFor="password"
                  className="block text-sm font-medium text-gray-900"
                >
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  className="mt-2 block w-full rounded-md border border-gray-300 px-3 py-1.5"
                  {...register("password")}
                />
                {errors.password && (
                  <p className="text-red-500 text-sm">
                    {errors.password.message}
                  </p>
                )}
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-indigo-500"
              >
                {isSubmitting ? "Signing in..." : "Sign in"}
              </button>

              {error && <p className="text-red-500 text-sm">{error}</p>}
            </form>

            <div className="relative mt-10">
              <div
                aria-hidden="true"
                className="absolute inset-0 flex items-center"
              >
                <div className="w-full border-t border-gray-200" />
              </div>
              <div className="relative flex justify-center text-sm font-medium">
                <span className="bg-white px-6 text-gray-900">
                  Or continue with
                </span>
              </div>
            </div>

            <div className="mt-6">
              <GoogleLoginButton />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
