import { type FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "../services/api";
import { useAuth } from "../hooks/useAuth";
import { apiErrorMessage } from "../utils/errors";

export default function LoginPage() {
  const navigate  = useNavigate();
  const { login } = useAuth();

  const [email,        setEmail]        = useState("");
  const [password,     setPassword]     = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading,      setLoading]      = useState(false);
  const [error,        setError]        = useState("");

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await api.post<{ access_token: string }>("/api/user/login", {
        email,
        password,
      });
      login(res.data.access_token);
      navigate("/user/workspace");
    } catch (err: unknown) {
      setError(apiErrorMessage(err, "Login failed"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#0b1326] p-6 text-[#dae2fd]">
      {/* Background glows */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute -right-1/4 -top-1/4 h-[600px] w-[600px] rounded-full bg-[#7bd0ff] opacity-[0.03] blur-[120px]" />
        <div className="absolute -bottom-1/4 -left-1/4 h-[600px] w-[600px] rounded-full bg-[#4ae176] opacity-[0.03] blur-[120px]" />
      </div>
      <div
        className="absolute inset-0"
        style={{
          backgroundImage:
            "radial-gradient(circle at 2px 2px, rgba(123,208,255,0.05) 1px, transparent 0)",
          backgroundSize: "32px 32px",
        }}
      />

      <div className="relative z-10 w-full max-w-[440px]">
        {/* Logo */}
        <div className="mb-10 flex flex-col items-center gap-2">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-[#3e4850]/20 bg-[#222a3d] shadow-[0_0_20px_rgba(123,208,255,0.1)]">
            <span className="text-2xl">🛡️</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[#7bd0ff]">SENTINEL.SQL</h1>
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#bec8d2] opacity-60">
            AI Injection Guard System
          </p>
        </div>

        {/* Card */}
        <div className="rounded-xl border border-[#3e4850]/20 bg-[rgba(49,57,77,0.8)] p-8 shadow-[0_0_32px_rgba(0,0,0,0.4)] backdrop-blur-[24px]">
          <div className="mb-8">
            <h2 className="mb-1 text-xl font-semibold tracking-tight">Login</h2>
            <p className="text-sm text-[#bec8d2]">Enter your credentials to continue</p>
          </div>

          <form className="space-y-5" onSubmit={(e) => void handleSubmit(e)}>
            <div className="space-y-1.5">
              <label className="ml-1 font-mono text-[11px] uppercase tracking-widest text-[#bec8d2]">
                Email
              </label>
              <input
                type="email"
                placeholder="admin@sentinel.network"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full rounded-lg border border-[#3e4850]/20 bg-[#060e20] px-4 py-3 text-sm text-[#dae2fd] outline-none placeholder:text-[#bec8d2]/40 focus:border-[#7bd0ff] focus:ring-4 focus:ring-[#7bd0ff]/10"
                required
                autoComplete="email"
              />
            </div>

            <div className="space-y-1.5">
              <label className="ml-1 font-mono text-[11px] uppercase tracking-widest text-[#bec8d2]">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full rounded-lg border border-[#3e4850]/20 bg-[#060e20] px-4 py-3 pr-16 text-sm text-[#dae2fd] outline-none placeholder:text-[#bec8d2]/40 focus:border-[#7bd0ff] focus:ring-4 focus:ring-[#7bd0ff]/10"
                  required
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((p) => !p)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 font-mono text-xs text-[#bec8d2] hover:text-[#dae2fd]"
                >
                  {showPassword ? "HIDE" : "SHOW"}
                </button>
              </div>
            </div>

            {error && (
              <div className="rounded-lg border border-red-400/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-gradient-to-br from-[#7bd0ff] to-[#00a7e0] py-3.5 font-bold text-[#00374d] shadow-[0_4px_12px_rgba(0,167,224,0.3)] transition-all hover:shadow-[0_4px_20px_rgba(0,167,224,0.5)] active:scale-[0.98] disabled:opacity-60"
            >
              {loading ? "SIGNING IN…" : "LOGIN"}
            </button>
          </form>
        </div>

        <div className="mt-6 text-center text-sm text-[#bec8d2]">
          Don&apos;t have an account?{" "}
          <Link to="/user/register" className="font-semibold text-[#7bd0ff] hover:underline">
            Register
          </Link>
        </div>
      </div>
    </div>
  );
}
