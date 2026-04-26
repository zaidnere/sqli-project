import { type FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "../services/api";
import { apiErrorMessage } from "../utils/errors";

export default function RegisterPage() {
  const navigate = useNavigate();

  const [fullName,        setFullName]        = useState("");
  const [email,           setEmail]           = useState("");
  const [password,        setPassword]        = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading,         setLoading]         = useState(false);
  const [error,           setError]           = useState("");

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    setLoading(true);
    try {
      await api.post("/api/user/register", { fullName, email, password });
      navigate("/user/login");
    } catch (err: unknown) {
      setError(apiErrorMessage(err, "Registration failed"));
    } finally {
      setLoading(false);
    }
  };

  const fieldClass =
    "w-full rounded-lg border border-[#3e4850]/20 bg-[#060e20] px-4 py-3 text-sm text-[#dae2fd] outline-none placeholder:text-[#bec8d2]/40 focus:border-[#7bd0ff] focus:ring-4 focus:ring-[#7bd0ff]/10";

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#0b1326] p-6 text-[#dae2fd]">
      {/* Background */}
      <div className="pointer-events-none absolute inset-0">
        <div
          className="absolute inset-0 opacity-30"
          style={{
            backgroundImage:
              "radial-gradient(circle at 2px 2px, rgba(123,208,255,0.1) 1px, transparent 0)",
            backgroundSize: "24px 24px",
          }}
        />
        <div className="absolute -left-[10%] -top-[10%] h-[50%] w-[50%] rounded-full bg-[#7bd0ff]/10 blur-[120px]" />
        <div className="absolute -bottom-[10%] -right-[10%] h-[50%] w-[50%] rounded-full bg-[#4ae176]/5 blur-[120px]" />
      </div>

      <div className="relative z-10 w-full max-w-md">
        {/* Header */}
        <div className="mb-10 flex flex-col items-center gap-2">
          <h1 className="font-['Space_Grotesk'] text-4xl font-bold text-[#7bd0ff]">
            SENTINEL.SQL
          </h1>
          <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-[#bec8d2] opacity-60">
            AI Injection Guard System
          </p>
        </div>

        {/* Card */}
        <div className="rounded-xl border border-[#3e4850]/20 bg-[rgba(23,31,51,0.7)] p-10 shadow-[0_0_20px_rgba(123,208,255,0.15)] backdrop-blur-xl">
          <div className="mb-8">
            <h2 className="text-2xl font-semibold">Create Account</h2>
            <div className="mt-2 h-1 w-12 bg-[#7bd0ff]" />
          </div>

          <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
            <input
              type="text"
              placeholder="Full Name"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className={fieldClass}
              required
              autoComplete="name"
            />
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className={fieldClass}
              required
              autoComplete="email"
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={fieldClass}
              required
              autoComplete="new-password"
            />
            <input
              type="password"
              placeholder="Confirm Password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className={fieldClass}
              required
              autoComplete="new-password"
            />

            {error && (
              <div className="rounded-lg border border-red-400/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-gradient-to-r from-[#7bd0ff] to-[#00a7e0] py-3.5 font-bold uppercase tracking-widest text-[#00374d] transition-all active:scale-[0.98] disabled:opacity-60"
            >
              {loading ? "CREATING…" : "REGISTER"}
            </button>
          </form>

          <div className="mt-8 text-center text-sm text-[#bec8d2]">
            Already have an account?{" "}
            <Link to="/user/login" className="font-semibold text-[#7bd0ff] hover:underline">
              Login
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
