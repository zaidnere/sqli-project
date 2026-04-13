import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "../services/api";

export default function RegisterPage() {
  const navigate = useNavigate();

  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    setLoading(true);

    try {
      await api.post("/api/user/register", {
        fullName,
        email,
        password,
      });

      navigate("/user/login");
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0b1326] text-[#dae2fd] p-6 relative overflow-hidden">

      {/* Background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute inset-0 opacity-30"
          style={{
            backgroundImage:
              "radial-gradient(circle at 2px 2px, rgba(123,208,255,0.1) 1px, transparent 0)",
            backgroundSize: "24px 24px",
          }}
        />
        <div className="absolute -top-[10%] -left-[10%] w-[50%] h-[50%] bg-[#7bd0ff]/10 blur-[120px] rounded-full" />
        <div className="absolute -bottom-[10%] -right-[10%] w-[50%] h-[50%] bg-[#4ae176]/5 blur-[120px] rounded-full" />
      </div>

      <div className="relative z-10 w-full max-w-md">

        {/* Header */}
        <div className="text-center mb-10">
          <h1 className="text-4xl font-bold text-[#7bd0ff]">
            SENTINEL.SQL
          </h1>
          <p className="text-[10px] uppercase tracking-[0.3em] text-[#bec8d2] mt-2">
            AI INJECTION GUARD SYSTEM
          </p>
        </div>

        {/* Card */}
        <div className="bg-[rgba(23,31,51,0.7)] backdrop-blur-xl border border-[#3e4850]/20 p-10 rounded-xl shadow-[0_0_20px_rgba(123,208,255,0.15)]">

          <div className="mb-8">
            <h2 className="text-2xl font-semibold">Create New Identity</h2>
            <div className="h-1 w-12 bg-[#7bd0ff] mt-2"></div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">

            {/* FULL NAME */}
            <input
              type="text"
              placeholder="Full Name"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="w-full bg-[#060e20] border border-[#3e4850]/20 rounded-lg px-4 py-3 text-sm outline-none focus:border-[#7bd0ff]"
              required
            />

            {/* EMAIL */}
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-[#060e20] border border-[#3e4850]/20 rounded-lg px-4 py-3 text-sm outline-none focus:border-[#7bd0ff]"
              required
            />

            {/* PASSWORD */}
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-[#060e20] border border-[#3e4850]/20 rounded-lg px-4 py-3 text-sm outline-none focus:border-[#7bd0ff]"
              required
            />

            {/* CONFIRM */}
            <input
              type="password"
              placeholder="Confirm Password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full bg-[#060e20] border border-[#3e4850]/20 rounded-lg px-4 py-3 text-sm outline-none focus:border-[#7bd0ff]"
              required
            />

            {/* ERROR */}
            {error && (
              <div className="text-red-400 text-sm">{error}</div>
            )}

            {/* BUTTON */}
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-[#7bd0ff] to-[#00a7e0] text-[#00374d] font-bold py-4 rounded-lg uppercase tracking-widest"
            >
              {loading ? "CREATING..." : "INITIALIZE REGISTRATION"}
            </button>

          </form>

          {/* Footer */}
          <div className="mt-8 text-center">
            <p className="text-sm text-[#bec8d2]">
              Already have an account?
              <Link
                to="/user/login"
                className="ml-1 text-[#7bd0ff] font-semibold hover:underline"
              >
                Login
              </Link>
            </p>
          </div>
        </div>

      </div>
    </div>
  );
}