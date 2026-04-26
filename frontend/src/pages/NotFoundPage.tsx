import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-[#0b1326] text-[#dae2fd]">
      <p className="font-mono text-8xl font-bold text-[#7bd0ff] opacity-20">404</p>
      <p className="mt-4 font-['Space_Grotesk'] text-2xl font-bold">Page not found</p>
      <p className="mt-2 text-sm text-[#bec8d2]">
        The route you requested does not exist.
      </p>
      <Link
        to="/user/login"
        className="mt-8 rounded-md bg-gradient-to-br from-[#7bd0ff] to-[#00a7e0] px-6 py-2.5 font-bold text-[#00374d]"
      >
        Go to Login
      </Link>
    </div>
  );
}
