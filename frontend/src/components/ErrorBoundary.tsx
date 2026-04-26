import { Component, type ReactNode } from "react";

type Props = { children: ReactNode };
type State = { hasError: boolean; message: string };

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, message: "" };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, message: error.message };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen flex-col items-center justify-center bg-[#0b1326] p-8 text-[#dae2fd]">
          <div className="w-full max-w-md rounded-xl border border-red-400/20 bg-red-500/10 p-8">
            <p className="mb-2 font-mono text-xs uppercase tracking-widest text-red-400">
              Application Error
            </p>
            <p className="text-sm text-red-200">{this.state.message}</p>
            <button
              onClick={() => window.location.reload()}
              className="mt-6 rounded-md border border-red-400/30 bg-red-500/10 px-4 py-2 text-sm font-semibold text-red-200 hover:bg-red-500/20"
            >
              Reload page
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
