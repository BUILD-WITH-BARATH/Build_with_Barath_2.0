import { Component, type ReactNode } from 'react';

interface Props {
  label: string;
  children: ReactNode;
}

interface State {
  error: Error | null;
}

// Wraps one dashboard panel, not the whole page - a bad response shape from
// one endpoint (e.g. the coordinated_attacks object-vs-number mismatch found
// this session) should take down that one card, not the entire dashboard.
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: { componentStack: string }) {
    console.error(`[${this.props.label}] panel crashed:`, error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <section className="bg-[#171717] rounded-2xl p-5 border border-[#FF3B5C]/40 shadow-sm">
          <p className="text-xs font-mono text-[#FF3B5C] uppercase tracking-wide mb-1">{this.props.label} failed to render</p>
          <p className="text-xs text-[#A3A3A3]">{this.state.error.message}</p>
        </section>
      );
    }
    return this.props.children;
  }
}
