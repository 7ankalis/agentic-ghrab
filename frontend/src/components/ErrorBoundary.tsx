import { Component, type ReactNode } from "react";
import { RefreshCw } from "lucide-react";

/** Keeps a rendering error inside a subtree from blanking the whole app —
 *  shows a recoverable fallback with a remount button instead of a white page. */
export default class ErrorBoundary extends Component<
  { children: ReactNode; fallbackTitle?: string },
  { failed: boolean; key: number }
> {
  state = { failed: false, key: 0 };

  static getDerivedStateFromError() {
    return { failed: true } as { failed: boolean };
  }

  componentDidCatch(error: unknown) {
    console.error(error);
  }

  render() {
    if (this.state.failed) {
      return (
        <div className="grid h-full min-h-[240px] place-items-center p-6 text-center">
          <div className="space-y-3">
            <p className="text-sm text-ink-muted">{this.props.fallbackTitle ?? "Something went wrong rendering this view."}</p>
            <button
              onClick={() => this.setState((s) => ({ failed: false, key: s.key + 1 }))}
              className="btn-primary mx-auto !py-1.5 text-xs"
            >
              <RefreshCw size={13} /> Reload
            </button>
          </div>
        </div>
      );
    }
    return <div key={this.state.key}>{this.props.children}</div>;
  }
}
