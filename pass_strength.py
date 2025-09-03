import argparse
import json
import math
import pathlib
import string
from typing import Dict, List, Optional, Tuple

from textual.app import App, ComposeResult
from textual.widgets import Button, Input, Select, Static
from textual.containers import Horizontal


def compute_entropy(password: str) -> Tuple[int, int, float, str]:
    """Compute password entropy using a simple pool-based model.

    The character pool is estimated from character classes present:
    - lower: 26
    - upper: 26
    - digits: 10
    - symbols: len(string.punctuation)
    - whitespace: len(string.whitespace) if any whitespace present
    - non_ascii: +100 if any code point > 127 (rough estimate)

    Entropy is length * log2(pool). Rating is:
    - Weak: length < 8 or entropy < 40
    - Moderate: entropy < 60
    - Strong: otherwise
    """
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if any(c.isspace() for c in password):
        pool += len(string.whitespace)
    if any(ord(c) > 127 for c in password):
        pool += 100

    length = len(password)
    entropy = 0.0 if pool == 0 or length == 0 else length * math.log2(pool)
    rating = (
        "Weak" if length < 8 or entropy < 40 else ("Moderate" if entropy < 60 else "Strong")
    )
    return length, pool, entropy, rating


def load_breach_list() -> List[str]:
    """Load list of common breached passwords (lowercased) from JSON.

    Returns a list of lowercased passwords. On error, returns an empty list.
    """
    path = pathlib.Path(__file__).with_name("breach_top_250.json")
    try:
        data = json.loads(path.read_text())
        if isinstance(data, list):
            return [str(x).lower() for x in data]
    except Exception:
        pass
    return []


class PassStrength(App):
    CSS = """
    Screen { align: left top; padding: 0 0 0 4; }
    #title { dock: top; content-align: left middle; height: 4; color: magenta; margin: 1 0; text-style: bold; }
    #policy_row { width: 72; height: 3; }
    #policy_label { width: 26; content-align: left middle; color: $accent; text-style: bold; }
    #policy { width: 46; }
    #policy_heading { width: 72; content-align: left middle; color: $accent; text-style: bold; }
    #policy_box { width: 72; border: round $accent; padding: 1 2; margin: 0 0 1 0; }
    #pw { width: 72; margin: 1 0; }
    #check { width: 16; margin: 1 0; text-style: bold; }
    #results_heading { width: 72; content-align: left middle; color: $accent; text-style: bold; }
    #results { width: 72; border: round $accent; padding: 1 2; margin: 0 0 1 0; }
    """

    policies: Dict[str, Dict]
    current: Optional[str]
    breach_list: List[str]
    load_error: Optional[str]

    def load_policies(self) -> None:
        """Load and validate policy frameworks from JSON with graceful fallback."""
        self.load_error = None
        path = pathlib.Path(__file__).with_name("frameworks.json")
        try:
            raw = json.loads(path.read_text())
        except Exception as exc:
            self.load_error = f"Failed to read frameworks.json: {exc}"
            raw = {}

        frameworks = raw.get("frameworks") if isinstance(raw, dict) else None
        if not isinstance(frameworks, dict):
            frameworks = {}

        def valid_bool(v):
            return isinstance(v, bool)

        def valid_int(v):
            return isinstance(v, int) and v >= 0

        def valid_number(v):
            return (isinstance(v, (int, float))) and v >= 0

        policies: Dict[str, Dict] = {}
        for name, cfg in frameworks.items():
            if not isinstance(cfg, dict):
                continue
            min_length = cfg.get("min_length", 0)
            min_entropy = cfg.get("min_entropy", 0)
            if not valid_int(min_length) or not valid_number(min_entropy):
                continue
            policy = {
                "min_length": int(min_length),
                "require_lower": bool(cfg.get("require_lower", False)),
                "require_upper": bool(cfg.get("require_upper", False)),
                "require_digits": bool(cfg.get("require_digits", False)),
                "require_symbols": bool(cfg.get("require_symbols", False)),
                "min_entropy": float(min_entropy),
                "desc": str(cfg.get("desc", "")),
            }
            # Ensure booleans are booleans
            if not all(
                valid_bool(policy[k])
                for k in [
                    "require_lower",
                    "require_upper",
                    "require_digits",
                    "require_symbols",
                ]
            ):
                continue
            policies[name] = policy

        if not policies:
            # Fallback minimal policy
            policies = {"Simple": {"min_length": 6, "desc": "Simple: 6+"}}
            self.load_error = self.load_error or "No valid policies found; using fallback."

        self.policies = policies
        default = raw.get("default") if isinstance(raw, dict) else None
        self.current = default if default in self.policies else next(iter(self.policies), None)
        self.breach_list = load_breach_list()

    def policy_text(self, name: str) -> str:
        """Return a human-readable description of the selected policy."""
        p = self.policies.get(name, {})
        if not p:
            return "No policy selected."
        reqs = [
            f"min_length>={p.get('min_length', 0)}",
            *(label for key, label in [
                ("require_lower", "lower"),
                ("require_upper", "upper"),
                ("require_digits", "digit"),
                ("require_symbols", "symbol"),
            ] if p.get(key)),
        ]
        if p.get("min_entropy"):
            reqs.append(f"min_entropy>={int(p['min_entropy'])}")
        desc = p.get("desc", "").strip()
        lead = f"{name}: {desc}" if desc else name
        return lead + ("\n" + ", ".join(reqs) if reqs else "")

    def _policy_check(self, password: str, entropy: float, length: int) -> Dict[str, bool]:
        """Evaluate policy requirement satisfaction for the current policy."""
        p = self.policies.get(self.current or "", {})
        return {
            "min_length": length >= p.get("min_length", 0),
            "lower": (not p.get("require_lower")) or any(c.islower() for c in password),
            "upper": (not p.get("require_upper")) or any(c.isupper() for c in password),
            "digit": (not p.get("require_digits")) or any(c.isdigit() for c in password),
            "symbol": (not p.get("require_symbols")) or any(c in string.punctuation for c in password),
            "entropy": (not p.get("min_entropy")) or entropy >= float(p.get("min_entropy", 0)),
        }

    def _update_results(self, password: str) -> None:
        """Compute and update the results panel for the given password."""
        length, pool, entropy, rating = compute_entropy(password)
        color = "red" if rating == "Weak" else ("yellow3" if rating == "Moderate" else "green")

        # Breach list check (case-insensitive)
        breach_line = "Breach List: [green]Not found[/]"
        if password and self.breach_list and password.lower() in self.breach_list:
            breach_line = "Breach List: [red](!) Found in top breaches[/]"

        # Policy compliance summary with per-requirement breakdown
        checks = self._policy_check(password, entropy, length)
        failed = [k for k, v in checks.items() if not v]
        p_title = f"Policy ({self.current}): " if self.current else "Policy: "
        policy_line = (
            f"{p_title}[green]Passed[/]" if not failed else f"{p_title}[red]Failed[/] ({', '.join(failed)})"
        )
        # Pretty per-requirement indicators
        labels = [
            ("min_length", f"min_length>={self.policies.get(self.current or '', {}).get('min_length', 0)}"),
            ("lower", "lower"),
            ("upper", "upper"),
            ("digit", "digit"),
            ("symbol", "symbol"),
            ("entropy", f"entropy>={int(self.policies.get(self.current or '', {}).get('min_entropy', 0))}"),
        ]
        parts = []
        for key, label in labels:
            ok = checks.get(key, True)
            mark = "[green]✓[/]" if ok else "[red]✗[/]"
            parts.append(f"{mark} {label}")
        breakdown = ", ".join(parts)

        txt = (
            f"Length: {length}\n"
            f"Character pool: {pool}\n"
            f"Entropy: {entropy:.2f} bits\n"
            f"Rating: [bold {color}]{rating}[/]\n"
            f"{breach_line}\n"
            f"{policy_line}\n"
            f"Requirements: {breakdown}"
        )
        self.query_one("#results", Static).update(txt)

    def compose(self) -> ComposeResult:
        title_text = "PassStrength"
        border = "-" * (len(title_text) + 4)
        boxed_title = f"{border}\n| {title_text} |\n{border}"
        yield Static(boxed_title, id="title")
        yield Horizontal(
            Static("Framework / Requirement:", id="policy_label"),
            Select(options=[], id="policy"),
            id="policy_row",
        )
        yield Static("Policy", id="policy_heading")
        yield Static("", id="policy_box")
        yield Input(placeholder="Enter password", password=True, id="pw")
        yield Button("Check", id="check")
        yield Static("Results", id="results_heading")
        yield Static("", id="results")

    def on_mount(self) -> None:
        self.load_policies()
        sel = self.query_one("#policy", Select)
        sel.set_options([(n, n) for n in self.policies.keys()])
        if self.current:
            sel.value = self.current
            sel.disabled = False
        else:
            sel.disabled = True
        self.query_one("#policy_box", Static).update(self.policy_text(sel.value))
        if self.load_error:
            self.query_one("#results", Static).update(f"[red]{self.load_error}[/]")
        # Prime breach list line even with empty password
        self._update_results("")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "policy":
            self.current = event.value
            self.query_one("#policy_box", Static).update(self.policy_text(self.current))
            # Re-evaluate current input against new policy
            pw = self.query_one("#pw", Input).value
            self._update_results(pw)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "check":
            return
        pw = self.query_one("#pw", Input).value
        self._update_results(pw)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Trigger check when pressing Enter in the password input."""
        if event.input.id == "pw":
            self._update_results(event.value)

    def on_input_changed(self, event: Input.Changed) -> None:
        """Live updates as the user types in the password field."""
        if event.input.id == "pw":
            self._update_results(event.value)


def _run_cli() -> None:
    """Minimal CLI interface for non-TUI usage."""
    parser = argparse.ArgumentParser(description="Password strength checker (CLI mode)")
    parser.add_argument("--policy", "-p", help="Policy name to evaluate against", default=None)
    parser.add_argument("--password", "-w", help="Password to evaluate (careful: visible in history)")
    args = parser.parse_args()

    app = PassStrength()
    # Load data without starting the event loop
    app.load_policies()
    if args.policy and args.policy in app.policies:
        app.current = args.policy

    pw = args.password or ""
    length, pool, entropy, rating = compute_entropy(pw)
    checks = app._policy_check(pw, entropy, length)
    failed = [k for k, v in checks.items() if not v]
    breach_hit = pw and app.breach_list and pw.lower() in app.breach_list

    print(f"Policy: {app.current}")
    print(f"Length: {length}")
    print(f"Pool: {pool}")
    print(f"Entropy: {entropy:.2f} bits")
    print(f"Rating: {rating}")
    print(f"Breach List: {'FOUND' if breach_hit else 'not found'}")
    print("Failed: " + (", ".join(failed) if failed else "(none)"))


if __name__ == "__main__":
    # Run CLI if explicitly requested via env/args: we choose arg presence
    import sys

    if any(arg in ("--cli", "cli") for arg in sys.argv):
        # Remove the flag and run CLI
        sys.argv = [a for a in sys.argv if a not in ("--cli", "cli")]
        _run_cli()
    else:
        PassStrength().run()
