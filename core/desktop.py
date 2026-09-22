"""Local operator review and selected-file analysis; core never executes actions."""
import argparse
import json
import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from file_security.desktop import FileReviewPanel

from .review_channel import OperatorReviewChannel
from .registry import ApplicationRegistry
from .authority_store import SQLiteAuthorityStore, AuthorityStoreError
from .service import TOKEN_ENV, create_server
from .history import read_decision_history
from .history_desktop import HistoryPanel


def display_review(review):
    # Literal rendering makes caller newlines, terminal escapes and bidi explicit.
    fields = (
        ("Request ID", review.request_id), ("Application", review.application_id),
        ("Credential verified", "yes" if review.authenticated else "no / privileged legacy path"),
        ("Action", review.action), ("Target", review.target),
        ("Category", review.category), ("Required scope (not a grant)", review.required_scope),
        ("Policy assessment", review.policy_reason), ("Why review is needed", review.review_reason),
        ("Requester explanation (unverified)", review.explanation),
    )
    return "\n\n".join(f"{label}: {json.dumps(value, ensure_ascii=True)}" for label, value in fields)


class ReviewWindow:
    def __init__(self, root, channel, *, application_reader=None, persistent_mode=False,
                 authority_unlock=None, authority_revoke=None, authority_lock=None):
        self.root = root
        self.channel = channel
        self.current = None
        self.application_reader = application_reader
        self.authority_unlock = authority_unlock
        self.authority_revoke = authority_revoke
        self.authority_lock = authority_lock
        self.persistent_mode = persistent_mode
        self._application_rows = {}
        self._poll_count = 0
        self._poll_timer = None
        self._application_snapshot = None
        self.closed = False
        root.title("SecurityBrightness - Human review")
        root.geometry("820x680")
        root.minsize(640, 520)
        tabs = ttk.Notebook(root)
        tabs.pack(fill="both", expand=True)
        frame = ttk.Frame(tabs, padding=20)
        tabs.add(frame, text="Human review")
        self.tabs = tabs
        self.review_frame = frame
        applications = ttk.Frame(tabs, padding=20)
        tabs.add(applications, text="Applications")
        self.file_review = FileReviewPanel(tabs)
        tabs.add(self.file_review.frame, text="File Security prototype")
        self.history = HistoryPanel(tabs, read_decision_history)
        tabs.add(self.history.frame, text="Decision history")
        ttk.Label(applications, text="Registered applications", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(applications, text=("Stored grants start locked. Unlock only the authority you intend to enable for this session." if persistent_mode else "Session-only registry. Registrations are lost when this service stops. Scopes are not resource-specific."),
                  wraplength=730).pack(anchor="w", pady=(8, 14))
        self.application_status = tk.StringVar(value="")
        ttk.Label(applications, textvariable=self.application_status, wraplength=730).pack(anchor="w", pady=(0, 10))
        self.application_table = ttk.Treeview(applications, columns=("application", "trust", "scopes", "state"), show="headings")
        for column, title, width in (("application", "Application", 180), ("trust", "Trust setting", 100),
                                     ("scopes", "Stored action scopes", 330), ("state", "Authority", 130)):
            self.application_table.heading(column, text=title)
            self.application_table.column(column, width=width, minwidth=80)
        self.application_table.pack(fill="both", expand=True)
        horizontal = ttk.Scrollbar(applications, orient="horizontal", command=self.application_table.xview)
        horizontal.pack(fill="x")
        self.application_table.configure(xscrollcommand=horizontal.set)
        ttk.Label(applications, text="Selected authority: identity, scope and lifetime").pack(anchor="w", pady=(12, 4))
        self.application_details = tk.Text(applications, height=7, wrap="word", state="disabled", font=("Segoe UI", 10))
        self.application_details.pack(fill="x")
        self.application_table.bind("<<TreeviewSelect>>", self.show_application)
        authority_buttons = ttk.Frame(applications)
        authority_buttons.pack(fill="x", pady=8)
        self.unlock_button = ttk.Button(authority_buttons, text="Unlock selected grant", command=lambda: self.change_authority("unlock"), state="disabled")
        self.unlock_button.pack(side="left")
        self.revoke_button = ttk.Button(authority_buttons, text="Revoke selected grant", command=lambda: self.change_authority("revoke"), state="disabled")
        self.revoke_button.pack(side="left", padx=8)
        self.lock_button = ttk.Button(authority_buttons, text="Lock all stored authority", command=self.lock_authority,
                                     state="normal" if persistent_mode and authority_lock else "disabled")
        self.lock_button.pack(side="right")
        ttk.Label(applications, text="No credentials or credential hashes are shown. Trust does not replace scope checks or human confirmation.",
                  wraplength=730).pack(anchor="w", pady=(12, 0))
        ttk.Label(frame, text="Application intent is not human permission", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Local operator prototype. Does not protect against hostile processes under your Windows account.",
                  wraplength=730).pack(anchor="w", pady=(8, 14))
        self.status = tk.StringVar(value="Waiting for a request that needs human review.")
        ttk.Label(frame, textvariable=self.status, wraplength=730).pack(anchor="w", pady=(0, 10))
        text_frame = ttk.Frame(frame)
        text_frame.pack(fill="both", expand=True)
        self.text = tk.Text(text_frame, wrap="word", state="disabled", font=("Segoe UI", 11))
        scroll = ttk.Scrollbar(text_frame, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        self.hint = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.hint).pack(anchor="w", pady=(12, 4))
        self.confirmation = ttk.Entry(frame)
        self.confirmation.pack(fill="x")
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=12)
        self.deny = ttk.Button(buttons, text="Deny", command=lambda: self.decide(False))
        self.deny.pack(side="left")
        self.allow = ttk.Button(buttons, text="Approve this proposal", command=lambda: self.decide(True))
        self.allow.pack(side="right")
        ttk.Label(frame, text="Approval is for this proposal only. No ongoing permission is granted. No action is executed.",
                  wraplength=730).pack(anchor="w")
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.poll()

    @staticmethod
    def authority_description(app):
        return (f"Application: {json.dumps(app.application_id, ensure_ascii=True)}\n"
                f"Stored scopes: {json.dumps(sorted(app.scopes), ensure_ascii=True)}\n"
                f"Trust setting: {'trusted' if app.trusted else 'recognized'}\n"
                f"Authority: {'active' if app.active else 'locked / inactive'}\n"
                f"Lifetime: {app.lifetime}\nCreated: {app.created_at}\nChanged: {app.updated_at}\n"
                f"Expiry: {app.expires_at or 'None configured; revocable'}\nGrant version: {app.grant_id}")

    def selected_application(self):
        selected = self.application_table.selection()
        return self._application_rows.get(selected[0]) if selected else None

    def show_application(self, _event=None):
        app = self.selected_application()
        self.application_details.configure(state="normal")
        self.application_details.delete("1.0", "end")
        if app:
            self.application_details.insert("1.0", self.authority_description(app))
        self.application_details.configure(state="disabled")
        self.unlock_button.configure(state="normal" if app and not app.active and self.authority_unlock and self.persistent_mode else "disabled")
        self.revoke_button.configure(state="normal" if app and self.authority_revoke else "disabled")

    def change_authority(self, action):
        app = self.selected_application()
        callback = self.authority_unlock if action == "unlock" else self.authority_revoke
        if app is None or callback is None:
            return
        if action == "unlock" and (app.active or not self.persistent_mode):
            return
        explanation = ("Enable these stored scopes for this service session? Read-like actions may proceed automatically; consequential proposals still need review."
                       if action == "unlock" else "Permanently revoke this registration and its credential, even if currently locked?")
        if not messagebox.askyesno("Confirm human authority", self.authority_description(app) + "\n\n" + explanation,
                                  default="no", parent=self.root):
            return
        try:
            accepted = callback(app.application_id, app.grant_id)
        except AuthorityStoreError:
            messagebox.showerror("Authority unavailable", "The change could not be committed. Stored authority is inactive; inspect storage before restarting.", parent=self.root)
        else:
            if not accepted:
                messagebox.showwarning("Authority changed", "This grant changed or is unavailable. Review the current version before trying again.", parent=self.root)
        self.refresh_applications()

    def lock_authority(self):
        if self.authority_lock:
            self.authority_lock()
        self.refresh_applications()

    def refresh_applications(self):
        try:
            snapshot = self.application_reader() if self.application_reader else ()
        except Exception:
            self.application_status.set("Registry view unavailable. Existing rows may be out of date.")
            return
        if snapshot != self._application_snapshot:
            self._application_snapshot = snapshot
            for item in self.application_table.get_children():
                self.application_table.delete(item)
            self._application_rows.clear()
            self.show_application()
            for app in snapshot:
                item = self.application_table.insert("", "end", values=(
                    json.dumps(app.application_id, ensure_ascii=True),
                    "trusted" if app.trusted else "recognized",
                    json.dumps(sorted(app.scopes), ensure_ascii=True),
                    "active" if app.active else "locked / inactive",
                ))
                self._application_rows[item] = app
        self.application_status.set(f"{len(snapshot)} registered application(s); {sum(app.active for app in snapshot)} active. Stored is not the same as active.")

    def poll(self):
        if self.closed:
            return
        if self._poll_timer is not None:
            self.root.after_cancel(self._poll_timer)
        if self._poll_count % 10 == 0:
            self.refresh_applications()
        self._poll_count += 1
        reviews = self.channel.pending_reviews()
        review = reviews[0] if reviews else None
        if review != self.current:
            self.current = review
            self.confirmation.configure(state="normal")
            self.confirmation.delete(0, "end")
            self.text.configure(state="normal")
            self.text.delete("1.0", "end")
            if review:
                self.tabs.select(self.review_frame)
                self.text.insert("1.0", display_review(review))
                self.status.set("Strong confirmation required" if review.strong else "Your decision is required")
                self.hint.set("Type ALLOW, then approve." if review.strong else "Choose Approve or Deny.")
                if not review.strong:
                    self.confirmation.configure(state="disabled")
                self.deny.focus_set()
            else:
                self.status.set("No pending review. Waiting for the next proposal.")
                self.hint.set("")
                self.confirmation.configure(state="disabled")
            self.text.configure(state="disabled")
        state = "normal" if review else "disabled"
        self.allow.configure(state=state)
        self.deny.configure(state=state)
        self._poll_timer = self.root.after(100, self.poll)

    def decide(self, approved):
        review = self.current
        if review is None:
            return
        accepted = self.channel.respond(review.review_id, approved, confirmation=self.confirmation.get())
        if not accepted:
            self.status.set("Not accepted: the review expired, was already answered, or needs exact ALLOW confirmation.")
        else:
            self.current = None
            self.text.configure(state="normal")
            self.text.delete("1.0", "end")
            self.text.configure(state="disabled")
            self.confirmation.configure(state="normal")
            self.confirmation.delete(0, "end")
            self.confirmation.configure(state="disabled")
            self.allow.configure(state="disabled")
            self.deny.configure(state="disabled")
            self.hint.set("")
            self.status.set("Decision submitted. The service must still persist its audit before returning authorization.")

    def close(self):
        self.closed = True
        if self._poll_timer is not None:
            self.root.after_cancel(self._poll_timer)
        self.file_review.close()
        self.history.close()
        if self.authority_lock:
            self.authority_lock()
        self.channel.close()
        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description="SecurityBrightness trusted local operator desktop")
    parser.add_argument("--store", help="Opt-in local SQLite authority file; grants start locked on every startup")
    args = parser.parse_args()
    root = tk.Tk()
    channel = OperatorReviewChannel()
    registry = None
    try:
        registry = ApplicationRegistry(store=SQLiteAuthorityStore(args.store)) if args.store else ApplicationRegistry()
        server = create_server(approval_provider=channel, registry=registry)
    except Exception:
        if registry is not None:
            registry.close()
        root.destroy()
        raise
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    worker.start()
    print(f"SecurityBrightness desktop service: http://127.0.0.1:{server.server_port}")
    if not os.environ.get(TOKEN_ENV):
        print(f"Session/admin token: {server.securitybrightness_token}")
    print("Keep the admin token private. Provision applications using the existing integration guide.")
    window = None
    try:
        window = ReviewWindow(root, channel, application_reader=registry.list_applications, persistent_mode=registry.persistent,
                     authority_unlock=registry.operator_unlock, authority_revoke=registry.operator_revoke,
                     authority_lock=registry.lock_all)
        root.mainloop()
    finally:
        registry.lock_all()
        channel.close()
        if window is not None:
            window.file_review.cancel_analysis()
            window.file_review.wait_for_cleanup()
        server.shutdown()
        server.server_close()
        worker.join(timeout=6)
        registry.close()
        try:
            root.destroy()
        except tk.TclError:
            pass


if __name__ == "__main__":
    main()
