"""Local operator desktop: python -m core.desktop. Authorization only."""
import json
import os
import threading
import tkinter as tk
from tkinter import ttk

from .review_channel import OperatorReviewChannel
from .service import TOKEN_ENV, create_server


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
    def __init__(self, root, channel, *, application_reader=None):
        self.root = root
        self.channel = channel
        self.current = None
        self.application_reader = application_reader
        self._poll_count = 0
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
        ttk.Label(applications, text="Registered applications", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(applications, text="Read-only local registry. Registrations are lost when this service stops. Scopes are not resource-specific.",
                  wraplength=730).pack(anchor="w", pady=(8, 14))
        self.application_status = tk.StringVar(value="")
        ttk.Label(applications, textvariable=self.application_status, wraplength=730).pack(anchor="w", pady=(0, 10))
        self.application_table = ttk.Treeview(applications, columns=("application", "trust", "scopes"), show="headings")
        for column, title, width in (("application", "Application", 180), ("trust", "Trust setting", 100),
                                     ("scopes", "Granted action scopes", 440)):
            self.application_table.heading(column, text=title)
            self.application_table.column(column, width=width, minwidth=80)
        self.application_table.pack(fill="both", expand=True)
        horizontal = ttk.Scrollbar(applications, orient="horizontal", command=self.application_table.xview)
        horizontal.pack(fill="x")
        self.application_table.configure(xscrollcommand=horizontal.set)
        ttk.Label(applications, text="Selected application's complete scopes:").pack(anchor="w", pady=(12, 4))
        self.application_details = tk.Text(applications, height=5, wrap="word", state="disabled", font=("Segoe UI", 10))
        self.application_details.pack(fill="x")
        self.application_table.bind("<<TreeviewSelect>>", self.show_application)
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

    def show_application(self, _event=None):
        selected = self.application_table.selection()
        self.application_details.configure(state="normal")
        self.application_details.delete("1.0", "end")
        if selected:
            values = self.application_table.item(selected[0], "values")
            self.application_details.insert("1.0", values[2])
        self.application_details.configure(state="disabled")

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
            self.show_application()
            for app in snapshot:
                self.application_table.insert("", "end", values=(
                    json.dumps(app.application_id, ensure_ascii=True),
                    "trusted" if app.trusted else "recognized",
                    json.dumps(sorted(app.scopes), ensure_ascii=True),
                ))
        self.application_status.set(f"{len(snapshot)} registered application(s). Updated from this service's in-memory registry.")

    def poll(self):
        if self.closed:
            return
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
        self.root.after(100, self.poll)

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
        self.channel.close()
        self.root.destroy()


def main():
    root = tk.Tk()
    channel = OperatorReviewChannel()
    try:
        server = create_server(approval_provider=channel)
    except Exception:
        root.destroy()
        raise
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    worker.start()
    print(f"SecurityBrightness desktop service: http://127.0.0.1:{server.server_port}")
    if not os.environ.get(TOKEN_ENV):
        print(f"Session/admin token: {server.securitybrightness_token}")
    print("Keep the admin token private. Provision applications using the existing integration guide.")
    try:
        ReviewWindow(root, channel, application_reader=server.application_registry.list_applications)
        root.mainloop()
    finally:
        channel.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=6)
        try:
            root.destroy()
        except tk.TclError:
            pass


if __name__ == "__main__":
    main()
