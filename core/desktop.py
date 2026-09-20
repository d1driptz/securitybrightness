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
    def __init__(self, root, channel):
        self.root = root
        self.channel = channel
        self.current = None
        self.closed = False
        root.title("SecurityBrightness - Human review")
        root.geometry("820x680")
        root.minsize(640, 520)
        frame = ttk.Frame(root, padding=20)
        frame.pack(fill="both", expand=True)
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

    def poll(self):
        if self.closed:
            return
        reviews = self.channel.pending_reviews()
        review = reviews[0] if reviews else None
        if review != self.current:
            self.current = review
            self.confirmation.configure(state="normal")
            self.confirmation.delete(0, "end")
            self.text.configure(state="normal")
            self.text.delete("1.0", "end")
            if review:
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
        ReviewWindow(root, channel)
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
