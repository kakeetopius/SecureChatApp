import tkinter as tk
from tkinter import messagebox, scrolledtext
import queue
import argparse
import sys
import time
import threading

from client import Client


# THEME
COLORS = {
    "background": "#0f172a",
    "surface": "#1e293b",
    "surface_light": "#334155",
    "primary": "#2563eb",
    "primary_hover": "#1d4ed8",
    "danger": "#dc2626",
    "danger_hover": "#b91c1c",
    "text": "#f8fafc",
    "muted": "#94a3b8",
    "border": "#475569",
    "online": "#22c55e",
}

TITLE_FONT = ("Segoe UI", 24, "bold")
SUBTITLE_FONT = ("Segoe UI", 11)
HEADER_FONT = ("Segoe UI", 13, "bold")
BODY_FONT = ("Segoe UI", 10)
BUTTON_FONT = ("Segoe UI", 10, "bold")


def style_button(button, normal, hover):
    """
    Gives a simple hover effect to buttons.
    """
    button.configure(
        bg=normal,
        fg="white",
        activebackground=hover,
        activeforeground="white",
        relief="flat",
        cursor="hand2",
        bd=0,
    )

    button.bind("<Enter>", lambda e: button.configure(bg=hover))

    button.bind("<Leave>", lambda e: button.configure(bg=normal))


# MAIN APPLICATION
class SecureChatApp:
    def __init__(self, root):

        self.root = root
        self.root.title("Secure Chat")
        self.root.geometry("1050x680")
        self.root.minsize(900, 600)
        self.root.configure(bg=COLORS["background"])

        self.client: Client = None
        self.username = None
        self.message_queue = queue.Queue()

        # Pages
        self.login_frame = LoginFrame(self)
        self.signup_frame = SignupFrame(self)
        self.chat_frame = ChatFrame(self)

        # Show login page first
        self.show_login()

        # Start listening for queued events
        self.process_queue()

    def process_queue(self):
        try:
            while True:
                command, data = self.message_queue.get_nowait()
                self.do_command(command, data)
        except queue.Empty:
            pass
        self.root.after(100, self.process_queue)

    def show_login(self):
        self.signup_frame.frame.pack_forget()
        self.chat_frame.frame.pack_forget()
        self.root.title("Secure Chat")
        self.login_frame.frame.pack(fill=tk.BOTH, expand=True)

    def show_signup(self):
        self.login_frame.frame.pack_forget()
        self.chat_frame.frame.pack_forget()
        self.root.title("Create Account")
        self.signup_frame.frame.pack(fill=tk.BOTH, expand=True)

    def show_chat(self):
        self.login_frame.frame.pack_forget()
        self.signup_frame.frame.pack_forget()
        self.root.title(f"Secure Chat   -   {self.username}")
        self.chat_frame.frame.pack(fill=tk.BOTH, expand=True)

    def login(self, username):
        self.username = username
        self.show_chat()

    def signup(self, username):
        messagebox.showinfo(
            "Account Created", f"Account successfully created for {username}"
        )
        self.show_login()

    def listen_for_updates(self, client: Client):
        while True:
            client.poll_server()
            time.sleep(0.5)

    def do_command(self, command, data=None):
        match command:
            case "show_chat":
                self.root.after(0, lambda: self.login(data))
            case "show_auth_error":
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "Login Failed", "Invalid username or password."
                    ),
                )
            case "add_active_user":
                self.root.after(0, lambda: self.chat_frame.add_active_user(data))
            case "remove_active_user":
                self.root.after(0, lambda: self.chat_frame.remove_active_user(data))
            case "display_message":
                self.root.after(
                    0, lambda: self.chat_frame.display_message(data[0], data[1])
                )
            case _:
                return


# LOGIN PAGE
class LoginFrame:
    def __init__(self, app):
        self.app = app
        self.frame = tk.Frame(app.root, bg=COLORS["background"])
        # Center everything
        container = tk.Frame(self.frame, bg=COLORS["background"])
        container.pack(expand=True)
        # Login Card
        card = tk.Frame(
            container,
            bg=COLORS["surface"],
            padx=45,
            pady=35,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        card.pack()
        tk.Label(
            card,
            text="Secure Chat",
            font=TITLE_FONT,
            bg=COLORS["surface"],
            fg=COLORS["text"],
        ).pack(pady=(5, 2))
        tk.Label(
            card,
            text="End-to-End Encrypted Messaging",
            font=SUBTITLE_FONT,
            bg=COLORS["surface"],
            fg=COLORS["muted"],
        ).pack(pady=(0, 25))
        # Username
        tk.Label(
            card,
            text="Username",
            font=BODY_FONT,
            bg=COLORS["surface"],
            fg=COLORS["text"],
            anchor="w",
        ).pack(fill="x")
        self.username_entry = tk.Entry(
            card,
            width=32,
            font=("Segoe UI", 11),
            bg=COLORS["surface_light"],
            fg="white",
            insertbackground="white",
            relief="flat",
            bd=8,
        )

        self.username_entry.pack(pady=(5, 18), ipady=4)
        # Password
        tk.Label(
            card,
            text="Password",
            font=BODY_FONT,
            bg=COLORS["surface"],
            fg=COLORS["text"],
            anchor="w",
        ).pack(fill="x")
        self.password_entry = tk.Entry(
            card,
            width=32,
            show="*",
            font=("Segoe UI", 11),
            bg=COLORS["surface_light"],
            fg="white",
            insertbackground="white",
            relief="flat",
            bd=8,
        )
        self.password_entry.pack(pady=(5, 25), ipady=4)
        self.password_entry.bind("<Return>", self.handle_login)

        # Login Button
        login_btn = tk.Button(
            card,
            text="Login",
            font=BUTTON_FONT,
            width=24,
            pady=8,
            command=self.handle_login,
        )
        style_button(login_btn, COLORS["primary"], COLORS["primary_hover"])
        login_btn.pack()

        # Divider
        tk.Frame(card, bg=COLORS["border"], height=1).pack(fill="x", pady=25)
        tk.Label(
            card,
            text="Don't have an account?",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            font=BODY_FONT,
        ).pack()
        signup_btn = tk.Button(
            card,
            text="Create Account",
            width=20,
            pady=6,
            font=BUTTON_FONT,
            command=self.app.show_signup,
        )
        style_button(signup_btn, COLORS["surface_light"], "#475569")
        signup_btn.pack(pady=(10, 0))
        # Focus username automatically
        self.username_entry.focus_set()

    def handle_login(self, event=None):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        self.app.client.username = username
        self.app.client.password = password
        self.app.client.send_login_request()


# SIGNUP PAGE
class SignupFrame:
    def __init__(self, app):
        self.app = app
        self.frame = tk.Frame(app.root, bg=COLORS["background"])
        container = tk.Frame(self.frame, bg=COLORS["background"])
        container.pack(expand=True)
        card = tk.Frame(
            container,
            bg=COLORS["surface"],
            padx=45,
            pady=35,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        card.pack()

        # Header
        tk.Label(
            card,
            font=("Segoe UI Emoji", 34),
            bg=COLORS["surface"],
            fg=COLORS["primary"],
        ).pack()
        tk.Label(
            card,
            text="Create Account",
            font=TITLE_FONT,
            bg=COLORS["surface"],
            fg=COLORS["text"],
        ).pack(pady=(5, 5))
        tk.Label(
            card,
            text="Register a new Secure Chat account",
            font=SUBTITLE_FONT,
            bg=COLORS["surface"],
            fg=COLORS["muted"],
        ).pack(pady=(0, 25))

        # Username
        tk.Label(
            card,
            text="Username",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=BODY_FONT,
            anchor="w",
        ).pack(fill="x")

        self.username_entry = tk.Entry(
            card,
            width=32,
            font=("Segoe UI", 11),
            bg=COLORS["surface_light"],
            fg="white",
            insertbackground="white",
            relief="flat",
            bd=8,
        )
        self.username_entry.pack(fill="x", pady=(5, 15), ipady=4)

        # Password
        tk.Label(
            card,
            text="Password",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=BODY_FONT,
            anchor="w",
        ).pack(fill="x")
        self.password_entry = tk.Entry(
            card,
            width=32,
            show="*",
            font=("Segoe UI", 11),
            bg=COLORS["surface_light"],
            fg="white",
            insertbackground="white",
            relief="flat",
            bd=8,
        )
        self.password_entry.pack(fill="x", pady=(5, 15), ipady=4)

        # Confirm Password
        tk.Label(
            card,
            text="Confirm Password",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=BODY_FONT,
            anchor="w",
        ).pack(fill="x")
        self.confirm_entry = tk.Entry(
            card,
            width=32,
            show="*",
            font=("Segoe UI", 11),
            bg=COLORS["surface_light"],
            fg="white",
            insertbackground="white",
            relief="flat",
            bd=8,
        )
        self.confirm_entry.pack(fill="x", pady=(5, 25), ipady=4)
        self.confirm_entry.bind("<Return>", lambda e: self.handle_signup())
        # Signup Button
        signup_btn = tk.Button(
            card,
            text="Create Account",
            width=24,
            pady=8,
            font=BUTTON_FONT,
            command=self.handle_signup,
        )
        style_button(signup_btn, COLORS["primary"], COLORS["primary_hover"])
        signup_btn.pack()

        # Divider
        tk.Frame(card, bg=COLORS["border"], height=1).pack(fill="x", pady=25)
        tk.Label(
            card,
            text="Already have an account?",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            font=BODY_FONT,
        ).pack()
        login_btn = tk.Button(
            card,
            text="Back to Login",
            width=20,
            pady=6,
            font=BUTTON_FONT,
            command=self.app.show_login,
        )
        style_button(login_btn, COLORS["surface_light"], "#475569")
        login_btn.pack(pady=(10, 0))
        self.username_entry.focus_set()

    def handle_signup(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        confirm = self.confirm_entry.get().strip()

        if not username or not password or not confirm:
            messagebox.showerror("Error", "All fields are required.")
            return
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        self.app.client.username = username
        self.app.client.password = password
        self.app.client.send_signup_request()


# ====================== CHAT PAGE ======================
class ChatFrame:
    def __init__(self, app):
        self.app: SecureChatApp = app
        self.frame = tk.Frame(app.root, bg=COLORS["background"])
        # Current conversation information
        self.current_user = None
        self.chat_histories = {}
        # LEFT SIDEBAR
        self.left_frame = tk.Frame(self.frame, width=240, bg=COLORS["surface"])
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y)
        self.left_frame.pack_propagate(False)
        # App title
        tk.Label(
            self.left_frame,
            text="🔒 Secure Chat",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=("Segoe UI", 15, "bold"),
        ).pack(pady=(20, 5))
        tk.Label(
            self.left_frame,
            text="ONLINE USERS",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            font=("Segoe UI", 9, "bold"),
        ).pack(pady=(10, 10))
        # Users list
        self.user_listbox = tk.Listbox(
            self.left_frame,
            font=("Segoe UI", 10),
            bg=COLORS["surface_light"],
            fg=COLORS["text"],
            selectbackground=COLORS["primary"],
            selectforeground="white",
            relief="flat",
            bd=0,
            highlightthickness=0,
            activestyle="none",
        )
        self.user_listbox.pack(fill=tk.BOTH, expand=True, padx=15)
        self.user_listbox.bind("<<ListboxSelect>>", self.on_user_select)
        logout_button = tk.Button(
            self.left_frame,
            text="Logout",
            font=BUTTON_FONT,
            pady=8,
            command=self.logout,
        )

        style_button(logout_button, COLORS["danger"], COLORS["danger_hover"])
        logout_button.pack(fill=tk.X, padx=15, pady=20)
        # RIGHT SIDE
        self.right_frame = tk.Frame(self.frame, bg=COLORS["background"])
        self.right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        # HEADER
        self.header = tk.Frame(self.right_frame, bg=COLORS["surface"], height=60)
        self.header.pack(fill=tk.X)
        self.header.pack_propagate(False)
        self.chat_title = tk.Label(
            self.header,
            text="No conversation selected",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=("Segoe UI", 13, "bold"),
        )

        self.chat_title.pack(side=tk.LEFT, padx=20)
        # CHAT WINDOW
        self.chat_area = scrolledtext.ScrolledText(
            self.right_frame,
            wrap=tk.WORD,
            state="disabled",
            bg=COLORS["background"],
            fg=COLORS["text"],
            relief="flat",
            bd=0,
            padx=18,
            pady=18,
            font=("Segoe UI", 10),
            insertbackground="white",
        )

        self.chat_area.tag_config("left", justify="left", spacing1=6, spacing3=12)
        self.chat_area.tag_config("right", justify="right", spacing1=6, spacing3=12)
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=15, pady=(15, 8))
        # MESSAGE BAR
        self.bottom_frame = tk.Frame(
            self.right_frame, bg=COLORS["surface"], padx=12, pady=12
        )
        self.bottom_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        self.msg_entry = tk.Entry(
            self.bottom_frame,
            font=("Segoe UI", 11),
            bg=COLORS["surface_light"],
            fg="white",
            insertbackground="white",
            relief="flat",
            bd=8,
        )

        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10), ipady=4)
        self.msg_entry.bind("<Return>", self.send_message)
        send_button = tk.Button(
            self.bottom_frame,
            text="Send",
            width=10,
            font=BUTTON_FONT,
            command=self.send_message,
        )
        style_button(send_button, COLORS["primary"], COLORS["primary_hover"])
        send_button.pack(side=tk.RIGHT)

    def on_user_select(self, event):
        """
        Handle user selection.
        """
        selection = self.user_listbox.curselection()
        if not selection:
            return
        selected_user = self.user_listbox.get(selection[0])
        if selected_user != self.current_user:
            self.current_user = selected_user

            # Update header
            self.chat_title.config(text=f"Chat with {selected_user}")

            self.update_chat_display()

    def add_active_user(self, name):
        # Don't add duplicates
        users = self.user_listbox.get(0, tk.END)
        if name in users:
            return
        self.user_listbox.insert(tk.END, name)
        if name not in self.chat_histories:
            self.chat_histories[name] = []

    def remove_active_user(self, name):
        users = self.user_listbox.get(0, tk.END)
        for index, username in enumerate(users):
            if username == name:
                self.user_listbox.delete(index)
                break
        if name in self.chat_histories:
            del self.chat_histories[name]

        # If chatting with that user,
        # clear the conversation.

        if self.current_user == name:
            self.current_user = None
            self.chat_title.config(text="No conversation selected")
            self.update_chat_display()

    def update_chat_display(self):
        self.chat_area.config(state="normal")
        self.chat_area.delete("1.0", tk.END)
        if self.current_user and self.current_user in self.chat_histories:
            for text, alignment in self.chat_histories[self.current_user]:
                if alignment == "right":
                    self.chat_area.insert(tk.END, "You\n", "right")

                    self.chat_area.insert(tk.END, f"{text}\n\n", "right")

                else:
                    self.chat_area.insert(tk.END, f"{self.current_user}\n", "left")

                    self.chat_area.insert(tk.END, f"{text}\n\n", "left")

        else:
            self.chat_area.insert(tk.END, "\n\n\n")

            self.chat_area.insert(
                tk.END, "        Select an online user to start chatting."
            )

        self.chat_area.config(state="disabled")
        self.chat_area.yview(tk.END)

    def display_message(self, sender, message):
        """
        Display a received message.
        """
        if sender not in self.chat_histories:
            self.chat_histories[sender] = []

        self.chat_histories[sender].append((message, "left"))
        # Refresh only if currently viewing that conversation
        if self.current_user == sender:
            self.update_chat_display()

    def send_message(self, event=None):
        """
        Send the current message.
        """
        msg = self.msg_entry.get().strip()

        if not msg:
            return

        if not self.current_user:
            messagebox.showinfo("No Conversation", "Please select a user first.")
            return

        if self.current_user not in self.chat_histories:
            self.chat_histories[self.current_user] = []

        # Store locally
        self.chat_histories[self.current_user].append((msg, "right"))

        # Refresh chat
        self.update_chat_display()

        # Clear input
        self.msg_entry.delete(0, tk.END)

        # Keep typing without clicking again
        self.msg_entry.focus_set()

        # Send through client
        if self.app.client:
            self.app.client.send_encrypted_message(self.current_user, msg)

    def logout(self):
        confirm = messagebox.askyesno("Logout", "Are you sure you want to logout?")
        if not confirm:
            return

        # Clear current chat selection
        self.current_user = None
        self.user_listbox.selection_clear(0, tk.END)
        self.chat_title.config(text="No conversation selected")
        self.chat_area.config(state="normal")
        self.chat_area.delete("1.0", tk.END)
        self.chat_area.config(state="disabled")
        self.msg_entry.delete(0, tk.END)
        self.app.show_login()


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)

    client = Client()

    client.on_message = lambda cmd, data=None: app.message_queue.put((cmd, data))

    app.client = client

    parser = argparse.ArgumentParser(description="Secure Chat Client")

    parser.add_argument("-p", "--port", dest="port", help="Server port (default: 9876)")

    parser.add_argument(
        "-i", "--ip", dest="ip", help="Server IP address (default: localhost)"
    )

    options = parser.parse_args()

    if options.port:
        app.client.server_port = int(options.port)

    if options.ip:
        app.client.server_address = options.ip

    # Connect to server
    try:
        client.dial_server()
    except Exception as e:
        print(f"Unable to connect to server: {e}")
        sys.exit(-1)

    # Start listener thread
    listener = threading.Thread(
        target=app.listen_for_updates, args=(client,), daemon=True
    )

    listener.start()

    # Start GUI
    root.mainloop()
