import linecache
import re
import sys
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox
from datetime import datetime
import socket
import threading
import ssl
import base64
from io import BytesIO
from PIL import Image, ImageTk
import os
import hashlib
import ast
import logging

logging.basicConfig(
    filename='chat_server.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

IP_Address = socket.gethostbyname(socket.gethostname())
PORT_ = "5000"
PASS_DIR = os.path.join(os.getcwd(), 'pass')
os.makedirs(PASS_DIR, exist_ok=True)


def print_exception():
    """
    Print the most recent exception with file, line, and code context.
    Useful for debugging server errors.
    """
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print('EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj))

def reset_password(username, new_password):
    """
    Reset a user's password hash file to a new password.

    Args:
        username (str): The username whose password to reset.
        new_password (str): The new password to set.
    Returns:
        bool: True on success, False otherwise.
    """
    hash_file = os.path.join(PASS_DIR, f"{username}.hash")
    if os.path.isfile(hash_file):
        pwd_hash = hashlib.sha256(new_password.encode()).hexdigest()
        with open(hash_file, 'w', encoding='utf-8') as f:
            f.write(pwd_hash)
        return True
    return False

def show_instructions():
    """
    Show the instruction window for chat server administrators.
    This now provides a more modern, detailed guide for all features and troubleshooting.
    """
    instr = tk.Tk()
    instr.title("Secure Chat Server - Admin Instructions")
    instr.geometry("750x680")
    instr.configure(bg="#f5f5f0")

    title = tk.Label(
        instr,
        text="Python Chat Server – Admin Guide",
        font=("Arial", 20, "bold"),
        bg="#f5f5f0"
    )
    title.pack(pady=10)

    long_text = (
        "🛡️ Secure Chat Server Administration Guide 🛡️\n\n"
        "🚀 Getting Started:\n"
        "- Ensure you have a valid SSL certificate (server.crt) and private key (server.key) in this directory.\n"
        "- The server listens on your machine's IP (see below) and port 5000 by default.\n"
        "- User passwords are stored hashed in the ./pass directory.\n"
        "\n"
        "🖥️ Main Interface Overview:\n"
        "- Uptime and system/network monitoring are shown in real time.\n"
        "- The left panel provides server controls: restart, clear logs, system/network stats.\n"
        "- The main window shows chat history; you can broadcast messages to all clients.\n"
        "- The 'Connection Info' panel shows the server's port, status, list of users, and lets you send system-wide messages.\n"
        "- Profanity filter can be toggled on/off as needed.\n"
        "- Use the 'Pause Accepting' button to temporarily stop allowing new connections.\n"
        "\n"
        "🔑 User Authentication & Management:\n"
        "- Users authenticate via username and password (auto-registers new users).\n"
        "- Passwords are never stored in plain text.\n"
        "- Users can reset their password by sending '/resetpass-NEWPASS-OLDPASS' as a chat command.\n"
        "- You can clear all logs with the button or by removing server.log.\n"
        "- Admin can view user infractions (for profanity) and user statistics.\n"
        "\n"
        "🛠️ Admin Console Commands:\n"
        "- /stats : Shows connected users and infraction counts.\n"
        "- /shutdown : Cleanly shuts down the server and notifies all clients.\n"
        "\n"
        "📦 Images & Attachments:\n"
        "- Images sent by clients are displayed in the chat history and can be previewed.\n"
        "- Supported formats: .png, .jpg, .jpeg, .gif, .bmp. Max size: 5MB.\n"
        "\n"
        "🧑‍💻 Technical/Network Notes:\n"
        "- For local/LAN use, clients may use 127.0.0.1 or your local IP.\n"
        "- For remote/internet access, ensure port 5000 is open in firewall/router.\n"
        "- SSL errors indicate the certificate or key is missing/invalid.\n"
        "\n"
        "🔧 Troubleshooting:\n"
        "- If clients can't connect, check the console and logs for errors.\n"
        "- Ensure the correct port/IP are being used, and that your network allows inbound connections.\n"
        "- Use 'Clear Logs' to reset the on-screen chat and server.log file.\n"
        "- Restart the server if configuration or network changes are made.\n"
        "- For debugging, check 'chat_server.log' in this directory.\n"
        "\n"
        "ℹ️ Tips:\n"
        "- You can broadcast a system message to all users via the 'System Message' entry.\n"
        "- The server interface supports real-time monitoring for CPU, RAM, and network speeds.\n"
        "- User list auto-refreshes; users are removed from the list when disconnected.\n"
        "\n"
    )

    text = tk.Text(
        instr,
        wrap="word",
        font=("Arial", 13),
        bg="#f5f5f0",
        relief="flat"
    )
    text.insert("1.0", long_text)
    text.config(state="disabled")
    text.pack(padx=24, pady=12, fill="both", expand=True)

    instr.mainloop()

def on_login(username_var, password_var):
    """
    Verifies or registers the username and password.

    Returns:
        int: 1 if verified, 2 if not verified, 3 if registered.
    """
    user = username_var.strip()
    pwd = password_var
    if not user or not pwd:
        return 2  # Not Verified (treat empty fields as failed verification)

    hash_file = os.path.join(PASS_DIR, f"{user}.hash")
    pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()
    if os.path.isfile(hash_file):
        # LOGIN flow
        with open(hash_file, 'r', encoding='utf-8') as f:
            stored_hash = f.read().strip()
        if pwd_hash == stored_hash:
            return 1  # Verified
        else:
            return 2  # Not Verified (wrong password)
    else:
        # REGISTRATION flow
        with open(hash_file, 'w', encoding='utf-8') as f:
            f.write(pwd_hash)
        return 3  # Registered

class SOCKETS:
    """
    Manages all server-side socket operations, including client management,
    message broadcasting, user authentication, profanity filtering, and
    system message handling.
    """
    def __init__(self, login_callback=None):
        """Initialize the server socket, client lists, and profanity filter."""
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = []
        self.usernames = {}  # Map conn -> username
        self.filter_enabled = True  # Profanity filter toggle
        self.infractions = {}  # Count of infractions per user
        self.login_callback = login_callback
        logging.info("Socket created for server")

    def handle_client_login(self, conn, username):
        """
        Invokes the login callback for a client connection, if set.

        Args:
            conn (socket.socket): The client socket.
            username (str): The client's username.
        """
        if self.login_callback:
            self.login_callback(conn, username)

    def load(self, ip_address, port, text, status):
        """
        Loads references to GUI variables and initializes profanity filter.

        Args:
            ip_address (tk.StringVar): IP address variable.
            port (tk.IntVar): Port variable.
            text (tk.Text): Chat history widget.
            status (tk.Label): Status label widget.
        """
        self.ip_address = ip_address
        self.port = port
        self.history = text
        self.status = status
        self.swear_words = self.load_swear_words()

    def broadcast_user_list(self):
        """
        Sends the current user list to all connected clients.
        """
        users = ",".join(self.usernames.values())
        msg = f"[USERLIST]{users}\n".encode('utf-8')
        for c in self.clients:
            try:
                c.sendall(msg)
            except Exception as e:
                logging.warning("Failed to send user list to %s: %s", c, e)

    def load_swear_words(self):
        """
        Loads the list of swear words from 'swear.txt'.

        Returns:
            list: List of swear words.
        """
        try:
            with open("swear.txt", "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content.startswith("[") and content.endswith("]"):
                    return ast.literal_eval(content)
                return [line.strip() for line in content.splitlines() if line.strip()]
        except Exception:
            return []

    def _filter_swears(self, text):
        """
        Internal method to replace swears in text with asterisks.

        Args:
            text (str): Input text.

        Returns:
            str: Filtered text.
        """
        def replace(match):
            return "*" * len(match.group())

        pattern = re.compile(r"\b(?:" + "|".join(re.escape(word) for word in self.swear_words) + r")\b", re.IGNORECASE)
        return pattern.sub(replace, text)

    def filter_swears(self, text, conn=None):
        """
        Filters profanity from text and tracks user infractions.

        Args:
            text (str): Input text.
            conn (socket.socket, optional): Client socket.

        Returns:
            str: Filtered text.
        """
        if not self.filter_enabled:
            return text
        filtered = self._filter_swears(text)
        if filtered != text and conn in self.usernames:
            user = self.usernames[conn]
            self.infractions[user] = self.infractions.get(user, 0) + 1
            logging.warning("Profanity infraction by %s (count %d)", user, self.infractions[user])
            if self.infractions[user] > 5:
                try:
                    conn.sendall(b"[SYSTEM]: You have been muted for excessive profanity.\n")
                except:
                    pass
        return filtered

    def bind(self):
        """
        Binds the server socket, starts listening, and launches accept_clients thread.
        """
        self.s.bind((IP_Address, int(self.port.get())))
        self.s.listen(5)
        logging.info("Server listening on %s:%s", IP_Address, self.port.get())
        self.status.config(text="Waiting for connections...", bg='yellow')
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        threading.Thread(target=self.accept_clients, daemon=True).start()

    def accept_clients(self):
        """
        Accepts incoming client connections, wraps with SSL, and starts client receive thread.
        """
        MAX_CLIENTS = 50
        self.accepting = True
        while True:
            try:
                conn, addr = self.s.accept()
                if not self.accepting:
                    try:
                        conn.send(b"[SYSTEM]: Server is not accepting new connections right now.\n")
                        conn.shutdown(socket.SHUT_RDWR)
                        conn.close()
                    except:
                        pass
                    continue
                if len(self.clients) >= MAX_CLIENTS:
                    conn.sendall(b"[SYSTEM]: Server is full; try again later.\n")
                    conn.close()
                    continue
                ssl_conn = self.context.wrap_socket(conn, server_side=True)
                ssl_conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.clients.append(ssl_conn)
                logging.info("Accepted connection from %s", addr)
                self.status.config(
                    text=f"Connected to {len(self.clients)} clients",
                    bg='lightgreen'
                )
                threading.Thread(target=self.recv, args=(ssl_conn,), daemon=True).start()
            except Exception as e:
                print(f"[!] Accept error: {e}")

    def send(self, text: str):
        """
        Broadcasts a message to all connected clients.

        Args:
            text (str): Message to broadcast.
        """
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        data = f"{timestamp} Server: {text}\n".encode('utf-8')
        for client in self.clients:
            try:
                client.sendall(data)
            except Exception:
                self.clients.remove(client)

    def recv(self, conn):
        """
        Receives and handles incoming messages from a client.

        Args:
            conn (socket.socket): The client socket.
        """
        buffer = b""
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                buffer += data

                while b"\n" in buffer:
                    msg_data, buffer = buffer.split(b"\n", 1)

                    if msg_data.startswith(b"Verify-Client.Ser ,"):
                        self.handle_verification_message(msg_data, conn)
                    elif msg_data.startswith(b"/resetpass-"):
                        print("RECV LOOP DATA:", repr(msg_data))
                        self.reset_pass(msg_data.decode("utf-8", errors="ignore"), conn)
                    elif msg_data.startswith(b"[IMG]"):
                        self.handle_image_message(msg_data, conn)
                    else:
                        self.handle_text_message(msg_data, conn)

            except Exception as e:
                print(f"[!] Connection error: {e}")
                if conn in self.clients:
                    self.clients.remove(conn)
                conn.close()
                break
        if conn in self.clients:
            self.clients.remove(conn)
            self.update_client_status()
        conn.close()

    def reset_pass(self, data: str, conn):
        """
        Handle password reset requests from clients.

        Args:
            data (str): The reset command string.
            conn (socket.socket): The client socket.
        """
        print("\n=== RESET_PASS CALLED ===")
        print("PASS_DIR:", os.path.abspath(PASS_DIR))
        print("RAW DATA:", repr(data))
        data = data.replace("\n", "")
        parts = data.split("-", 2)
        print("SPLIT PARTS:", parts)
        if len(parts) < 3:
            print("Malformed request")
            try:
                conn.sendall(b"RESETFAIL\n")
            except:
                pass
            return

        new_pass = parts[1].strip()
        old_pass = parts[2].strip()
        pwd_hash = hashlib.sha256(old_pass.encode()).hexdigest()
        print("OLD PASS:", repr(old_pass), "NEW PASS:", repr(new_pass))
        print("OLD PASS HASH:", pwd_hash)

        found = False
        for file_name in os.listdir(PASS_DIR):
            file_path = os.path.join(PASS_DIR, file_name)
            print("CHECKING FILE:", file_path)
            if os.path.isfile(file_path) and file_name.endswith('.hash'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    stored_hash = f.read().strip()
                print(f"   STORED: {stored_hash} vs INPUT: {pwd_hash}")
                if stored_hash == pwd_hash:
                    username = file_name.replace('.hash', '')
                    new_hash = hashlib.sha256(new_pass.encode()).hexdigest()
                    print(f"   MATCH! WRITING {new_hash} to {file_path}")
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_hash)
                        f.flush()
                        os.fsync(f.fileno())
                    print("   FILE WRITTEN!")
                    found = True
                    try:
                        conn.sendall(b"RESETSUCCESS\n")
                    except:
                        pass
                    break

        if not found:
            print("No matching password found to reset.")
            try:
                conn.sendall(b"RESETFAIL\n")
            except:
                pass

    def update_client_status(self):
        """
        Updates the connected client count displayed in the GUI.
        """
        client_count = len(self.clients)
        self.status.config(
            text=f"Connected to {client_count} client{'s' if client_count != 1 else ''}",
            bg='lightgreen' if client_count > 0 else 'red'
        )

    def handle_verification_message(self, msg_data, conn):
        """
        Handles login/registration requests from clients.

        Args:
            msg_data (bytes): The raw message data.
            conn (socket.socket): The client socket.
        """
        try:
            parts = msg_data.decode("utf-8", errors="ignore").split(",")
            if len(parts) != 3:
                conn.sendall(b"2")  # Send "Not Verified" for malformed messages
                return

            _, username, password = parts
            result = on_login(username.strip(), password.strip())
            conn.sendall(f"{result}".encode("utf-8"))
            if result in (1, 3):
                self.usernames[conn] = username.strip()
                logging.info("User %s connected", username.strip())
                self.broadcast_user_list()
                self.handle_client_login(conn, username.strip())  # <-- call after updating self.usernames!

        except Exception as e:
            print(f"[!] Error handling verification message: {e}")
            conn.sendall(b"2\n")

    def handle_image_message(self, msg_data, conn):
        """
        Handles incoming image messages from clients and displays/broadcasts them.

        Args:
            msg_data (bytes): The message data with image.
            conn (socket.socket): The client socket.
        """
        try:
            b64_data = msg_data[5:]
            img = Image.open(BytesIO(base64.b64decode(b64_data)))
            img.thumbnail((150, 150))
            thumb = ImageTk.PhotoImage(img)

            def display_image():
                self.history.image_create("end", image=thumb)
                self.history.insert("end", " (Image received)\n")
                if not hasattr(self.history, '_image_refs'):
                    self.history._image_refs = []
                self.history._image_refs.append(thumb)

            self.history.after(0, display_image)
            self.broadcast(msg_data + b"\n", conn)
        except Exception as e:
            print(f"[!] Error decoding image: {e}")

    def handle_text_message(self, msg_data, conn):
        """
        Handles incoming text messages from clients and displays/broadcasts them.

        Args:
            msg_data (bytes): The message data.
            conn (socket.socket): The client socket.
        """
        try:
            msg = msg_data.decode('utf-8', errors='ignore') + "\n"
            msg = self.filter_swears(msg)

            def display_text():
                self.history.insert("end", msg)
                self.history.see("end")

            self.history.after(0, display_text)
            self.broadcast(msg.encode() + b"\n", conn)
        except Exception as e:
            print(f"[!] Error decoding text: {e}")

    def broadcast(self, data, sender_conn):
        """
        Broadcasts data to all clients except the sender.

        Args:
            data (bytes): Data to broadcast.
            sender_conn (socket.socket): The sender's socket.
        """
        for client in self.clients:
            if client != sender_conn:
                try:
                    client.sendall(data)
                except Exception as e:
                    print(f"[!] Error broadcasting data: {e}")
                    self.clients.remove(client)

    def toggle_accepting(self):
        """
        Toggle whether the server is accepting new connections.

        Returns:
            bool: The new accepting state.
        """
        self.accepting = not getattr(self, 'accepting', True)
        return self.accepting

    def broadcast_system_message(self, time, msg):
        """
        Broadcast a system message to all clients.

        Args:
            time (str): Timestamp string.
            msg (str): The message to broadcast.
        """
        data = f"{time} [SYSTEM]: {msg}\n".encode('utf-8')
        for client in self.clients:
            try:
                if isinstance(client, tuple):
                    conn = client[0]
                else:
                    conn = client
                conn.sendall(data)
            except Exception:
                pass

class ServerDialogBox(tk.Tk):
    """
    The main GUI application window for the chat server admin.
    Handles all widgets, panels, and integrates with SOCKETS for server logic.
    """
    def __init__(self, *args, **kwargs):
        """
        Initialize the ServerDialogBox, build UI, and launch server threads.
        """
        super().__init__(*args, **kwargs)
        self.geometry('1200x800')
        self.title('Python Chat Server')
        self.ip_address = tk.StringVar()
        self.port = tk.IntVar(value=int(PORT_))
        self.resizable(False, False)
        self.create_additional_panel()
        threading.Thread(target=self.socket_connections, daemon=True).start()

        # Uptime & system/network monitoring
        from datetime import datetime
        import psutil
        self.start_time = datetime.now()
        self._prev_net = psutil.net_io_counters()
        self.update_uptime()
        self.update_system_status()
        self.update_user_list_gui()

    def socket_connections(self):
        """
        Create and bind the SOCKETS server object to start listening for connections.
        """
        self.s = SOCKETS(login_callback=self.handle_login_success)
        self.s.load(
            self.ip_address,
            self.port,
            self.history,
            self.status,
        )
        self.s.bind()

    def send_text_message(self):
        """
        Send a message from the admin to all clients.
        """
        if "Connected" in self.status.cget('text'):
            input_data = self.Sending_data.get('1.0', 'end').strip()
            if input_data:
                timestamp = datetime.now().strftime("[%H:%M:%S]")
                formatted_text = f"{timestamp} Me: {input_data}\n"
                self.history.insert("end", formatted_text)
                self.Sending_data.delete('1.0', 'end')
                self.s.send(input_data)
        else:
            print("[+] Not Connected")

    def create_additional_panel(self):
        """
        Create all main panels/widgets in the GUI.
        """
        self.create_panel_for_widget()
        self.create_panel_for_ip()
        self.create_panel_for_connections_info()
        self.create_panel_for_chat_history()
        self.create_panel_for_sending_text()

    def create_panel_for_sending_text(self):
        """
        Create the sending panel with text box and send button.
        """
        self.Sending_data = tk.Text(
            self.Sending_panel,
            font=('arial', 14),
            background='cornsilk2',
            width=60,
            height=10
        )
        self.Sending_data.pack(side='right')
        self.Sending_Trigger = tk.Button(
            self.Sending_panel,
            text='Send',
            width=15,
            height=5,
            bg='tan1',
            command=self.send_text_message
        )
        self.Sending_Trigger.pack(side='left')

    def create_panel_for_chat_history(self):
        """
        Create the chat history panel.
        """
        self.history = tk.Text(
            self.history_frame,
            font=('arial', 14),
            background='cornsilk2',
            width=65,
            height=18
        )
        self.history.pack()

    def create_panel_for_widget(self):
        """
        Create the left-side server control and status panels.
        """
        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=0)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(2, weight=0)

        self.server_controls = tk.LabelFrame(self, text='Server Controls', font=('arial', 16), fg='skyblue',
                                             bg='cornsilk4', height=200)
        self.server_controls.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        self.server_controls.grid_propagate(False)

        tk.Label(self.server_controls, text='Uptime:', bg='cornsilk4').pack(anchor='w', padx=5, pady=2)
        self.uptime_label = tk.Label(self.server_controls, text='00:00:00', bg='cornsilk2')
        self.uptime_label.pack(anchor='w', padx=5, pady=2)

        tk.Button(self.server_controls, text='Restart Server', bg='lightgray', command=self.restart_server).pack(fill='x', padx=5, pady=2)
        tk.Button(self.server_controls, text='Clear Logs', bg='lightgray', command=self.clear_logs).pack(fill='x', padx=5, pady=2)

        self.system_status_frame = tk.LabelFrame(self.server_controls, text='System Status', font=('arial', 14),
                                                 fg='mediumseagreen', bg='cornsilk3')
        self.system_status_frame.pack(fill='x', padx=5, pady=5)

        tk.Label(self.system_status_frame, text='CPU Usage:', bg='cornsilk3').grid(row=0, column=0, sticky='w', padx=3)
        self.cpu_label = tk.Label(self.system_status_frame, text='0%', bg='cornsilk2')
        self.cpu_label.grid(row=0, column=1, sticky='w', padx=3)

        tk.Label(self.system_status_frame, text='Memory Usage:', bg='cornsilk3').grid(row=1, column=0, sticky='w', padx=3)
        self.memory_label = tk.Label(self.system_status_frame, text='0%', bg='cornsilk2')
        self.memory_label.grid(row=1, column=1, sticky='w', padx=3)

        self.network_status_frame = tk.LabelFrame(self.server_controls, text='Network Status', font=('arial', 14),
                                                  fg='slateblue', bg='cornsilk3')
        self.network_status_frame.pack(fill='x', padx=5, pady=5)

        tk.Label(self.network_status_frame, text='Upload Speed:', bg='cornsilk3').grid(row=0, column=0, sticky='w', padx=3)
        self.upload_label = tk.Label(self.network_status_frame, text='0 KB/s', bg='cornsilk2')
        self.upload_label.grid(row=0, column=1, sticky='w', padx=3)

        tk.Label(self.network_status_frame, text='Download Speed:', bg='cornsilk3').grid(row=1, column=0, sticky='w', padx=3)
        self.download_label = tk.Label(self.network_status_frame, text='0 KB/s', bg='cornsilk2')
        self.download_label.grid(row=1, column=1, sticky='w', padx=3)


        tk.Button(
            self.server_controls,
            text='Instructions',
            bg='lightgray',
            command=show_instructions
        ).pack(fill='x', padx=5, pady=2)


        self.IP_of_server = tk.Label(self, text='IP of server', font=('arial', 18), fg='cadetblue1', bg='cornsilk4')
        self.IP_of_server.grid(sticky='w', padx=5, pady=5)

        self.Connection_info = tk.LabelFrame(self, text='Connection Info', font=('arial', 16), fg='cadetblue1',
                                             bg='cornsilk4')
        self.Connection_info.grid(row=2, column=0, sticky='nsew', padx=5, pady=5)

        self.history_frame = tk.LabelFrame(self, text='Chat History', font=('arial', 16), fg='lemonchiffon',
                                           bg='cornsilk4')
        self.history_frame.grid(row=0, column=1, rowspan=2, sticky='nsew', padx=5, pady=5)

        self.Sending_panel = tk.LabelFrame(self, text='Send Text', font=('arial', 16), fg='gold2', bg='cornsilk4')
        self.Sending_panel.grid(row=2, column=1, sticky='nsew', padx=5, pady=5)

    def update_uptime(self):
        """
        Update the uptime label every second.
        """
        elapsed = datetime.now() - self.start_time
        self.uptime_label.config(text=str(elapsed).split('.')[0])
        self.after(1000, self.update_uptime)

    def update_system_status(self):
        """
        Update the system status panel with current CPU, RAM, and network usage.
        """
        import psutil
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        self.cpu_label.config(text=f"{cpu}%")
        self.memory_label.config(text=f"{mem}%")

        now = psutil.net_io_counters()
        sent = now.bytes_sent - self._prev_net.bytes_sent
        recv = now.bytes_recv - self._prev_net.bytes_recv
        self._prev_net = now

        up_kbps = sent / 1024
        down_kbps = recv / 1024
        self.upload_label.config(text=f"{up_kbps:.1f} KB/s")
        self.download_label.config(text=f"{down_kbps:.1f} KB/s")

        self.after(1000, self.update_system_status)

    def create_panel_for_ip(self):
        """
        Create and show the server's IP address in the UI.
        """
        style = ttk.Style()
        style.configure("Custom.TFrame", background="cornsilk3")
        style.configure("Custom.TLabel", background="cornsilk3")
        style.configure("Custom.TButton", background="lightgray")

        self.frame = ttk.Frame(self.IP_of_server, style="Custom.TFrame")
        self.frame.pack(side='top', padx=10, pady=10)
        ttk.Label(self.frame, text='Server IP:', style="Custom.TLabel", font=('arial',20)).grid(row=0, column=1, sticky='w')
        ttk.Label(self.frame, text=IP_Address, style="Custom.TLabel", font=('arial',30)).grid(row=3, column=2, sticky='w')

    def create_panel_for_connections_info(self):
        """
        Create the connection info panel and all its widgets.
        """
        style = ttk.Style()
        style.configure("Custom.TFrame", background="cornsilk3")
        style.configure("Custom.TLabel", background="cornsilk3")
        style.configure("Custom.TButton", background="lightgray")

        self.frame = ttk.Frame(self.Connection_info, style="Custom.TFrame")
        self.frame.pack(side='top', padx=10, pady=10)

        ttk.Label(self.frame, text='Port:', style="Custom.TLabel", width=27).grid(row=2, column=1, sticky='w')
        ttk.Label(self.frame, text=str(PORT_), style="Custom.TLabel", width=30).grid(row=2, column=2, sticky='w')
        ttk.Label(self.frame, text='Status:', style="Custom.TLabel", width=27).grid(row=3, column=1, sticky='w')

        self.status = tk.Label(
            self.frame,
            text="Not Connected",
            width=25,
            bg="red"
        )
        self.status.grid(row=3, column=1, columnspan=2)

        self.accept_btn = tk.Button(
            self.frame,
            text="Pause Accepting",
            command=self.toggle_accepting_clients,
            bg="lightgray"
        )
        self.accept_btn.grid(row=8, column=1, pady=5)

        tk.Label(self.frame, text="System Message:", background='cornsilk3', width=23).grid(row=9, column=1)
        self.sys_msg_entry = tk.Entry(self.frame, width=30, background='cornsilk2',)
        self.sys_msg_entry.grid(row=9, column=2)
        tk.Button(self.frame, text="Broadcast", bg="rosybrown4", command=self.broadcast_system_message).grid(
            row=10,
            column=1,
            columnspan=2,
            pady=5
        )
        tk.Label(self.frame, text='Users:', background='cornsilk3').grid(row=4, column=1, sticky='w')
        self.user_listbox = tk.Listbox(self.frame, height=4)
        self.user_listbox.grid(row=4, column=2, pady=5)

        self.filter_var = tk.BooleanVar(value=True)
        cb = tk.Checkbutton(
            self.frame,
            text="Enable Profanity Filter",
            variable=self.filter_var,
            command=self.toggle_profanity_filter
        )
        cb.grid(row=6, column=1, columnspan=2)

        tk.Label(self.frame, text="Admin Cmd:", bg='cornsilk4').grid(row=7, column=1, sticky='w')
        self.cmd_entry = tk.Entry(self.frame)
        self.cmd_entry.grid(row=7, column=2)
        tk.Button(self.frame, text="Run", command=self.run_admin_cmd).grid(row=8, column=1, columnspan=2, pady=5)

    def toggle_profanity_filter(self):
        # make sure the sockets object exists
        if not hasattr(self, 's'):
            return

        new_state = self.filter_var.get()
        self.s.filter_enabled = new_state


    def update_user_list_gui(self):
        """
        Updates the user list displayed in the connection info panel.
        """
        self.user_listbox.delete(0, 'end')
        unique_users = set(self.s.usernames.values())
        for user in sorted(unique_users):
            self.user_listbox.insert('end', user)
        self.after(2000, self.update_user_list_gui)

    def handle_login_success(self, conn, username):
        """
        Handle a successful login from a client.

        Args:
            conn (socket.socket): The client socket.
            username (str): The username.
        """
        self.s.usernames[conn] = username
        if conn not in self.s.clients:
            self.s.clients.append(conn)
        logging.info("[+] %s logged in successfully", username)
        self.after(500, self.update_user_list_gui)

    def restart_server(self):
        """
        Restart the server application using exec.
        """
        if messagebox.askyesno("Restart Server", "Are you sure you want to restart the server?"):
            print("[+] Restarting server…")
            import os, sys
            os.execv(sys.executable, [sys.executable] + sys.argv)

    def clear_logs(self):
        """
        Clear the server log file and on-screen chat history.
        """
        if messagebox.askyesno("Clear Logs", "Are you sure you want to clear the logs?"):
            print("[+] Clearing logs…")
            with open("server.log", "w"):
                pass
            self.history.delete("1.0", "end")
            messagebox.showinfo("Logs Cleared", "Server logs and on-screen history have been cleared.")

    def run_admin_cmd(self):
        """
        Run an admin console command from the entry field.
        """
        cmd = self.cmd_entry.get().strip()
        if cmd == "/stats":
            stats = f"Users: {len(self.s.clients)}, Infractions: {self.s.infractions}"
            messagebox.showinfo("Server Stats", stats)
        elif cmd == "/shutdown":
            for conn in list(self.s.clients):
                try:
                    conn.sendall(b"[SYSTEM]: Server is shutting down.\n"); conn.close()
                except:
                    pass
            self.destroy()
        self.cmd_entry.delete(0, 'end')

    def toggle_accepting_clients(self):
        """
        Toggle whether the server is accepting new client connections.
        """
        accepting = self.s.toggle_accepting()
        self.accept_btn.config(text="Resume Accepting" if not accepting else "Pause Accepting")
        self.status.config(
            text="Paused accepting new clients" if not accepting else f"Connected to {len(self.s.clients)} clients",
            bg='orange' if not accepting else 'lightgreen'
        )

    def broadcast_system_message(self):
        """
        Send a system message to all connected clients.
        """
        msg = self.sys_msg_entry.get().strip()
        if msg:
            timestamp = datetime.now().strftime("[%H:%M:%S]")
            self.history.insert("end", f"{timestamp} [SYSTEM]: {msg}\n")
            self.history.see("end")
            self.s.broadcast_system_message(timestamp, msg)
            self.sys_msg_entry.delete(0, 'end')

if __name__ == '__main__':
    """
    Main entry point for the chat server admin interface.
    """
    ServerDialogBox(className='Python Chatting [Server Mode]').mainloop()