import linecache
import sys
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog, messagebox, Toplevel, Label, Button
import socket
import threading
import ssl
import base64
from io import BytesIO
from PIL import Image, ImageTk
import emoji
from datetime import datetime
import time
import winsound
from games_menu import GamesManager



IP_Address = socket.gethostbyname(socket.gethostname())
PORT_ = "5000"
SUPPORTED_FILES = [".png", ".jpg", ".jpeg", ".gif", ".bmp"]
RATE_LIMIT_SECONDS = 1.0

spinner_running = False
cancel_button = None
spinner_label = None
spinner_overlay = None

THEMES = {
     "default": {
        "bg": "cornsilk4",        # dark creamy tan
        "panel_bg": "cornsilk4",   # dark creamy tan
        "frame_bg": "cornsilk3",   # light creamy tan
        "frame_text_fg": "cornsilk1", # very pale cream
        "text_bg": "cornsilk2",    # pale yellow cream
        "text_fg": "cornsilk4",     # dark creamy tan
        "btn_bg": "tan1",           # soft tan brown
        "btn_fg": "black",          # pure black
        "receive_text": "seagreen"  # soft teal green
    },
    "light": {
        "bg": "misty rose",          # very soft pink
        "panel_bg": "bisque3",        # muted peach
        "frame_bg": "linen",           # warm light beige
        "frame_text_fg": "#333333",    # dark charcoal gray
        "text_bg": "papaya whip",     # creamy orange
        "text_fg": "#333333",          # dark charcoal gray
        "btn_bg": "navajo white",     # light pastel orange
        "btn_fg": "black",             # pure black
        "receive_text": "mediumorchid" # medium bright purple
    },
    "chocolate": {
        "bg": "#2E2B2B",             # very dark gray
        "panel_bg": "#3E3A3A",        # darker slate gray
        "frame_bg": "#4B3F39",        # muted brown gray
        "frame_text_fg": "#F5DEB3",    # soft wheat
        "text_bg": "#5C5148",         # rich dark mocha
        "text_fg": "#F5DEB3",          # soft wheat
        "btn_bg": "#6E5849",          # medium warm brown
        "btn_fg": "white",             # pure white
        "receive_text": "lightblue"    # very pale blue
    },
    "blue": {
        "bg": "#005954",             # deep sea teal
        "panel_bg": "#338b85",        # medium teal
        "frame_bg": "#5dc1b9",        # light aqua teal
        "frame_text_fg": "white",      # pure white
        "text_bg": "#9ae7e3",         # soft turquoise
        "text_fg": "white",            # pure white
        "btn_bg": "#338b85",           # medium teal
        "btn_fg": "white",             # pure white
        "receive_text": "royalblue"    # bright royal blue
    },
    "matte": {
        "bg": "#1c1c1c",             # deep matte black
        "panel_bg": "#2b2b2b",        # charcoal black
        "frame_bg": "#3a3a3a",        # dark gray
        "frame_text_fg": "#d3d3d3",    # light silver gray
        "text_bg": "#4a4a4a",         # mid-dark gray
        "text_fg": "#d3d3d3",          # light silver gray
        "btn_bg": "#5a5a5a",           # steel gray
        "btn_fg": "white",             # pure white
        "receive_text": "gold"          # bright metallic yellow
    },
    "sunset": {
        "bg": "#FF5E5B",             # bright sunset red
        "panel_bg": "#FFB400",         # vivid golden yellow
        "frame_bg": "#FF8A5B",         # strong peach orange
        "frame_text_fg": "#3B0D0C",    # deep brown
        "text_bg": "#FFD6A5",          # soft peach cream
        "text_fg": "#3B0D0C",           # deep brown
        "btn_bg": "#F76C5E",           # salmon coral
        "btn_fg": "white",             # pure white
        "receive_text": "orangered"     # fiery red-orange
    },
    "forest": {
        "bg": "#2F3E46",             # deep pine green
        "panel_bg": "#52796F",         # muted jungle green
        "frame_bg": "#84A98C",         # sage green
        "frame_text_fg": "#1B1A17",     # very dark olive
        "text_bg": "#CAD2C5",          # pale moss
        "text_fg": "#1B1A17",           # very dark olive
        "btn_bg": "#354F52",           # midnight green
        "btn_fg": "white",             # pure white
        "receive_text": "limegreen"     # fresh bright green
    },
    "pastel": {
        "bg": "#fceef5",             # pastel pink
        "panel_bg": "#f8d6e0",        # rosy pink
        "frame_bg": "#fcdada",         # pale peach pink
        "frame_text_fg": "#f9b4c3",    # dusty pink
        "text_bg": "#fff0f5",          # soft white pink
        "text_fg": "#4a4a4a",          # charcoal gray
        "btn_bg": "#f9b4c3",           # dusty pink
        "btn_fg": "#4a4a4a",            # charcoal gray
        "receive_text": "deeppink"      # strong vivid pink
    },
    "neon": {
        "bg": "#0F0F0F",             # pitch black
        "panel_bg": "#1A1A1D",         # dark grayish black
        "frame_bg": "#333333",         # medium dark gray
        "frame_text_fg": "#39FF14",     # bright neon green
        "text_bg": "#1A1A1D",          # dark gray black
        "text_fg": "#39FF14",           # bright neon green
        "btn_bg": "#1F1F1F",            # almost black
        "btn_fg": "#39FF14",            # neon green
        "receive_text": "magenta"       # electric purple-pink
    },
    "ocean": {
        "bg": "#011F4B",             # deep navy blue
        "panel_bg": "#03396C",         # dark ocean blue
        "frame_bg": "#005B96",         # strong marine blue
        "frame_text_fg": "#EAF6FF",     # icy white blue
        "text_bg": "#6497B1",          # sky blue gray
        "text_fg": "#EAF6FF",           # icy white blue
        "btn_bg": "#03396C",            # dark ocean blue
        "btn_fg": "#EAF6FF",             # icy white blue
        "receive_text": "lightcyan"      # pale icy cyan
    },
    "vintage": {
        "bg": "#704214",             # sepia brown
        "panel_bg": "#C0A080",         # soft tan
        "frame_bg": "#A77B5A",         # warm mid-brown
        "frame_text_fg": "#FFFFFF",     # white
        "text_bg": "#D2B48C",          # tan
        "text_fg": "#5B4636",           # dark brown
        "btn_bg": "#A77B5A",            # warm brown
        "btn_fg": "#FFFFFF",            # white text
        "receive_text": "saddlebrown"  # deep brown
    },
    "dusk": {
        "bg": "#2E1A47",             # twilight purple
        "panel_bg": "#3C1361",         # dark violet
        "frame_bg": "#5E239D",         # rich purple
        "frame_text_fg": "#E0C3FC",     # soft lavender
        "text_bg": "#A4508B",          # mauve
        "text_fg": "#FFFFFF",           # white text
        "btn_bg": "#5E239D",            # rich purple
        "btn_fg": "#E0C3FC",             # lavender
        "receive_text": "orchid"        # vibrant purple pink
    },
    "cyberpunk": {
        "bg": "#0A0A23",             # dark midnight
        "panel_bg": "#1A1A3D",         # dark navy
        "frame_bg": "#292961",         # deep blue
        "frame_text_fg": "#FF00FF",     # magenta
        "text_bg": "#191933",          # deep night blue
        "text_fg": "#FF00FF",           # magenta
        "btn_bg": "#FF00FF",            # neon pink
        "btn_fg": "#0A0A23",            # midnight
        "receive_text": "cyan"          # bright cyan
    },
    "autumn": {
        "bg": "#FFBB73",             # light orange
        "panel_bg": "#FF944D",         # pumpkin orange
        "frame_bg": "#FF7733",         # sunset orange
        "frame_text_fg": "#663300",     # dark brown
        "text_bg": "#FFE6CC",          # pale orange
        "text_fg": "#663300",           # dark brown
        "btn_bg": "#FF944D",            # pumpkin orange
        "btn_fg": "#663300",            # dark brown
        "receive_text": "orangered"     # rich orange-red
    },
    "lavender": {
        "bg": "#E6E6FA",             # lavender
        "panel_bg": "#D8BFD8",         # thistle
        "frame_bg": "#DDA0DD",         # plum
        "frame_text_fg": "#4B0082",     # indigo
        "text_bg": "#F8F8FF",          # ghost white
        "text_fg": "#4B0082",           # indigo
        "btn_bg": "#DDA0DD",            # plum
        "btn_fg": "#4B0082",            # indigo
        "receive_text": "mediumorchid" # vivid purple
    },
    "desert": {
        "bg": "#EDC9AF",             # desert sand
        "panel_bg": "#C2B280",         # sand
        "frame_bg": "#A67B5B",         # earth brown
        "frame_text_fg": "#5C4033",     # deep brown
        "text_bg": "#FFF8DC",          # cornsilk
        "text_fg": "#5C4033",           # deep brown
        "btn_bg": "#C2B280",            # sand
        "btn_fg": "#5C4033",            # deep brown
        "receive_text": "sienna"        # reddish brown
    },
    "aurora": {
        "bg": "#001F3F",             # midnight blue
        "panel_bg": "#0074D9",         # strong blue
        "frame_bg": "#39CCCC",         # teal
        "frame_text_fg": "#7FDBFF",     # sky blue
        "text_bg": "#001F3F",          # midnight blue
        "text_fg": "#7FDBFF",           # sky blue
        "btn_bg": "#39CCCC",            # teal
        "btn_fg": "#001F3F",            # midnight blue
        "receive_text": "mediumturquoise" # blue teal
    },
    "steel": {
        "bg": "#3C3C3C",             # dark gray
        "panel_bg": "#5A5A5A",         # steel gray
        "frame_bg": "#7A7A7A",         # light steel
        "frame_text_fg": "#C0C0C0",     # silver
        "text_bg": "#A9A9A9",          # light gray
        "text_fg": "#C0C0C0",           # silver
        "btn_bg": "#5A5A5A",            # steel gray
        "btn_fg": "#C0C0C0",            # silver
        "receive_text": "lightsteelblue" # soft blue gray
    },
    "bubblegum": {
        "bg": "#FF69B4",             # hot pink
        "panel_bg": "#BA55D3",         # medium orchid
        "frame_bg": "#9370DB",         # medium purple
        "frame_text_fg": "#00FFFF",     # aqua
        "text_bg": "#FFE4E1",          # misty rose
        "text_fg": "#00FFFF",           # aqua
        "btn_bg": "#BA55D3",            # orchid
        "btn_fg": "#00FFFF",            # aqua
        "receive_text": "yellow"        # bright yellow
    }
}



def print_exception():
    """
    Print the most recent exception with its file, line, and code context.

    This function is intended to aid debugging by showing where an exception occurred,
    along with the relevant code line.
    """
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print('EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj))


def is_valid_ip(ip):
    """
    Validates the format of an IPv4 address.

    Args:
        ip (str): The IP address string to validate.

    Returns:
        bool: True if valid IPv4, False otherwise.
    """
    import re
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(pattern, ip):
        return all(0 <= int(octet) <= 255 for octet in ip.split("."))
    return False


def send_server(ip_var, username_var, password_var, mainroot):
    """
    Sends the login/register request to the server and closes the dialog on success.
    Adds retry mechanism with animated circular spinner, cancel button, dim overlay, and sound feedback.

    Args:
        ip_var (tk.StringVar): Variable holding the IP address.
        username_var (tk.StringVar): Variable holding the username.
        password_var (tk.StringVar): Variable holding the password.
        mainroot (tk.Toplevel): The parent dialog widget.
    """
    def attempt_connection():
        """
        Attempt to connect to the server and handle login/register response.
        Handles spinner and cancellation logic.
        """
        global spinner_running, cancel_button, spinner_label, spinner_overlay

        if spinner_running:
            return

        spinner_running = True

        # Create semi-transparent overlay
        spinner_overlay = tk.Frame(mainroot, bg='#FFF5E1')
        spinner_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        spinner_overlay.attributes = {}
        try:
            spinner_overlay.attributes['alpha'] = spinner_overlay.tk.call("tk", "windowingsystem") == 'win32'
            spinner_overlay.configure(bg="#FFF5E1", highlightthickness=0)
        except:
            pass

        spinner_chars = ['◜', '◠', '◝', '◞', '◡', '◟']
        spinner_label = tk.Label(spinner_overlay, text="Connecting", font=("Segoe UI", 12, "bold"), fg="#CC5500", bg='#FFF5E1')
        spinner_label.place(relx=0.5, rely=0.4, anchor='center')

        def cancel():
            """Cancel spinner and close overlay."""
            global spinner_running, cancel_button, spinner_label, spinner_overlay
            spinner_running = False
            if spinner_label:
                spinner_label.destroy()
                spinner_label = None
            if cancel_button:
                cancel_button.destroy()
                cancel_button = None
            if spinner_overlay:
                spinner_overlay.destroy()
                spinner_overlay = None

        if cancel_button:
            cancel_button.destroy()

        cancel_button = tk.Button(spinner_overlay, text="Cancel", command=cancel, bg="#FFA07A", fg="#333333", relief=tk.RAISED)
        cancel_button.place(relx=0.5, rely=0.85, anchor='center')

        def animate_spinner():
            """Animate the connection spinner."""
            idx = 0
            def loop():
                nonlocal idx
                if spinner_running and spinner_label:
                    spinner_label.config(
                        text=f"Connecting... {spinner_chars[idx % len(spinner_chars)]}"
                    )
                    idx += 1
                    mainroot.after(100, loop)
            loop()

        mainroot.after(0, animate_spinner)

        ip = ip_var.get()
        port = 5000
        username = username_var.get().strip()
        password = password_var.get().strip()

        if not ip or not username or not password:
            cancel()
            return messagebox.showwarning("Input Error", "All fields must be filled out.")

        if not is_valid_ip(ip):
            cancel()
            return messagebox.showerror("Invalid IP", "Please enter a valid IPv4 address.")

        retry_attempts = 3
        for attempt in range(retry_attempts):
            if not spinner_running:
                break
            try:
                raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_socket.settimeout(10)

                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                ssl_socket = context.wrap_socket(raw_socket, server_hostname=ip)
                ssl_socket.connect((ip, int(port)))

                message = f"Verify-Client.Ser ,{username},{password}\n"
                ssl_socket.sendall(message.encode("utf-8"))
                data = ssl_socket.recv(1024).decode()

                ssl_socket.close()
                cancel()

                if data == "1":
                    winsound.MessageBeep(winsound.MB_OK)
                    messagebox.showinfo("Success", "Logged in")
                    mainroot.destroy()
                    mainroot.quit()
                    return
                elif data == "2":
                    winsound.MessageBeep(winsound.MB_ICONHAND)
                    messagebox.showerror("Failed", "Wrong password")
                    return
                elif data == "3":
                    winsound.MessageBeep(winsound.MB_OK)
                    messagebox.showinfo("Success", "Registered")
                    mainroot.destroy()
                    mainroot.quit()
                    return
                else:
                    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
                    messagebox.showerror("Error", f"Unexpected server response: {data}")
                    return
            except Exception as e:
                if attempt == retry_attempts - 1:
                    cancel()
                    winsound.MessageBeep(winsound.MB_ICONHAND)
                    messagebox.showerror("Connection Error", f"Failed after {retry_attempts} attempts.\n{e}")
                time.sleep(1.5)

    threading.Thread(target=attempt_connection, daemon=True).start()


def ask_ip_dialog(ip_var, port_var, username_var, password_var):
    """
    Displays a dialog for entering server connection information.

    Args:
        ip_var (tk.StringVar): IP address variable.
        port_var (tk.IntVar): Port variable.
        username_var (tk.StringVar): Username variable.
        password_var (tk.StringVar): Password variable.
    """
    mainroot = tk.Toplevel()
    mainroot.title("Enter Connection Info")
    mainroot.resizable(False, False)
    mainroot.focus_force()

    frame = ttk.Frame(mainroot)
    frame.pack(padx=10, pady=10)

    port_var.set(5000)
    labels = ["Server IP Address:", "Username:", "Password:", "Port:"]
    variables = [ip_var, username_var, password_var, port_var]
    show_values = [None, None, '*', None]

    for i, (label, var, show) in enumerate(zip(labels, variables, show_values)):
        ttk.Label(frame, text=label, width=20, anchor='e').grid(row=i, column=0)
        ttk.Entry(frame, textvariable=var, width=25, show=show).grid(row=i, column=1)

    ttk.Entry(frame, textvariable=port_var, state='disabled', width=25).grid(row=3, column=1)

    ttk.Button(
        frame,
        text="Login/Register",
        command=lambda: send_server(ip_var, username_var, password_var, mainroot),
        width=20
    ).grid(row=4, column=0, columnspan=2, pady=10)

    mainroot.mainloop()


class SOCKETS:
    """Class to manage all client socket communications and chat protocol."""

    def __init__(self):
        """Initialize the SOCKETS object and internal state."""
        self.s = None
        print("[+] Socket is now created")

    def load(self, ip_address, port, text, status, server_info, username, connect_button, log_panel=None, typing_indicator=None):
        """
        Load the GUI variables and setup the connection parameters.

        Args:
            ip_address (tk.StringVar): IP Address variable.
            port (tk.IntVar): Port variable.
            text (tk.Text): Text widget for chat history.
            status (tk.Button): Status button widget.
            server_info (ttk.Label): Label for server info.
            username (tk.StringVar): Username variable.
            connect_button (tk.Button): Button to connect/reconnect.
            log_panel (tk.Text, optional): Log panel widget.
            typing_indicator (tk.Label, optional): Typing indicator widget.
        """
        self.ip_address = ip_address
        self.port = port
        self.history = text
        self.status = status
        self.server_info = server_info
        self.username = username
        self.connect_button = connect_button
        self.reconnect_attempts = 0
        self.log_panel = log_panel
        self.typing_indicator = typing_indicator

    def log(self, message):
        """
        Log a message to the log panel if it exists.

        Args:
            message (str): Message to log.
        """
        if self.log_panel:
            self.log_panel.config(state='normal')
            self.log_panel.insert('end', f"{message}\n")
            self.log_panel.config(state='disabled')
            self.log_panel.see('end')

    def bind(self):
        """
        Connect to the server and start the receiving thread.
        Handles auto-retry and status updates in the GUI.
        """
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.s = context.wrap_socket(raw_sock, server_hostname=self.ip_address.get())
        max_attempts = 5

        while self.reconnect_attempts < max_attempts:
            try:
                self.log(f"Attempt {self.reconnect_attempts + 1}: Trying to connect...")
                self.s.connect((self.ip_address.get(), int(self.port.get())))
                self.server_info.config(text=f"{self.ip_address.get()}:{self.port.get()}")
                self.status.config(text="Connected", bg='lightgreen')
                if self.connect_button:
                    self.connect_button.config(state='disabled')
                self.log("Connected to server.")
                threading.Thread(target=self.recv, daemon=True).start()
                self.reconnect_attempts = 0
                return
            except Exception:
                self.reconnect_attempts += 1
                self.log("Connection failed. Retrying...")

        self.log("Max attempts reached. Connection failed.")
        messagebox.showerror("Connection Error", "Server is not accepting connections.")
        if self.connect_button:
            self.connect_button.config(state='normal')

    def recv(self):
        """
        Receive messages and images from the server, updating the GUI appropriately.
        Handles both text and image messages, as well as connection loss.
        """
        buffer = b""
        while True:
            try:
                data = self.s.recv(4096)
                if not data:
                    raise ConnectionResetError("Connection lost")
                buffer += data

                while buffer:
                    if buffer.startswith(b"[IMG]"):
                        try:
                            b64_data = buffer[5:].split(b"\n")[0]
                            img_data = base64.b64decode(b64_data)
                            img = Image.open(BytesIO(img_data))
                            img.thumbnail((150, 150))
                            thumb = ImageTk.PhotoImage(img)
                            self._display_image_in_chat(thumb, img_data)
                            buffer = buffer[5 + len(b64_data) + 1:]
                        except Exception:
                            break
                    else:
                        try:
                            msg = buffer.decode('utf-8')
                            self.history.config(state='normal')
                            start = self.history.index('end') + "-1l"
                            self.history.insert("end", f"{emoji.emojize(msg, language='alias')}\n")
                            end = self.history.index('end') + "-1l"
                            self.history.tag_add("RECV_TEXT", start, end)
                            self.history.tag_config("RECV_TEXT", foreground=self.history.master.receive_text_color)
                            self.history.config(state='disabled')
                            self.history.see("end")
                            buffer = b""
                            if self.typing_indicator:
                                self.typing_indicator.config(text="hi")
                            break
                        except Exception:
                            break
            except Exception as e:
                print(e, 'recv')
                self.status.config(text="Connection Lost", bg='red')
                if self.connect_button:
                    self.connect_button.config(state='normal')
                self.log("Connection lost.")
                break

    def send(self, text: str):
        """
        Send a text message or special command to the server.

        Args:
            text (str): The message or command to send.
        """
        try:
            now = time.time()
            if hasattr(self, 'last_sent_time') and now - self.last_sent_time < RATE_LIMIT_SECONDS:
                messagebox.showwarning("Rate Limit", "Please wait before sending another message.")
                return
            self.last_sent_time = now

            text = emoji.emojize(text, language='alias')
            if text.startswith('/resetpass-'):
                self.s.sendall((text + "\n").encode('utf-8'))
            else:
                timestamp = datetime.now().strftime("[%H:%M:%S]")
                message = f"{timestamp} {self.username.get()}: {text}"
                self.s.sendall((message + "\n").encode('utf-8'))
        except Exception as e:
            print("[=] Not connected", e)

    def send_image(self, image_path):
        """
        Send an image file to the server.

        Args:
            image_path (str): Path to the image file to send.
        """
        try:
            img = Image.open(image_path)
            img.thumbnail((800, 800))
            buffer = BytesIO()
            img.save(buffer, format="JPEG", quality=85)
            buffer.seek(0)

            if len(buffer.getvalue()) > 5 * 1024 * 1024:
                messagebox.showerror("Image Too Large", "Image exceeds 5MB even after compression.")
                return

            encoded = base64.b64encode(buffer.read()).decode('utf-8')
            message = f"[IMG]{encoded}\n"
            self.s.sendall(message.encode('utf-8'))
            self._add_sent_image_to_chat(image_path)

        except Exception as e:
            print("[!] Failed to send image", e)

    def _add_sent_image_to_chat(self, image_path):
        """
        Add a sent image to the chat history.

        Args:
            image_path (str): Path to the sent image file.
        """
        img = Image.open(image_path)
        img.thumbnail((150, 150))
        thumb = ImageTk.PhotoImage(img)
        self.history.config(state='normal')
        index = self.history.index("end")
        self.history.image_create("end", image=thumb)
        self.history.insert("end", " (Image sent)\n")
        if not hasattr(self.history, '_image_refs'):
            self.history._image_refs = []
        self.history._image_refs.append(thumb)
        self.history.config(state='disabled')

    def _display_image_in_chat(self, thumb, img_data):
        """
        Display a received image in the chat history and support preview.

        Args:
            thumb (ImageTk.PhotoImage): Thumbnail image.
            img_data (bytes): Raw image data.
        """
        self.history.config(state='normal')
        index = self.history.index("end")
        tag_name = f"IMG_TAG_{len(getattr(self.history, '_image_refs', []))}"
        self.history.image_create(index, image=thumb)
        self.history.insert("end", " (Image received)\n")
        if not hasattr(self.history, '_image_refs'):
            self.history._image_refs = []
        self.history._image_refs.append(thumb)
        self.history.tag_add(tag_name, index, f"{index} +1 line")

        def preview():
            """Show a preview of the image in a new window."""
            top = Toplevel()
            top.title("Preview")
            image = Image.open(BytesIO(img_data))
            photo = ImageTk.PhotoImage(image)
            label = Label(top, image=photo)
            label.image = photo
            label.pack()

        self.history.tag_bind(tag_name, "<Button-1>", lambda e: preview())
        self.history.config(state='disabled')


class EmojiPicker(Toplevel):
    """A dialog for picking and inserting emojis into a text widget."""

    def __init__(self, parent, target_text_widget):
        """
        Initialize the EmojiPicker dialog.

        Args:
            parent (tk.Widget): The parent widget.
            target_text_widget (tk.Text): The text widget to insert emoji into.
        """
        super().__init__(parent)
        self.title("Emoji Picker")
        self.geometry("500x600")
        self.target = target_text_widget

        emojis = {
            "Smileys": [":grinning:", ":smiley:", ":smile:", ":grin:", ":laughing:", ":sweat_smile:", ":joy:", ":rofl:",
                        ":relaxed:", ":blush:", ":innocent:", ":slightly_smiling_face:", ":upside_down_face:", ":wink:",
                        ":relieved:", ":heart_eyes:", ":kissing_heart:", ":kissing:", ":kissing_smiling_eyes:",
                        ":kissing_closed_eyes:", ":face_with_hand_over_mouth:", ":face_with_monocle:", ":nerd_face:",
                        ":star_struck:", ":partying_face:", ":cold_face:", ":hot_face:", ":smiling_face_with_tear:",
                        ":face_with_head_bandage:", ":nauseated_face:", ":woozy_face:", ":pleading_face:",
                        ":exploding_head:", ":shushing_face:", ":yawning_face:", ":thinking_face:", ":sleeping:",
                        ":sleepy:", ":expressionless:", ":no_mouth:", ":neutral_face:"],
            "Gestures": [":wave:", ":raised_back_of_hand:", ":raised_hand_with_fingers_splayed:", ":hand:", ":v:",
                         ":metal:", ":call_me_hand:", ":point_left:", ":point_right:", ":point_up_2:", ":point_down:",
                         ":thumbsup:", ":thumbsdown:", ":clap:", ":raised_hands:", ":open_hands:",
                         ":palms_up_together:", ":handshake:", ":pray:", ":ok_hand:", ":pinching_hand:",
                         ":pinched_fingers:", ":vulcan_salute:", ":crossed_fingers:", ":writing_hand:", ":selfie:",
                         ":love_you_gesture:", ":call_me_hand:", ":oncoming_fist:", ":left_facing_fist:",
                         ":right_facing_fist:", ":fist:", ":backhand_index_pointing_right:",
                         ":index_pointing_at_the_viewer:", ":middle_finger:", ":raised_hand:",
                         ":backhand_index_pointing_up:", ":backhand_index_pointing_down:"],
            "Emotions": [":red_heart:", ":orange_heart:", ":yellow_heart:", ":green_heart:", ":blue_heart:",
                         ":purple_heart:", ":brown_heart:", ":black_heart:", ":white_heart:", ":broken_heart:",
                         ":heart_on_fire:", ":heart_with_arrow:", ":heartpulse:", ":sparkling_heart:", ":cupid:",
                         ":revolving_hearts:", ":anger:", ":boom:", ":sweat_drops:", ":dash:", ":zzz:", ":poop:",
                         ":100:", ":collision:", ":dizzy:", ":anger_symbol:", ":cry:", ":sob:", ":persevere:",
                         ":disappointed_relieved:", ":weary:", ":tired_face:", ":yawning_face:", ":triumph:",
                         ":fearful:", ":anguished:", ":grimacing:", ":scream:", ":confounded:"],
            "Animals": [":dog:", ":cat:", ":mouse:", ":hamster:", ":rabbit:", ":fox:", ":bear:", ":panda_face:",
                        ":koala:", ":tiger:", ":lion:", ":cow:", ":pig:", ":frog:", ":monkey:", ":chicken:",
                        ":penguin:", ":bird:", ":baby_chick:", ":unicorn:", ":boar:", ":dromedary_camel:",
                        ":two_hump_camel:", ":elephant:", ":goat:", ":ram:", ":sheep:", ":horse:", ":racehorse:",
                        ":deer:", ":llama:", ":giraffe:", ":zebra:", ":gorilla:", ":rhinoceros:", ":kangaroo:",
                        ":badger:", ":sloth:", ":otter:"],
            "Food": [":apple:", ":green_apple:", ":pear:", ":peach:", ":cherries:", ":strawberry:", ":blueberries:",
                     ":melon:", ":watermelon:", ":banana:", ":pineapple:", ":mango:", ":grapes:", ":kiwi_fruit:",
                     ":tomato:", ":eggplant:", ":avocado:", ":carrot:", ":corn:", ":hot_pepper:", ":cucumber:",
                     ":broccoli:", ":garlic:", ":onion:", ":potato:", ":bread:", ":croissant:", ":bagel:", ":pancakes:",
                     ":cheese:", ":meat_on_bone:", ":poultry_leg:", ":cut_of_meat:", ":bacon:", ":taco:", ":burrito:",
                     ":hamburger:", ":fries:", ":pizza:"],
            "Nature": [":sunny:", ":cloud:", ":rainbow:", ":snowflake:", ":fire:", ":star:", ":crescent_moon:",
                       ":sunflower:", ":rose:", ":hibiscus:", ":cactus:", ":palm_tree:", ":four_leaf_clover:",
                       ":seedling:", ":maple_leaf:", ":fallen_leaf:", ":cherry_blossom:", ":mushroom:", ":herb:",
                       ":mountain:", ":volcano:", ":desert:", ":water_wave:", ":ocean:", ":tornado:", ":fog:",
                       ":wind_face:", ":comet:", ":earth_americas:", ":earth_africa:", ":earth_asia:", ":milky_way:",
                       ":shamrock:", ":bouquet:", ":butterfly:", ":spider:", ":snail:"],
            "Travel": [":airplane:", ":rocket:", ":ship:", ":train:", ":tram:", ":bus:", ":car:", ":bicycle:",
                       ":motor_scooter:", ":motorcycle:", ":taxi:", ":fire_engine:", ":ambulance:", ":police_car:",
                       ":station:", ":fuelpump:", ":helicopter:", ":busstop:", ":bullettrain_front:",
                       ":bullettrain_side:", ":steam_locomotive:", ":canoe:", ":sailboat:", ":mountain_railway:",
                       ":aerial_tramway:", ":ferry:", ":minibus:", ":oncoming_police_car:", ":oncoming_taxi:",
                       ":oncoming_bus:", ":kick_scooter:", ":auto_rickshaw:", ":pickup_truck:", ":articulated_lorry:",
                       ":tractor:", ":speedboat:", ":parachute:"],
            "Objects": [":watch:", ":alarm_clock:", ":stopwatch:", ":hourglass:", ":light_bulb:", ":flashlight:",
                        ":battery:", ":electric_plug:", ":computer:", ":desktop_computer:", ":printer:", ":keyboard:",
                        ":trackball:", ":joystick:", ":microphone:", ":headphones:", ":speaker:", ":loudspeaker:",
                        ":megaphone:", ":radio:", ":tv:", ":camera:", ":video_camera:", ":telephone:", ":pager:",
                        ":fax:", ":satellite:", ":magnifying_glass_tilted_left:", ":magnifying_glass_tilted_right:",
                        ":lock:", ":key:", ":wrench:", ":hammer:", ":nut_and_bolt:", ":gear:"],
            "Symbols": [":check_mark:", ":recycle:", ":peace_symbol:", ":radioactive:", ":biohazard:", ":infinity:",
                        ":heart_exclamation:", ":star_of_david:", ":om_symbol:", ":yin_yang:", ":wheel_of_dharma:",
                        ":trident:", ":menorah:", ":six_pointed_star:", ":aquarius:", ":aries:", ":cancer:",
                        ":capricorn:", ":gemini:", ":leo:", ":libra:", ":pisces:", ":sagittarius:", ":scorpius:",
                        ":taurus:", ":virgo:", ":warning:", ":prohibited:", ":no_entry:", ":no_smoking:",
                        ":do_not_litter:", ":non-potable_water:", ":underage:", ":wheelchair:", ":recycle:",
                        ":sparkle:"]
        }

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True)

        for category, em_list in emojis.items():
            frame = ttk.Frame(self.tabs)
            self.tabs.add(frame, text=category)

            for idx, em in enumerate(em_list):
                try:
                    display = emoji.emojize(em, language='alias')
                    if display == em:  # Skip if the emoji alias isn't valid
                        continue
                    btn = Button(frame, text=display, font=("Arial", 24), width=3, command=lambda e=em: self.insert_emoji(e))
                    btn.grid(row=idx // 6, column=idx % 6, padx=8, pady=8)
                except Exception as e:
                    print(f"[!] Error processing emoji {em}: {e}")
                    continue

    def insert_emoji(self, em):
        """
        Insert the selected emoji into the target text widget and close the picker.

        Args:
            em (str): Emoji shortcode to insert.
        """
        self.target.insert("insert", em)
        self.destroy()


class ClientDialogBox(tk.Tk):
    """Main chat client application window."""

    def __init__(self, *args, **kwargs):
        """
        Initialize the chat client window, variables, and GUI layout.
        """
        super().__init__(*args, **kwargs)
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.ip_address = tk.StringVar()
        self.port = tk.IntVar()
        self.resizable(False, False)
        self.current_theme = "default"
        self.s = None
        self.chat_cache = ""
        self.image_refs_cache = []
        self.apply_theme(self.current_theme)
        self.ask_ip_address()
        self.attributes('-fullscreen', True)
        self.create_additional_widgets()

    def apply_theme(self, theme_name):
        """
        Apply the selected theme to the application.

        Args:
            theme_name (str): Name of the theme from THEMES.
        """
        theme = THEMES[theme_name]
        self.target_colors = theme

        def animate_transition(duration=0.2, steps=20):
            """
            Animate the background color transition for smoothness.

            Args:
                duration (float): Total duration of the animation in seconds.
                steps (int): Number of animation steps.
            """
            for _ in range(steps):
                self.update_idletasks()
                time.sleep(duration / steps)
            self.configure(bg=theme['bg'])

        threading.Thread(target=animate_transition, daemon=True).start()

        self.bg_color = theme['bg']
        self.panel_bg = theme['panel_bg']
        self.frame_bg = theme['frame_bg']
        self.frame_fg = theme['frame_text_fg']
        self.text_bg = theme['text_bg']
        self.text_fg = theme['text_fg']
        self.btn_bg = theme['btn_bg']
        self.btn_fg = theme['btn_fg']
        self.receive_text_color = theme.get('receive_text', 'green')  # default if missing

        if hasattr(self, 'history'):
            self.history.tag_config("RECV_TEXT", foreground=self.receive_text_color)

    def set_theme(self, event=None):
        """
        Handle theme selection from the dropdown and apply theme.

        Args:
            event: Tkinter event object (optional).
        """
        selected = self.theme_selector.get()
        if selected in THEMES:
            self.current_theme = selected
            self.apply_theme(self.current_theme)

            if hasattr(self, 'history'):
                self.chat_cache = self.history.get("1.0", "end")
                while self.chat_cache.endswith("\n"):
                    self.chat_cache = self.chat_cache[:-2:]
                self.chat_cache += "\n"
                self.image_refs_cache = getattr(self.history, '_image_refs', []).copy()

            self.disconnect_from_server()
            self.clear_widgets()
            self.create_additional_widgets()
            self.reconnect_to_server()

            if self.chat_cache.strip():
                self.history.config(state='normal')
                self.history.insert('1.0', self.chat_cache)
                self.history.config(state='disabled')

            if self.image_refs_cache:
                self.history._image_refs = []
                for ref in self.image_refs_cache:
                    self.history.image_create("end", image=ref)
                    self.history.insert("end", " (Image restored)\n")
                    self.history._image_refs.append(ref)

    def disconnect_from_server(self):
        """
        Disconnect from the server and close the socket.
        """
        if self.s:
            try:
                self.s.s.close()
            except:
                pass
            self.s = None

    def reconnect_to_server(self):
        """
        Attempt to reconnect to the server using the current IP and port.
        """
        if len(self.ip_address.get().split('.')) == 4:
            try:
                from client import SOCKETS  # assuming SOCKETS is defined in client.py
                self.s = SOCKETS()
                self.s.load(self.ip_address, self.port, self.history, self.status, self.server_info, self.username, self.status)
                self.s.bind()
            except Exception as e:
                print("[!] Failed to reconnect:", e)

    def clear_widgets(self):
        """
        Destroy all widgets in the main window (for theme/layout reload).
        """
        for widget in self.winfo_children():
            widget.destroy()

    def ask_ip_address(self):
        """
        Popup dialog for asking IP address and port on startup.
        """
        ask_ip_dialog(self.ip_address, self.port, self.username, self.password)

    def socket_connections_start(self):
        """
        Start the socket connection to the server in a separate thread.
        """
        if len(self.ip_address.get().split('.')) == 4:
            threading.Thread(target=self.socket_connections, daemon=True).start()

    def socket_connections(self):
        """
        Initialize and bind the socket connection.
        """
        self.s = SOCKETS()
        self.s.load(
            self.ip_address,
            self.port,
            self.history,
            self.status,
            self.server_info,
            self.username,
            self.status,
            self.log_panel,
            self.typing_indicator
        )
        self.s.bind()

    def update_status(self, Connection='Connected', color='lightgreen'):
        """
        Update the status button text and color.

        Args:
            Connection (str): Status message.
            color (str): Background color.
        """
        self.status.config(text=Connection, bg=color)

    def create_additional_widgets(self):
        """
        Create all primary widgets and panels for the main window.
        """
        self.create_exit_button()
        self.create_theme_selector()
        self.create_panel_for_widget()
        self.create_help_button()
        self.create_games_button()
        self.create_panel_for_connections_info()
        self.create_panel_for_chat_history()
        self.create_panel_for_sending_text()

    def create_exit_button(self):
        """
        Creates an Exit button in the top-right corner.
        """
        exit_button = tk.Button(self, text="Exit", bg="red3", fg="white", command=self.destroy, width=8, height=1)
        exit_button.place(relx=0.95, rely=0.01, anchor="ne")

    def create_theme_selector(self):
        """
        Creates the theme selection dropdown in the top-right corner.
        """
        self.theme_selector = ttk.Combobox(self, values=list(THEMES.keys()), state="readonly", width=8)
        self.theme_selector.set(self.current_theme)
        self.theme_selector.place(relx=0.85, rely=0.01, anchor="ne")
        self.theme_selector.bind("<<ComboboxSelected>>", self.set_theme)

    def create_games_button(self):
        """
        Create a Games button in the top right corner, under help.
        """
        self.games_manager = GamesManager(self)
        games_button = tk.Button(
            self, text="Games", bg="plum2", fg="black",
            command=self.games_manager.show_games_menu,
            width=8, height=1
        )
        # Place it next the help button (which is at relx=0.95, rely=0.07)
        games_button.place(relx=0.90, rely=0.07, anchor="ne")

    def send_text_message(self):
        """
        Send the content of the text input box as a chat message to the server.
        Handles special commands and help.
        """
        if self.status.cget('text') == 'Connected':
            input_data = self.Sending_data.get('1.0', 'end').strip()
            if input_data:
                if input_data == "?help":
                    self.show_help_window()
                elif input_data.startswith("/resetpass-"):
                    self.s.send(input_data)
                else:
                    self.s.send(input_data)
                    timestamp = datetime.now().strftime("[%H:%M:%S]")
                    input_data = emoji.emojize(f"{timestamp} Me: {input_data}\n", language='alias')
                    self.history.config(state='normal')
                    start = self.history.index('end') + "-1l"
                    self.history.insert("end", input_data)
                    end = self.history.index('end') + "-1l"
                    self.history.tag_add("SENDBYME", start, end)
                    self.history.tag_config("SENDBYME", foreground=self.text_fg)
                    self.history.config(state='disabled')
                self.Sending_data.delete('1.0', 'end')
            else:
                print("[=] Input not provided")
        else:
            print("[+] Not Connected")

    def send_image_message(self):
        """
        Open a file dialog to select and send an image to the server.
        """
        if self.status.cget('text') == 'Connected':
            filepath = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp")])
            if filepath:
                self.s.send_image(filepath)
        else:
            messagebox.showwarning("Warning", "You are not connected to a server.")

    def create_help_button(self):
        """
        Creates a Help button in the top-right corner, under the exit and theme selector.
        """
        help_button = tk.Button(
            self, text="Help", bg="skyblue", fg="black",
            command=self.show_help_window,
            width=8, height=1
        )
        # Place it under the exit button (which is at relx=0.95, rely=0.01)
        help_button.place(relx=0.95, rely=0.07, anchor="ne")

    def show_help_window(self):
        """
        Display the help window with instructions and tips for using the chat client.
        """
        help_text = (
            "🛡️ Welcome to Python Chat Client – User Guide 🛡️\n"
            "\n"
            "🌟 Quick Start:\n"
            "• Connect: Enter the server's IP address, your username, and password when prompted. If the username is new, you'll be registered automatically.\n"
            "• Send messages: Type in the text box at the bottom and press Enter or click 'Send Text'.\n"
            "• Send images: Click 'Send Image' and select an image file (max 5MB, common formats supported).\n"
            "\n"
            "🖥️ Interface Overview:\n"
            "• Chat History: See all messages and images in the main window.\n"
            "• Send Text area: Type your messages here. Use Shift+Enter for a new line.\n"
            "• Theme Dropdown: Change the look and feel instantly using the theme menu in the top right.\n"
            "• Emoji Button: Open the emoji picker to insert fun emojis into your messages.\n"
            "• Clear Chat: Wipe your local chat history (does not affect other users).\n"
            "• Help Button: Click 'Help' (top right) to open this guide any time.\n"
            "• Exit Button: Click 'Exit' (top right) to quit the application safely.\n"
            "• Game Button: Click 'Game' (top right) to open the games that are available"
            "• Top-Right: Exit, Theme, Help, Games\n"
            "• Left Panel: Connection info, Log output\n"
            "• Middle Panel: Chat history\n"
            "• Bottom Panel: Text input, buttons\n"
            "\n"
            "🔐 Account & Passwords:\n"
            "• Logging in: Use your registered username and password. If you are new, you’ll be signed up automatically.\n"
            "• Forgot password? Use the command: /resetpass-NEWPASS-OLDPASS in the chat box to update your password (e.g., /resetpass-new123-old123).\n"
            "• Passwords are securely hashed and stored on the server; your privacy is respected.\n"
            "\n"
            "🖼️ Images:\n"
            "• Supported formats: .png, .jpg, .jpeg, .gif, .bmp\n"
            "• Max file size: 5MB (after compression)\n"
            "• Sent and received images appear directly in the chat history. Click an image to preview it in a larger window.\n"
            "\n"
            "🎨 Themes & Customization:\n"
            "• Choose from vibrant themes such as Default, Light, Dark, Blue, Matte, Sunset, Forest, Pastel, Neon, Ocean, Vintage, Dusk, Cyberpunk, Autumn, Lavender, Desert, Aurora, Steel, and Bubblegum.\n"
            "• Switch themes instantly—your chat will remain, but appearance will refresh.\n"
            "\n"
            "😃 Emojis:\n"
            "• Click the emoji button below the chat box, browse by category, and click to insert into your message.\n"
            "• You can also type emoji shortcodes (e.g., :smile:) and they will be rendered if recognized.\n"
            "\n"
            "🎮 Games:\n"
            "• Click the 'Games' button to open fun features\n"
            "(Feature managed via GamesManager)\n"
            "\n"
            "⚡ Shortcuts & Special Commands:\n"
            "• Enter: Send message\n"
            "• Shift+Enter: Add new line (without sending)\n"
            "• /resetpass-NEWPASS-OLDPASS: Change your password (see above)\n"
            "• ?help: Open this help window\n"
            "\n"
            "📱 Fullscreen:\n"
            "• App launches in fullscreen\n"
            "• Use system controls to exit fullscreen\n"
            "\n"
            "⏳ Rate Limiting:\n"
            "• You can only send a message once per second\n"
            "\n"
            "❓ Frequently Asked Questions:\n"
            "• Q: Why can't I send messages?\n"
            "  A: Make sure you are connected (status is 'Connected'). If not, reconnect to the server.\n\n"
            "• Q: How do I use a different theme?\n"
            "  A: Select from the theme dropdown in the top right.\n\n"
            "• Q: Why is my image not sending?\n"
            "  A: Make sure it's under 5MB and in a supported format.\n\n"
            "• Q: How do I clear the chat?\n"
            "  A: Click 'Clear Chat' below the message box. This only clears your local history.\n\n"
            "• Q: What's the rate limit?\n"
            "  A: To prevent spam, you must wait about 1 second between messages.\n\n"
            "• Q: Can I use the chat in full screen?\n"
            "  A: Yes, the client opens in full screen by default for best experience.\n"
            "\n"
            "🔧 Troubleshooting:\n"
            "• Connection refused? Check the server is running, firewall is open, and IP/port are correct.\n"
            "• SSL errors? Verify the server's SSL certificate is valid and trusted, or contact your admin.\n"
            "• For persistent issues, restart the application or check your network settings.\n"
            "• Image fails? Check format or file size\n"
            "• Not connected? Press Status button to reconnect\n"
            "\n"
            "🆘 Need more help?\n"
            "• Contact your chat server administrator for advanced support.\n\n"
            "• This client is designed for ease of use—explore, enjoy, and happy chatting! 🎉\n"
        )
        help_window = tk.Toplevel(self)
        help_window.title("Help")
        help_window.geometry("700x700")

        frame = tk.Frame(help_window)
        frame.pack(fill='both', expand=True)

        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side='right', fill='y')

        text = tk.Text(frame, wrap='word', font=('Arial', 12), yscrollcommand=scrollbar.set)
        text.insert('1.0', help_text)
        text.config(state='disabled')
        text.pack(side='left', expand=True, fill='both')

        scrollbar.config(command=text.yview)

    def show_emoji_menu(self):
        """
        Show the emoji picker dialog for inserting emojis.
        """
        EmojiPicker(self, self.Sending_data)

    def clear_chat_history(self):
        """
        Clears the chat history text widget.
        """
        self.history.config(state='normal')
        self.history.delete('1.0', 'end')
        self.history.config(state='disabled')

    def create_panel_for_sending_text(self):
        """
        Create the panel and widgets for sending text and images.
        """
        self.Sending_data = tk.Text(self.Sending_panel, font=('arial', 17), width=60, height=3, background=self.text_bg, fg=self.text_fg)
        self.Sending_data.pack(side='left')
        self.Sending_data.bind("<Return>", self.on_enter_key_pressed)

        self.Sending_Trigger = tk.Button(self.Sending_panel, text="send\ntext", width=7, height=5, bg=self.btn_bg, fg=self.btn_fg, command=self.send_text_message, activebackground='lightgreen')
        self.Sending_Trigger.pack(side='left')

        self.Image_Trigger = tk.Button(self.Sending_panel, text='send\nImage', width=7, height=5, bg=self.btn_bg, fg=self.btn_fg, command=self.send_image_message, activebackground='lightgreen')
        self.Image_Trigger.pack(side='left')

        self.Clear_Chat_Button = tk.Button(self.Sending_panel, text='Clear\nChat', width=7, height=3, bg=self.btn_bg, fg=self.btn_fg, command=self.clear_chat_history, activebackground='pink')
        self.Clear_Chat_Button.pack(side='left', pady=(0, 2))

        self.Emoji_Button = tk.Button(self.Sending_panel, text='😀', width=5, height=3, bg=self.btn_bg, fg=self.btn_fg, command=self.show_emoji_menu)
        self.Emoji_Button.pack(side='left')

    def on_enter_key_pressed(self, event):
        """
        Handle the Enter key press in the text sending box.
        Shift+Enter inserts a newline; Enter alone sends the message.

        Args:
            event (tk.Event): The keyboard event.
        Returns:
            str or None: "break" to prevent newline, or None to allow.
        """
        if event.state & 0x0001:  # Shift key is pressed
            return None  # Allow newline
        input_data = self.Sending_data.get('1.0', 'end').strip()
        if input_data:
            self.send_text_message()
        return "break"  # Prevent default newline if not shift

    def create_panel_for_chat_history(self):
        """
        Create the chat history panel and text widget.
        """
        self.history = tk.Text(self.history_frame, font=('arial 17'), background=self.text_bg, fg=self.text_fg, width=75, height=20, state='disabled')
        self.history.pack()

    def create_panel_for_widget(self):
        """
        Create the log panel, chat history frame, and sending panel.
        """
        self.log_panel = tk.Text(self, height=20, width=40, state='disabled', bg=self.frame_bg, fg=self.frame_fg)
        self.log_panel.place(relx=0.01, rely=0.1, anchor="nw")

        self.history_frame = tk.LabelFrame(self, text='Chat History ', font='arial 16', fg=self.frame_fg, bg=self.panel_bg)
        self.history_frame.place(relx=0.3, rely=0.05, relwidth=0.65, relheight=0.7)
        self.typing_indicator = tk.Label(self.history_frame, text="", font=("Arial", 5), fg=self.frame_fg, bg=self.panel_bg)
        self.typing_indicator.pack(anchor='w', padx=5, pady=2)

        self.Sending_panel = tk.LabelFrame(self, text='Send Text', font='arial 16', fg=self.frame_fg, bg=self.panel_bg)
        self.Sending_panel.place(relx=0.3, rely=0.75, relwidth=0.65, relheight=0.15)

    def create_panel_for_connections_info(self):
        """
        Create the connections info panel and fill with connection details.
        """
        self.Connection_info = tk.LabelFrame(self, text='Connection Informations', font='arial 16', fg=self.frame_fg, bg=self.panel_bg)
        self.Connection_info.place(relx=0.01, rely=0.55, relwidth=0.25, relheight=0.18)

        style = ttk.Style()
        style.configure("Custom.TFrame", background="cornsilk3")
        style.configure("Custom.TLabel", background="cornsilk3")
        style.configure("Custom.TButton", background="lightgray")

        # Create the frame with the custom style
        self.frame = ttk.Frame(self.Connection_info, style="Custom.TFrame")
        self.frame.pack(fill='both', expand=True, padx=5, pady=5)

        ttk.Label(self.frame, text='Your Entered Address   : ', relief="groove", anchor='center', style="Custom.TLabel", width=25).grid(row=1, column=1, ipadx=10, ipady=5)
        ttk.Label(self.frame, textvariable=self.ip_address, relief='sunken', anchor='center', style="Custom.TLabel", width=25).grid(row=1, column=2, ipadx=10, ipady=5)
        ttk.Label(self.frame, text='Your Entered Port Number  : ', relief="groove", anchor='center', style="Custom.TLabel", width=25).grid(row=2, column=1, ipadx=10, ipady=5)
        ttk.Label(self.frame, textvariable=self.port, relief="sunken", anchor="center", style="Custom.TLabel", width=25).grid(row=2, column=2, ipadx=10, ipady=5)
        ttk.Label(self.frame, text='Status            : ', relief="groove", anchor="center", style="Custom.TLabel", width=25).grid(row=3, column=1, ipadx=10, ipady=5)
        ttk.Label(self.frame, text='Connected with    : ', relief='groove', anchor='center', style="Custom.TLabel", width=25).grid(row=4, column=1, ipadx=10, ipady=5)

        self.status = tk.Button(self.frame, text="Not Connected", anchor='center', width=25, bg="red", command=self.socket_connections_start)
        self.status.grid(row=3, column=2, ipadx=10, ipady=5)

        self.server_info = ttk.Label(self.frame, text=f"{self.ip_address.get()}:{self.port.get()}", relief='sunken', anchor='center',style= "Custom.TLabel", width=25)
        self.server_info.grid(row=4, column=2, ipadx=10, ipady=5)


if __name__ == '__main__':
    """Main entry point for the chat client application."""
    ClientDialogBox(className='Python Chatting [Client Mode]').mainloop()