import customtkinter as tk
import sqlite3
import hashlib

class MatrixApp(tk.CTk):
    """
    A Secure Authentication System providing a 'Matrix' themed interface.
    """
    def __init__(self):
        super().__init__()

        self.title("Matrix")
        self.geometry("450x200")
        self.resizable(False, False)

        tk.set_appearance_mode("System")
        tk.set_default_color_theme("dark-blue")
        
        self.create_database()

        # Frames
        self.frame_welcome = tk.CTkFrame(self, fg_color="#000C04", corner_radius=0)
        self.frame_signup = tk.CTkFrame(self, fg_color="#000C04", corner_radius=0)
        self.frame_login = tk.CTkFrame(self, fg_color="#000C04", corner_radius=0)
        self.matrix_site = tk.CTkScrollableFrame(self, fg_color="#000C04", corner_radius=0)

        
        self.setup_welcome_page()
        self.show_frame(self.frame_welcome)

    # - Database Logic -

    def create_database(self):
        """Initializes the SQLite database and users table if not already exist."""
        with sqlite3.connect("users.db") as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS users(
                            username text primary key,
                            password_hash text NOT NULL)''')

    def hash_password(self, password):
        """Converts a plain-text password into a SHA-256 hash for secure storage."""
        return hashlib.sha256(password.encode()).hexdigest()

    # - UI Logic -

    def show_frame(self, frame_to_show):
        """Hide all existing frames and display the requested one."""
        for f in [self.frame_welcome, self.frame_signup, self.frame_login, self.matrix_site]:
            f.pack_forget()
        frame_to_show.pack(fill="both", expand=True)

    def toggle_password(self, entry, button):
        """Switches password field between masked (*) and plain text."""
        if entry.cget("show") == "*":
            entry.configure(show="")
            button.configure(text="Hide")
        else:
            entry.configure(show="*")
            button.configure(text="See")

    # - Pages -

    def setup_welcome_page(self):
        """Builds the initial landing page with Login/Signup options."""
        tk.CTkLabel(self.frame_welcome, text="Welcome to the matrix enviroment!", 
                    text_color="#2DFF08", font=("Segoe UI", 25)).pack()
        
        tk.CTkButton(self.frame_welcome, text="Sign-Up", text_color="#2DFF08", font=("Segoe UI", 30),
                    fg_color="#0D0D0D", hover_color="#001A0F",
                    corner_radius=15, border_width=0,
                    command=lambda: self.setup_signup_page()).pack()
        
        tk.CTkLabel(self.frame_welcome, text="or", text_color="green", font=("", 12)).pack()
        
        tk.CTkButton(self.frame_welcome, text="Log-in", text_color="#2DFF08", font=("Segoe UI", 30),
                    fg_color="#0D0D0D", hover_color="#001A0F",
                    corner_radius=15, border_width=0,
                    command=lambda: self.setup_login_page()).pack()

    def setup_signup_page(self):
        """Builds the user registration interface."""
        self.show_frame(self.frame_signup)
        for widget in self.frame_signup.winfo_children(): widget.destroy()

        tk.CTkLabel(self.frame_signup, text="Sign-Up", text_color="#2DFF08", font=("Segoe UI", 30)).pack()
        
        tk.CTkLabel(self.frame_signup, text="Username:", text_color="#2DFF08", font=("Segoe UI", 25)).pack()
        entry_name = tk.CTkEntry(self.frame_signup, font=("Segoe UI", 15), corner_radius=15, border_width=0)
        entry_name.pack()

        tk.CTkLabel(self.frame_signup, text="Password:", text_color="#2DFF08", font=("Segoe UI", 25)).pack()
        entry_pass = tk.CTkEntry(self.frame_signup, font=("Segoe UI", 15), show="*", corner_radius=15, border_width=0)
        entry_pass.pack()

        # See/Hide Button
        btn_see = tk.CTkButton(self.frame_signup, text="See", text_color="#2DFF08", font=("Segoe UI", 15),
                              fg_color="transparent", hover_color="#001A0F", width=35, height=30)
        btn_see.configure(command=lambda: self.toggle_password(entry_pass, btn_see))
        btn_see.place(x=155, y=168)

        lbl_err_name = tk.CTkLabel(self.frame_signup, text="", text_color="#FF0808", font=("Segoe UI", 13))
        lbl_err_name.place(x=30, y=75)
        lbl_err_pass = tk.CTkLabel(self.frame_signup, text="", text_color="#FF0808", font=("Segoe UI", 13))
        lbl_err_pass.place(x=30, y=138)

        tk.CTkButton(self.frame_signup, text="Go Back", fg_color="transparent", width=70, corner_radius=100,
                    hover_color="#023715", command=lambda: self.show_frame(self.frame_welcome)).place(x=1, y=1)

        tk.CTkButton(self.frame_signup, text="Next...", text_color="#FF3300", fg_color="#0D0D0D", width=70,
                    corner_radius=100, hover_color="#1C0101",
                    command=lambda: self.validate_signup(entry_name.get(), entry_pass.get(), lbl_err_name, lbl_err_pass)).place(x=307, y=138)

    def setup_login_page(self):
        """Builds the user authentication interface."""
        self.show_frame(self.frame_login)
        for widget in self.frame_login.winfo_children(): widget.destroy()

        tk.CTkLabel(self.frame_login, text="Log-in", text_color="#2DFF08", font=("Segoe UI", 30)).pack()
        
        tk.CTkLabel(self.frame_login, text="Username:", text_color="#2DFF08", font=("Segoe UI", 25)).pack()
        ent_user = tk.CTkEntry(self.frame_login, corner_radius=15, border_width=0)
        ent_user.pack()
        
        tk.CTkLabel(self.frame_login, text="Password:", text_color="#2DFF08", font=("Segoe UI", 25)).pack()
        ent_pass = tk.CTkEntry(self.frame_login, show="*", corner_radius=15, border_width=0)
        ent_pass.pack()

        # See/Hide Button
        btn_see = tk.CTkButton(self.frame_login, text="See", text_color="#2DFF08", font=("Segoe UI", 15),
                              fg_color="transparent", hover_color="#001A0F", width=35, height=30)
        btn_see.configure(command=lambda: self.toggle_password(ent_pass, btn_see))
        btn_see.place(x=155, y=168)

        lbl_invalid = tk.CTkLabel(self.frame_login, text="", text_color="#FF0808")
        lbl_invalid.place(x=30, y=138)

        tk.CTkButton(self.frame_login, text="Go Back", fg_color="transparent", width=70, corner_radius=100,
                    hover_color="#023715", command=lambda: self.show_frame(self.frame_welcome)).place(x=1, y=1)
        
        tk.CTkButton(self.frame_login, text="Join...", text_color="#FF3300", fg_color="#0D0D0D", width=40,
                    corner_radius=100, hover_color="#1C0101",
                    command=lambda: self.check_login(ent_user.get(), ent_pass.get(), lbl_invalid)).place(x=307, y=138)


    def validate_signup(self, name, password, lbl_name, lbl_pass):
        if not name or not password:
            lbl_name.configure(text="Fields Empty")
            return
        
        if not name.isalnum() or not password.isalnum():
            lbl_name.configure(text="Invalid Characters")
            return

        h = self.hash_password(password)
        try:
            with sqlite3.connect("users.db") as conn:
                conn.execute('INSERT INTO users VALUES (?, ?)', (name, h))
            self.setup_login_page()
        except sqlite3.IntegrityError:
            lbl_name.configure(text="User Already Exists!")

    def check_login(self, name, password, lbl_err):
        h = self.hash_password(password)
        with sqlite3.connect("users.db") as conn:
            res = conn.execute('SELECT * FROM users WHERE username=? AND password_hash=?', (name, h)).fetchone()
            if res:
                self.show_matrix_site()
            else:
                lbl_err.configure(text="User Not Found!")

    def show_matrix_site(self):
        self.show_frame(self.matrix_site)
        tk.CTkLabel(self.matrix_site, text="Welcome to the Matrix!", text_color="#2DFF08", font=("Segoe UI", 40)).pack(pady=50)

if __name__ == "__main__":
    app = MatrixApp()
    app.mainloop()
