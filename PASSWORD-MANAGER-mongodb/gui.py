import customtkinter as ctk
from tkinter import messagebox
import sys
import os
from datetime import datetime, timedelta
from auth.auth_manager import AuthManager
from db.db_connect import db_name
import uuid
from dotenv import load_dotenv
from user.user_data_manager import UserDataManager
from PIL import Image, ImageTk
import bcrypt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time

# Load environment variables
load_dotenv()

class PasswordManagerGUI:
    def __init__(self, auth):
        self.auth = auth
        self.user_data_manager = None
        self.otp = None
        self.otp_timestamp = None
        self.cooldown_active = False
        self.otp_sent = False  # Add flag to track if OTP was sent
        self.setup_gui()
        
    def setup_gui(self):
        # Set theme and color scheme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Create main window
        self.root = ctk.CTk()
        self.root.title("Password Manager")
        self.root.geometry("1000x700")
        
        # Create main container with gradient background
        self.main_container = ctk.CTkFrame(self.root)
        self.main_container.pack(fill="both", expand=True)
        
        # Show login frame initially
        self.show_login_frame()
        
    def show_login_frame(self):
        # Clear main container
        for widget in self.main_container.winfo_children():
            widget.destroy()
            
        # Create login frame with padding
        login_frame = ctk.CTkFrame(self.main_container)
        login_frame.pack(pady=50)
        
        # Title
        title_label = ctk.CTkLabel(
            login_frame,
            text="Welcome Back!",
            font=("Helvetica", 24, "bold")
        )
        title_label.pack(pady=(20, 30))
        
        # Username entry with icon
        username_frame = ctk.CTkFrame(login_frame)
        username_frame.pack(fill="x", padx=40, pady=5)
        username_label = ctk.CTkLabel(username_frame, text="👤")
        username_label.pack(side="left", padx=5)
        self.username_entry = ctk.CTkEntry(
            username_frame,
            placeholder_text="Username",
            width=300
        )
        self.username_entry.pack(side="left", padx=5)
        
        # Password entry with icon
        password_frame = ctk.CTkFrame(login_frame)
        password_frame.pack(fill="x", padx=40, pady=5)
        password_label = ctk.CTkLabel(password_frame, text="🔒")
        password_label.pack(side="left", padx=5)
        self.password_entry = ctk.CTkEntry(
            password_frame,
            placeholder_text="Password",
            show="•",
            width=300
        )
        self.password_entry.pack(side="left", padx=5)
        
        # Login button
        login_button = ctk.CTkButton(
            login_frame,
            text="Login",
            command=self.login,
            width=300,
            height=40,
            font=("Helvetica", 14)
        )
        login_button.pack(pady=20)
        
        # Forgot password link
        forgot_link = ctk.CTkButton(
            login_frame,
            text="Forgot Password?",
            command=self.show_forgot_password_frame,
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        )
        forgot_link.pack(pady=5)
        
        # Register button
        register_button = ctk.CTkButton(
            login_frame,
            text="Create New Account",
            command=self.show_register_frame,
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        )
        register_button.pack(pady=5)
        
    def show_register_frame(self):
        # Reset OTP state when showing register frame
        self.otp = None
        self.otp_timestamp = None
        self.otp_sent = False
        self.cooldown_active = False
        
        # Clear main container
        for widget in self.main_container.winfo_children():
            widget.destroy()
            
        # Create register frame with padding
        register_frame = ctk.CTkFrame(self.main_container)
        register_frame.pack(pady=50)
        
        # Title
        title_label = ctk.CTkLabel(
            register_frame,
            text="Create New Account",
            font=("Helvetica", 24, "bold")
        )
        title_label.pack(pady=(20, 30))
        
        # Username entry with icon
        username_frame = ctk.CTkFrame(register_frame)
        username_frame.pack(fill="x", padx=40, pady=5)
        username_label = ctk.CTkLabel(username_frame, text="👤")
        username_label.pack(side="left", padx=5)
        self.reg_username_entry = ctk.CTkEntry(
            username_frame,
            placeholder_text="Username",
            width=300
        )
        self.reg_username_entry.pack(side="left", padx=5)
        
        # Email entry with icon
        email_frame = ctk.CTkFrame(register_frame)
        email_frame.pack(fill="x", padx=40, pady=5)
        email_label = ctk.CTkLabel(email_frame, text="📧")
        email_label.pack(side="left", padx=5)
        self.email_entry = ctk.CTkEntry(
            email_frame,
            placeholder_text="Email",
            width=300
        )
        self.email_entry.pack(side="left", padx=5)
        
        # Password entry with icon
        password_frame = ctk.CTkFrame(register_frame)
        password_frame.pack(fill="x", padx=40, pady=5)
        password_label = ctk.CTkLabel(password_frame, text="🔒")
        password_label.pack(side="left", padx=5)
        self.reg_password_entry = ctk.CTkEntry(
            password_frame,
            placeholder_text="Password",
            show="•",
            width=300
        )
        self.reg_password_entry.pack(side="left", padx=5)
        
        # Confirm password entry with icon
        confirm_frame = ctk.CTkFrame(register_frame)
        confirm_frame.pack(fill="x", padx=40, pady=5)
        confirm_label = ctk.CTkLabel(confirm_frame, text="🔒")
        confirm_label.pack(side="left", padx=5)
        self.confirm_password_entry = ctk.CTkEntry(
            confirm_frame,
            placeholder_text="Confirm Password",
            show="•",
            width=300
        )
        self.confirm_password_entry.pack(side="left", padx=5)
        
        # Send OTP button
        self.send_otp_button = ctk.CTkButton(
            register_frame,
            text="Send OTP",
            command=self.send_otp,
            width=300,
            height=40,
            font=("Helvetica", 14)
        )
        self.send_otp_button.pack(pady=10)
        
        # OTP entry with icon
        otp_frame = ctk.CTkFrame(register_frame)
        otp_frame.pack(fill="x", padx=40, pady=5)
        otp_label = ctk.CTkLabel(otp_frame, text="🔢")
        otp_label.pack(side="left", padx=5)
        self.otp_entry = ctk.CTkEntry(
            otp_frame,
            placeholder_text="Enter OTP",
            width=300
        )
        self.otp_entry.pack(side="left", padx=5)
        
        # Register button
        register_button = ctk.CTkButton(
            register_frame,
            text="Create Account",
            command=self.register,
            width=300,
            height=40,
            font=("Helvetica", 14)
        )
        register_button.pack(pady=20)
        
        # Back to login button
        back_button = ctk.CTkButton(
            register_frame,
            text="Back to Login",
            command=self.show_login_frame,
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        )
        back_button.pack(pady=5)
        
    def send_email(self, to_email, subject, body):
        try:
            # Get email credentials from environment variables
            sender_email = os.getenv('SENDER_EMAIL')
            sender_password = os.getenv('EMAIL_PASSWORD')
            
            print(f"Debug - Sender Email: {sender_email}")  # Debug print
            
            if not sender_email or not sender_password:
                print("Debug - Missing email credentials")  # Debug print
                raise ValueError("Email credentials not found in environment variables")
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Add body
            msg.attach(MIMEText(body, 'plain'))
            
            print("Debug - Attempting to connect to SMTP server...")  # Debug print
            
            # Create SMTP session
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            
            print("Debug - Attempting to login...")  # Debug print
            server.login(sender_email, sender_password)
            
            print("Debug - Sending email...")  # Debug print
            # Send email
            server.send_message(msg)
            server.quit()
            
            print("Debug - Email sent successfully")  # Debug print
            return True
            
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            print(f"Error type: {type(e)}")  # Debug print
            import traceback
            print(f"Full traceback: {traceback.format_exc()}")  # Debug print
            return False
            
    def start_cooldown(self):
        self.cooldown_active = True
        self.send_otp_button.configure(state="disabled")
        
        def cooldown_thread():
            for i in range(30, 0, -1):
                self.send_otp_button.configure(text=f"Resend OTP ({i}s)")
                time.sleep(1)
            self.cooldown_active = False
            self.send_otp_button.configure(state="normal", text="Resend OTP")
            
        threading.Thread(target=cooldown_thread, daemon=True).start()
        
    def send_otp(self):
        if self.cooldown_active or self.otp_sent:
            return
            
        email = self.email_entry.get()
        username = self.reg_username_entry.get()
        
        if not email or not username:
            self.show_error("Please enter both username and email address")
            return
            
        # Check if username or email already exists
        if self.auth.check_user_exists(username, email):
            self.show_error("Username or email already exists")
            return
            
        # Generate a 6-digit OTP
        import random
        self.otp = str(random.randint(100000, 999999))
        self.otp_timestamp = datetime.now()
        
        # Send OTP via email
        subject = "Your Password Manager Registration OTP"
        body = f"""
        Hello,
        
        Your OTP for Password Manager registration is: {self.otp}
        
        This OTP will expire in 5 minutes.
        
        If you didn't request this OTP, please ignore this email.
        
        Best regards,
        Password Manager Team
        """
        
        if self.send_email(email, subject, body):
            self.otp_sent = True  # Set flag after successful send
            self.start_cooldown()
        else:
            self.show_error("Failed to send OTP. Please check your email settings.")
            
    def register(self):
        username = self.reg_username_entry.get()
        email = self.email_entry.get()
        password = self.reg_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        otp = self.otp_entry.get()
        
        if not username or not email or not password or not confirm_password or not otp:
            self.show_error("Please fill in all fields")
            return
            
        if password != confirm_password:
            self.show_error("Passwords do not match")
            return
            
        if not self.otp or not self.otp_timestamp:
            self.show_error("Please request an OTP first")
            return
            
        # Check if OTP has expired (5 minutes)
        if datetime.now() - self.otp_timestamp > timedelta(minutes=5):
            self.show_error("OTP has expired. Please request a new one.")
            return
            
        if otp != self.otp:
            self.show_error("Invalid OTP")
            return
            
        if self.auth.register(username, email, password):
            self.show_success("Registration successful! Please login.")
            self.show_login_frame()
        else:
            self.show_error("Registration failed. Username or email may already exist.")
            
    def show_forgot_password_frame(self):
        # Clear main container
        for widget in self.main_container.winfo_children():
            widget.destroy()
            
        # Create forgot password frame with padding
        forgot_frame = ctk.CTkFrame(self.main_container)
        forgot_frame.pack(pady=50)
        
        # Title
        title_label = ctk.CTkLabel(
            forgot_frame,
            text="Reset Password",
            font=("Helvetica", 24, "bold")
        )
        title_label.pack(pady=(20, 30))
        
        # Description
        desc_label = ctk.CTkLabel(
            forgot_frame,
            text="Enter your email address to receive a password reset link",
            font=("Helvetica", 12)
        )
        desc_label.pack(pady=(0, 20))
        
        # Email entry with icon
        email_frame = ctk.CTkFrame(forgot_frame)
        email_frame.pack(fill="x", padx=40, pady=5)
        email_label = ctk.CTkLabel(email_frame, text="📧")
        email_label.pack(side="left", padx=5)
        self.reset_email_entry = ctk.CTkEntry(
            email_frame,
            placeholder_text="Email",
            width=300
        )
        self.reset_email_entry.pack(side="left", padx=5)
        
        # Reset button
        reset_button = ctk.CTkButton(
            forgot_frame,
            text="Send Reset Link",
            command=self.reset_password,
            width=300,
            height=40,
            font=("Helvetica", 14)
        )
        reset_button.pack(pady=20)
        
        # Back to login button
        back_button = ctk.CTkButton(
            forgot_frame,
            text="Back to Login",
            command=self.show_login_frame,
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        )
        back_button.pack(pady=5)
        
    def reset_password(self):
        email = self.reset_email_entry.get()
        if not email:
            self.show_error("Please enter your email address")
            return
            
        # Here you would implement the password reset logic
        # For now, we'll just show a success message
        self.show_success("Password reset link has been sent to your email")
        self.show_login_frame()
        
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.show_error("Please enter both username and password")
            return
            
        if self.auth.login(username, password):
            self.user_data_manager = UserDataManager(self.auth.get_current_user())
            self.show_main_frame()
        else:
            self.show_error("Invalid username or password")
            
    def show_main_frame(self):
        # Clear main container
        for widget in self.main_container.winfo_children():
            widget.destroy()
            
        # Create main frame with padding
        main_frame = ctk.CTkFrame(self.main_container)
        main_frame.pack(pady=30)
        
        # Create header frame
        header_frame = ctk.CTkFrame(main_frame)
        header_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        # Welcome message
        welcome_label = ctk.CTkLabel(
            header_frame,
            text=f"Welcome, {self.auth.get_current_user()['username']}!",
            font=("Helvetica", 20, "bold")
        )
        welcome_label.pack(side="left", pady=10)
        
        # Logout button in header
        logout_button = ctk.CTkButton(
            header_frame,
            text="Logout",
            command=self.logout,
            width=100,
            height=35,
            font=("Helvetica", 12),
            fg_color="red",
            hover_color="darkred"
        )
        logout_button.pack(side="right", pady=10)
        
        # Create content frame
        content_frame = ctk.CTkFrame(main_frame)
        content_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        # Create grid of buttons (2x2)
        # Add password button
        add_button = ctk.CTkButton(
            content_frame,
            text="Add New Password",
            command=self.show_add_password_frame,
            width=180,
            height=40,
            font=("Helvetica", 12)
        )
        add_button.grid(row=0, column=0, padx=10, pady=10)
        
        # View passwords button
        view_button = ctk.CTkButton(
            content_frame,
            text="View Passwords",
            command=self.show_passwords,
            width=180,
            height=40,
            font=("Helvetica", 12)
        )
        view_button.grid(row=0, column=1, padx=10, pady=10)
        
        # Search passwords button
        search_button = ctk.CTkButton(
            content_frame,
            text="Search Passwords",
            command=self.show_search_frame,
            width=180,
            height=40,
            font=("Helvetica", 12)
        )
        search_button.grid(row=1, column=0, padx=10, pady=10)
        
        # Configure grid columns to be equal
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)
        
        # Create recent passwords frame
        recent_frame = ctk.CTkFrame(main_frame)
        recent_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        # Recent passwords title
        recent_title = ctk.CTkLabel(
            recent_frame,
            text="Recent Passwords",
            font=("Helvetica", 16, "bold")
        )
        recent_title.pack(pady=(10, 5))
        
        # Get recent passwords
        passwords = self.user_data_manager.get_user_passwords()[:5]  # Get only 5 most recent
        
        # Create table for recent passwords
        table = ctk.CTkTextbox(recent_frame, height=150)
        table.pack(fill="x", padx=10, pady=(0, 10))
        
        # Add headers
        table.insert("end", "Website\tUsername\tNotes\n")
        table.insert("end", "-" * 50 + "\n")
        
        # Add passwords
        for pwd in passwords:
            website = pwd.get("website", "")
            login_entries = pwd.get("loginEntries", [])
            for entry in login_entries:
                username = entry.get("username", "")
                notes = entry.get("notes", "")
                table.insert("end", f"{website}\t{username}\t{notes}\n")
                
        table.configure(state="disabled")
        
    def show_add_password_frame(self):
        # Create add password frame
        add_frame = ctk.CTkFrame(self.main_container)
        add_frame.pack(pady=20)
        
        # Website entry
        website_label = ctk.CTkLabel(add_frame, text="Website:")
        website_label.pack(pady=5)
        self.website_entry = ctk.CTkEntry(add_frame)
        self.website_entry.pack(pady=5)
        
        # Username entry
        username_label = ctk.CTkLabel(add_frame, text="Username:")
        username_label.pack(pady=5)
        self.add_username_entry = ctk.CTkEntry(add_frame)
        self.add_username_entry.pack(pady=5)
        
        # Password entry
        password_label = ctk.CTkLabel(add_frame, text="Password:")
        password_label.pack(pady=5)
        self.add_password_entry = ctk.CTkEntry(add_frame, show="*")
        self.add_password_entry.pack(pady=5)
        
        # Notes entry
        notes_label = ctk.CTkLabel(add_frame, text="Notes (optional):")
        notes_label.pack(pady=5)
        self.notes_entry = ctk.CTkTextbox(add_frame, height=100)
        self.notes_entry.pack(pady=5)
        
        # Save button
        save_button = ctk.CTkButton(add_frame, text="Save Password", command=self.save_password)
        save_button.pack(pady=10)
        
        # Back button
        back_button = ctk.CTkButton(add_frame, text="Back", command=self.show_main_frame)
        back_button.pack(pady=5)
        
    def save_password(self):
        website = self.website_entry.get()
        username = self.add_username_entry.get()
        password = self.add_password_entry.get()
        notes = self.notes_entry.get("1.0", "end-1c")
        
        if not website or not username or not password:
            self.show_error("Please fill in all required fields")
            return
            
        if self.user_data_manager.add_password(website, username, password, notes):
            self.show_success("Password saved successfully!")
            self.show_main_frame()
        else:
            self.show_error("Failed to save password")
            
    def show_passwords(self):
        # Create passwords frame
        passwords_frame = ctk.CTkFrame(self.main_container)
        passwords_frame.pack(fill="both", expand=True, pady=20)
        
        # Get all passwords
        passwords = self.user_data_manager.get_user_passwords()
        
        # Create table
        table = ctk.CTkTextbox(passwords_frame, height=400)
        table.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add headers
        table.insert("end", "Website\tUsername\tNotes\n")
        table.insert("end", "-" * 50 + "\n")
        
        # Add passwords
        for pwd in passwords:
            website = pwd.get("website", "")
            login_entries = pwd.get("loginEntries", [])
            for entry in login_entries:
                username = entry.get("username", "")
                notes = entry.get("notes", "")
                table.insert("end", f"{website}\t{username}\t{notes}\n")
                
        table.configure(state="disabled")
        
        # Back button
        back_button = ctk.CTkButton(passwords_frame, text="Back", command=self.show_main_frame)
        back_button.pack(pady=10)
        
    def show_search_frame(self):
        # Create search frame
        search_frame = ctk.CTkFrame(self.main_container)
        search_frame.pack(pady=20)
        
        # Search entry
        search_label = ctk.CTkLabel(search_frame, text="Search:")
        search_label.pack(pady=5)
        self.search_entry = ctk.CTkEntry(search_frame)
        self.search_entry.pack(pady=5)
        
        # Search button
        search_button = ctk.CTkButton(search_frame, text="Search", command=self.search_passwords)
        search_button.pack(pady=10)
        
        # Back button
        back_button = ctk.CTkButton(search_frame, text="Back", command=self.show_main_frame)
        back_button.pack(pady=5)
        
    def search_passwords(self):
        query = self.search_entry.get()
        if not query:
            self.show_error("Please enter a search term")
            return
            
        results = self.user_data_manager.search_passwords(query)
        
        # Create results frame
        results_frame = ctk.CTkFrame(self.main_container)
        results_frame.pack(fill="both", expand=True, pady=20)
        
        # Create table
        table = ctk.CTkTextbox(results_frame, height=400)
        table.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add headers
        table.insert("end", "Website\tUsername\tNotes\n")
        table.insert("end", "-" * 50 + "\n")
        
        # Add results
        for pwd in results:
            website = pwd.get("website", "")
            login_entries = pwd.get("loginEntries", [])
            for entry in login_entries:
                username = entry.get("username", "")
                notes = entry.get("notes", "")
                table.insert("end", f"{website}\t{username}\t{notes}\n")
                
        table.configure(state="disabled")
        
        # Back button
        back_button = ctk.CTkButton(results_frame, text="Back", command=self.show_main_frame)
        back_button.pack(pady=10)
        
    def logout(self):
        self.auth.logout()
        self.user_data_manager = None
        self.show_login_frame()
        
    def show_error(self, message):
        error_window = ctk.CTkToplevel(self.root)
        error_window.title("Error")
        error_window.geometry("300x150")
        
        error_label = ctk.CTkLabel(
            error_window,
            text=message,
            font=("Helvetica", 14)
        )
        error_label.pack(pady=20)
        
        ok_button = ctk.CTkButton(
            error_window,
            text="OK",
            command=error_window.destroy,
            width=100
        )
        ok_button.pack(pady=10)
        
    def show_success(self, message):
        success_window = ctk.CTkToplevel(self.root)
        success_window.title("Success")
        success_window.geometry("300x150")
        
        success_label = ctk.CTkLabel(
            success_window,
            text=message,
            font=("Helvetica", 14)
        )
        success_label.pack(pady=20)
        
        ok_button = ctk.CTkButton(
            success_window,
            text="OK",
            command=success_window.destroy,
            width=100
        )
        ok_button.pack(pady=10)
        
    def run(self):
        self.root.mainloop()

def main(auth):
    app = PasswordManagerGUI(auth)
    app.run() 