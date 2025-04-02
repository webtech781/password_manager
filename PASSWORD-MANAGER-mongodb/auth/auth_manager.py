import sys
import os
import bcrypt
import re
from datetime import datetime, timezone, timedelta
from tabulate import tabulate
import msvcrt  # For Windows keyboard input
import time
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
import uuid

# Adjust sys.path to include parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import database connection
from db.db_connect import db_name

# Load environment variables
load_dotenv()
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

class AuthManager:
    def __init__(self):
        """Initialize the AuthManager"""
        self.current_user = None
        self.user_collection = db_name['users']
        self.otp_collection = db_name['otps']  # New collection for OTPs
        
        # Initialize collections if they don't exist
        if 'users' not in db_name.list_collection_names():
            db_name.create_collection('users')
        if 'otps' not in db_name.list_collection_names():
            db_name.create_collection('otps')
            
        # Initialize current_user as None
        self.current_user = None

    def handle_special_key(self, key):
        """Handle special keys"""
        if key == b'\x1b':  # ESC
            return 'ESC'
        elif key == b'\x08':  # Backspace
            return 'BACKSPACE'
        elif key == b'\x7f':  # Delete
            return 'DELETE'
        elif key == b'\x03':  # Ctrl+C
            return 'CTRL+C'
        return None

    def get_input(self, prompt):
        """Get input with special key support"""
        print(prompt, end='', flush=True)
        value = ""
        while True:
            if msvcrt.kbhit():
                key = msvcrt.getch()
                special_key = self.handle_special_key(key)
                
                if special_key == 'ESC':
                    print("\nOperation cancelled.")
                    return None
                elif special_key == 'BACKSPACE':
                    if value:
                        value = value[:-1]
                        print('\b \b', end='', flush=True)
                    continue
                elif special_key == 'CTRL+C':
                    raise KeyboardInterrupt
                elif key == b'\r':  # Enter key
                    break
                else:
                    # Handle regular character input
                    try:
                        char = key.decode()
                        value += char
                        print(char, end='', flush=True)
                        continue
                    except UnicodeDecodeError:
                        continue
            time.sleep(0.1)  # Small delay to prevent CPU overuse
        return value.strip()

    def generate_otp(self):
        """Generate a 6-digit OTP"""
        return ''.join(random.choices('0123456789', k=6))

    def send_verification_email(self, email, otp, username):
        """Send verification email with OTP"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = os.getenv('SENDER_EMAIL')
            msg['To'] = email
            msg['Subject'] = "Email Verification"
            
            # Create HTML content
            html = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #1a237e;">Email Verification</h2>
                    <p>Hello {username},</p>
                    <p>Use the code below to verify your email address:</p>
                    <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0; text-align: center; font-size: 24px; letter-spacing: 5px;">
                        {otp}
                    </div>
                    <p>OTP Expires at: {datetime.now().strftime('%I:%M %p')}</p>
                    <p>If you did not request this, please ignore this email or contact support.</p>
                </body>
            </html>
            """
            
            msg.attach(MIMEText(html, 'html'))
            
            # Connect to SMTP server
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(os.getenv('SENDER_EMAIL'), os.getenv('EMAIL_PASSWORD'))
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Error sending verification email: {str(e)}")
            return False

    def verify_otp(self, email, otp):
        """Verify the OTP for email verification"""
        try:
            # Find the OTP record
            otp_record = self.otp_collection.find_one({
                "email": email.lower(),
                "otp": otp,
                "expires_at": {"$gt": datetime.now()},
                "type": "verification"
            })
            
            if otp_record:
                # Delete the used OTP
                self.otp_collection.delete_one({"_id": otp_record["_id"]})
                return True
            return False
        except Exception as e:
            print(f"Error verifying OTP: {str(e)}")
            return False

    def hash_password(self, password):
        """Hashes the password using bcrypt"""
        try:
            # Ensure password is bytes
            if isinstance(password, str):
                password = password.encode('utf-8')
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password, salt)
        except Exception as e:
            print(f"Error hashing password: {str(e)}")
            return None

    def verify_password(self, password, hashed_password):
        """Verifies the password against its hash"""
        try:
            # Ensure both inputs are bytes
            if isinstance(password, str):
                password = password.encode('utf-8')
            if isinstance(hashed_password, str):
                hashed_password = hashed_password.encode('utf-8')
            return bcrypt.checkpw(password, hashed_password)
        except Exception as e:
            print(f"Error verifying password: {str(e)}")
            return False

    def is_valid_email(self, email):
        """Validates email format"""
        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return re.match(email_regex, email)

    def register(self, username, email, password):
        """Handle user registration"""
        try:
            # Debug logging
            print(f"Registration attempt - Username type: {type(username)}, Email type: {type(email)}, Password type: {type(password)}")
            
            # Ensure all inputs are strings
            username = str(username) if username is not None else ""
            email = str(email) if email is not None else ""
            password = str(password) if password is not None else ""
            
            # Validate input
            if not username or not email or not password:
                print("Empty username, email, or password")
                return False
            
            # Hash master password
            hashed_master_password = self.hash_password(password)
            if not hashed_master_password:
                print("Failed to hash password")
                return False
            
            # Generate encryption key and IV
            encryption_key = bcrypt.gensalt()  # This will be used to encrypt stored passwords
            iv = bcrypt.gensalt()  # Initialization vector for encryption
            
            # Create user document with proper type handling
            user_data = {
                "username": str(username).lower(),
                "email": str(email).lower(),
                "hashedMasterPassword": hashed_master_password,  # Store as binary
                "salt": bcrypt.gensalt(),  # Store salt separately
                "encryptionKey": encryption_key,
                "iv": iv,
                "createdAt": datetime.now(),
                "updatedAt": datetime.now(),
                "email_verified": bool(True)  # Set to True since we've already verified the email
            }
            
            # Insert user into database
            result = self.user_collection.insert_one(user_data)
            
            if result.inserted_id:
                print("Registration successful")
                return True
            print("Registration failed - no inserted ID")
            return False
            
        except Exception as e:
            print(f"Registration error: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            return False

    def login(self, username, password):
        """Handle user login"""
        try:
            # Debug logging
            print(f"Login attempt - Username type: {type(username)}, Password type: {type(password)}")
            
            # Ensure username and password are strings and not None
            username = str(username) if username is not None else ""
            password = str(password) if password is not None else ""
            
            # Validate input
            if not username or not password:
                print("Empty username or password")
                return False
                
            # Convert username to lowercase
            username = username.lower()
            
            # Find user by username
            user = self.user_collection.find_one({"username": username})
            
            if not user:
                print("User not found")
                return False
                
            # Verify password
            stored_password = user.get('hashedMasterPassword')
            if not stored_password:
                print("No stored password found")
                return False
                
            # Verify password using our verify_password method
            if not self.verify_password(password, stored_password):
                print("Invalid password")
                return False
                
            # Check if email is verified
            if not user.get('email_verified', False):
                print("Email not verified")
                return False
                
            # Set current user with proper data structure and type handling
            self.current_user = {
                "user_id": str(user.get("_id")),
                "username": str(user.get("username", "")),
                "email": str(user.get("email", "")),
                "encryptionKey": user.get("encryptionKey"),
                "iv": user.get("iv"),
                "createdAt": user.get("createdAt"),
                "email_verified": bool(user.get("email_verified", False))
            }
            
            print("Login successful")
            return True
            
        except Exception as e:
            print(f"Login error: {str(e)}")
            return False

    def logout(self):
        """Handle user logout"""
        try:
            self.current_user = None
            print("Logged out successfully")
        except Exception as e:
            print(f"Error during logout: {str(e)}")

    def is_logged_in(self):
        """Check if user is logged in"""
        try:
            if not self.current_user:
                return False
            if not isinstance(self.current_user, dict):
                return False
            if not self.current_user.get("username"):
                return False
            return True
        except Exception as e:
            print(f"Error checking login status: {str(e)}")
            return False

    def get_current_user(self):
        """Get the current user's data"""
        try:
            if not self.current_user or not isinstance(self.current_user, dict):
                print("No current user or invalid user data")
                return None
                
            # Get the latest user data from the database
            user = self.user_collection.find_one({"username": self.current_user.get("username")})
            if not user:
                print("User not found in database")
                return None
                
            # Create a clean user dictionary with only necessary fields
            user_data = {
                "user_id": str(user.get("_id")),
                "username": str(user.get("username", "")),
                "email": str(user.get("email", "")),
                "encryptionKey": user.get("encryptionKey"),
                "iv": user.get("iv"),
                "createdAt": user.get("createdAt"),
                "email_verified": bool(user.get("email_verified", False))
            }
            
            # Update current_user with the clean data
            self.current_user = user_data
            return user_data
            
        except Exception as e:
            print(f"Error getting current user: {str(e)}")
            return None

    def show_menu(self):
        while True:
            try:
                print("\n=== Authentication Menu ===")
                print("1. Register")
                print("2. Login")
                print("3. Exit")
                print("\nPress ESC at any time to return to menu")
                print("Press Ctrl+C to exit")

                choice = self.get_input("\nEnter your choice: ")
                if not choice:  # ESC was pressed
                    continue

                if choice == "1":
                    self.register()
                elif choice == "2":
                    if self.login():
                        return True
                elif choice == "3":
                    print("\nExiting Authentication Menu. Goodbye!")
                    return False
                else:
                    print("\nInvalid choice. Please select a valid option.")
            except KeyboardInterrupt:
                print("\n\nExiting Password Manager. Goodbye!")
                sys.exit(0)
            except Exception as e:
                print(f"\nAn error occurred: {e}")
                print("Returning to menu...")

    def forgot_password(self, identifier):
        """Handle forgot password request using username or email"""
        try:
            # Find user by username or email
            user = self.user_collection.find_one({
                "$or": [
                    {"username": identifier.lower()},
                    {"email": identifier.lower()}
                ]
            })
            
            if not user:
                print("\nNo account found with this username or email.")
                return False
                
            # Generate reset code
            reset_code = self.generate_otp()
            expiry = datetime.utcnow() + timedelta(minutes=15)
            
            # Store reset code
            self.otp_collection.update_one(
                {"email": user["email"], "type": "reset"},
                {
                    "$set": {
                        "code": reset_code,
                        "expiry": expiry,
                        "last_sent": datetime.utcnow()
                    }
                },
                upsert=True
            )
            
            # Send reset email
            self.send_reset_email(user["email"], reset_code, user["username"])
            return True
            
        except Exception as e:
            print(f"\nFailed to process password reset: {e}")
            return False

    def send_reset_email(self, email, reset_code, username):
        """Send password reset email"""
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = email
        msg["Subject"] = "Password Manager - Reset Your Password"
        
        expiration_time = datetime.now() + timedelta(minutes=10)
        expiration_time_str = expiration_time.strftime("%I:%M %p")

        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
    <style>
        .reset-container {{
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            margin: 20px 0;
            flex-wrap: nowrap;
        }}
        .reset-box {{
            width: 40px;
            height: 40px;
            background: #28a745;
            color: #ffffff;
            font-size: 20px;
            font-weight: bold;
            text-align: center;
            display: flex;
            justify-content: center;
            align-items: center;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin: 0 2px;
        }}
        .button-container {{
            display: flex;
            justify-content: center;
            gap: 15px;
            margin: 20px 0;
        }}
        .button {{
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }}
        .copy-button {{
            background-color: #28a745;
        }}
        .copy-button:hover {{
            background-color: #218838;
            transform: translateY(-2px);
        }}
        .expiry {{
            font-size: 14px;
            color: #d9534f;
            font-weight: bold;
            margin: 15px 0;
            padding: 10px;
            background: #fff3f3;
            border-radius: 5px;
        }}
        .warning {{
            font-size: 12px;
            color: #888;
            margin-top: 20px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
    </style>
    <script>
        function copyToClipboard(text) {{
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            try {{
                document.execCommand('copy');
                alert('Code copied to clipboard!');
            }} catch (err) {{
                console.error('Failed to copy text: ', err);
            }}
            document.body.removeChild(textarea);
        }}
    </script>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f7; text-align: center; padding: 20px;">
    <div style="max-width: 480px; background: #ffffff; padding: 30px; border-radius: 8px; 
                box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1); margin: auto;">
        <h1 style="color: #333; font-size: 22px; margin-bottom: 20px;">Reset Your Password</h1>
        <p style="color: #555; font-size: 16px; line-height: 1.6;">
            Hello <strong>{username}</strong>,
        </p>
        <p style="color: #555; font-size: 16px;">
            Use the code below to reset your password:
        </p>

        <div class="reset-container">
            <div class="reset-box">{reset_code[0]}</div>
            <div class="reset-box">{reset_code[1]}</div>
            <div class="reset-box">{reset_code[2]}</div>
            <div class="reset-box">{reset_code[3]}</div>
            <div class="reset-box">{reset_code[4]}</div>
            <div class="reset-box">{reset_code[5]}</div>
        </div>

        <div class="button-container">
            <a href="#" class="button copy-button" onclick="copyToClipboard('{reset_code}'); return false;">
                Copy Code
            </a>
        </div>

        <div class="expiry">
            Reset Code Expires at: <strong>{expiration_time_str}</strong>
        </div>

        <div class="warning">
            If you did not request this, please ignore this email or contact support.
        </div>
    </div>
</body>
</html>
"""
        msg.attach(MIMEText(html_template, "html"))
        
        try:
            smtp_server = smtplib.SMTP("smtp.gmail.com", 587)
            smtp_server.starttls()
            smtp_server.login(SENDER_EMAIL, EMAIL_PASSWORD)
            smtp_server.sendmail(SENDER_EMAIL, email, msg.as_string())
            print("\nReset email sent successfully!")
            return True
        except Exception as e:
            print(f"\nError sending reset email: {str(e)}")
            return False
        finally:
            smtp_server.quit()

    def verify_reset_otp(self, email, otp):
        """Verify the OTP for password reset"""
        try:
            otp_record = self.otp_collection.find_one({
                "email": email.lower(),
                "code": otp,
                "expiry": {"$gt": datetime.utcnow()},
                "type": "reset"
            })
            
            if otp_record:
                # Delete the used OTP
                self.otp_collection.delete_one({"_id": otp_record["_id"]})
                return True
            return False
        except Exception as e:
            print(f"\nError verifying reset OTP: {e}")
            return False

    def reset_password(self, email, new_password):
        """Reset user's password"""
        try:
            # Hash the new password using our hash_password method
            hashed_password = self.hash_password(new_password)
            if not hashed_password:
                print("Failed to hash new password")
                return False
            
            # Update user's password
            result = self.user_collection.update_one(
                {"email": email.lower()},
                {"$set": {"hashedMasterPassword": hashed_password}}
            )
            
            if result.modified_count > 0:
                return True
            return False
        except Exception as e:
            print(f"\nError resetting password: {e}")
            return False

    def show_user_panel(self):
        """Display the user panel after successful login"""
        try:
            while True:
                print("\n=== User Panel ===")
                print(f"Welcome, {self.current_user['username']}!")
                print("\n1. View Passwords")
                print("2. Add New Password")
                print("3. Search Passwords")
                print("4. Settings")
                print("5. Logout")
                print("\nPress ESC at any time to return to menu")
                print("Press Ctrl+C to exit")

                choice = self.get_input("\nEnter your choice: ")
                if not choice:  # ESC was pressed
                    continue

                if choice == "1":
                    self.view_passwords()
                elif choice == "2":
                    self.add_password()
                elif choice == "3":
                    self.search_passwords()
                elif choice == "4":
                    self.show_settings()
                elif choice == "5":
                    self.logout()
                    print("\nLogged out successfully!")
                    return
                else:
                    print("\nInvalid choice. Please select a valid option.")
                    
        except KeyboardInterrupt:
            print("\n\nExiting User Panel. Goodbye!")
            sys.exit(0)
        except Exception as e:
            print(f"\nAn error occurred: {e}")
            print("Returning to menu...")

    def view_passwords(self):
        """View all stored passwords"""
        print("\n=== Stored Passwords ===")
        # TODO: Implement password viewing functionality
        print("Password viewing functionality coming soon!")

    def add_password(self):
        """Add a new password"""
        print("\n=== Add New Password ===")
        # TODO: Implement password adding functionality
        print("Password adding functionality coming soon!")

    def search_passwords(self):
        """Search stored passwords"""
        print("\n=== Search Passwords ===")
        # TODO: Implement password search functionality
        print("Password search functionality coming soon!")

    def show_settings(self):
        """Show user settings"""
        print("\n=== User Settings ===")
        # TODO: Implement settings functionality
        print("Settings functionality coming soon!") 