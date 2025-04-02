import bcrypt
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv
import os
from bson import ObjectId

# Load environment variables
load_dotenv()

class AuthManager:
    def __init__(self):
        """Initialize the authentication system"""
        # Connect to MongoDB
        self.client = MongoClient(os.getenv('MONGODB_URI', 'mongodb://localhost:27017/'))
        self.db = self.client[os.getenv('DB_NAME', 'password_manager')]
        self.users = self.db.users
        self.current_user = None
        
        # Create collections if they don't exist
        if 'users' not in self.db.list_collection_names():
            self.db.create_collection('users')
            
    def register(self, username, email, password):
        """Register a new user"""
        try:
            # Input validation
            if not all(isinstance(x, str) for x in [username, email, password]):
                raise ValueError("All inputs must be strings")
                
            if not all([username, email, password]):
                raise ValueError("All fields are required")
                
            # Check if user exists
            if self.users.find_one({"$or": [{"username": username}, {"email": email}]}):
                raise ValueError("Username or email already exists")
                
            # Hash password
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            # Create user document
            user = {
                "username": username,
                "email": email,
                "password": hashed,
                "created_at": datetime.now(),
                "email_verified": True
            }
            
            # Insert user
            result = self.users.insert_one(user)
            return bool(result.inserted_id)
            
        except Exception as e:
            print(f"Registration error: {str(e)}")
            return False
            
    def login(self, username, password):
        """Login a user"""
        try:
            # Input validation
            if not all(isinstance(x, str) for x in [username, password]):
                raise ValueError("Username and password must be strings")
                
            if not all([username, password]):
                raise ValueError("Username and password are required")
                
            # Find user
            user = self.users.find_one({"username": username})
            if not user:
                raise ValueError("User not found")
                
            # Get stored password
            stored_password = user.get('password')
            if not stored_password:
                raise ValueError("No password found for user")
                
            # Verify password
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                # Set current user
                self.current_user = {
                    "id": str(user["_id"]),
                    "username": user["username"],
                    "email": user["email"]
                }
                return True
            else:
                raise ValueError("Invalid password")
                
        except Exception as e:
            print(f"Login error: {str(e)}")
            return False
            
    def logout(self):
        """Logout current user"""
        self.current_user = None
        return True
        
    def is_logged_in(self):
        """Check if user is logged in"""
        return self.current_user is not None
        
    def get_current_user(self):
        """Get current user data"""
        if not self.current_user:
            return None
            
        return {
            "id": str(self.current_user["id"]),
            "username": str(self.current_user["username"]),
            "email": str(self.current_user["email"])
        }
        
    def change_password(self, old_password, new_password):
        """Change user's password"""
        try:
            if not self.current_user:
                raise ValueError("No user logged in")
                
            # Input validation
            if not all(isinstance(x, str) for x in [old_password, new_password]):
                raise ValueError("Passwords must be strings")
                
            if not all([old_password, new_password]):
                raise ValueError("Both passwords are required")
                
            # Find user
            user = self.users.find_one({"_id": ObjectId(self.current_user["id"])})
            if not user:
                raise ValueError("User not found")
                
            # Verify old password
            if not bcrypt.checkpw(old_password.encode('utf-8'), user['password']):
                raise ValueError("Invalid old password")
                
            # Hash new password
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(new_password.encode('utf-8'), salt)
            
            # Update password
            result = self.users.update_one(
                {"_id": user["_id"]},
                {"$set": {"password": hashed}}
            )
            
            return result.modified_count > 0
            
        except Exception as e:
            print(f"Error changing password: {str(e)}")
            return False
            
    def delete_account(self, password):
        """Delete user account"""
        try:
            if not self.current_user:
                raise ValueError("No user logged in")
                
            # Input validation
            if not isinstance(password, str):
                raise ValueError("Password must be a string")
                
            if not password:
                raise ValueError("Password is required")
                
            # Find user
            user = self.users.find_one({"_id": ObjectId(self.current_user["id"])})
            if not user:
                raise ValueError("User not found")
                
            # Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
                raise ValueError("Invalid password")
                
            # Delete user
            result = self.users.delete_one({"_id": user["_id"]})
            
            if result.deleted_count > 0:
                self.current_user = None
                return True
            return False
            
        except Exception as e:
            print(f"Error deleting account: {str(e)}")
            return False

    def check_user_exists(self, username, email):
        """Check if username or email already exists in the database."""
        try:
            # Check for existing username or email
            existing_user = self.users.find_one({
                "$or": [
                    {"username": username},
                    {"email": email}
                ]
            })
            return existing_user is not None
        except Exception as e:
            print(f"Error checking user existence: {str(e)}")
            return False 