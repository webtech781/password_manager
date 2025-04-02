import bcrypt
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv
import os
from bson import ObjectId

# Load environment variables
load_dotenv()

class SimpleAuth:
    def __init__(self):
        """Initialize the SimpleAuth system"""
        self.client = MongoClient(os.getenv('MONGODB_URI'))
        self.db = self.client[os.getenv('DB_NAME')]
        self.users = self.db.users
        self.current_user = None
        
        # Create users collection if it doesn't exist
        if 'users' not in self.db.list_collection_names():
            self.db.create_collection('users')
            
    def register(self, username, email, password):
        """Register a new user"""
        try:
            # Validate inputs
            if not isinstance(username, str) or not isinstance(email, str) or not isinstance(password, str):
                print("Invalid input types")
                return False
                
            # Check if username or email already exists
            if self.users.find_one({"$or": [{"username": username}, {"email": email}]}):
                print("Username or email already exists")
                return False
                
            # Hash the password
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            # Create user document
            user = {
                "username": username,
                "email": email,
                "password": hashed,
                "created_at": datetime.now(),
                "email_verified": True  # For simplicity, we'll set this to True
            }
            
            # Insert user
            result = self.users.insert_one(user)
            if result.inserted_id:
                print("Registration successful!")
                return True
            return False
            
        except Exception as e:
            print(f"Registration error: {str(e)}")
            return False
            
    def login(self, username, password):
        """Login a user"""
        try:
            # Validate inputs
            if not isinstance(username, str) or not isinstance(password, str):
                print("Invalid input types")
                return False
                
            # Find user
            user = self.users.find_one({"username": username})
            if not user:
                print("User not found")
                return False
                
            # Get stored password
            stored_password = user.get('password')
            if not stored_password:
                print("No password found for user")
                return False
                
            # Verify password
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                # Set current user
                self.current_user = {
                    "id": str(user["_id"]),
                    "username": user["username"],
                    "email": user["email"]
                }
                print("Login successful!")
                return True
            else:
                print("Invalid password")
                return False
                
        except Exception as e:
            print(f"Login error: {str(e)}")
            return False
            
    def logout(self):
        """Logout current user"""
        self.current_user = None
        print("Logged out successfully")
        
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
                print("No user logged in")
                return False
                
            # Validate inputs
            if not isinstance(old_password, str) or not isinstance(new_password, str):
                print("Invalid input types")
                return False
                
            # Find user
            user = self.users.find_one({"_id": ObjectId(self.current_user["id"])})
            if not user:
                print("User not found")
                return False
                
            # Verify old password
            if not bcrypt.checkpw(old_password.encode('utf-8'), user['password']):
                print("Invalid old password")
                return False
                
            # Hash new password
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(new_password.encode('utf-8'), salt)
            
            # Update password
            result = self.users.update_one(
                {"_id": user["_id"]},
                {"$set": {"password": hashed}}
            )
            
            if result.modified_count > 0:
                print("Password changed successfully!")
                return True
            return False
            
        except Exception as e:
            print(f"Error changing password: {str(e)}")
            return False
            
    def delete_account(self, password):
        """Delete user account"""
        try:
            if not self.current_user:
                print("No user logged in")
                return False
                
            # Validate input
            if not isinstance(password, str):
                print("Invalid input type")
                return False
                
            # Find user
            user = self.users.find_one({"_id": ObjectId(self.current_user["id"])})
            if not user:
                print("User not found")
                return False
                
            # Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
                print("Invalid password")
                return False
                
            # Delete user
            result = self.users.delete_one({"_id": user["_id"]})
            
            if result.deleted_count > 0:
                self.current_user = None
                print("Account deleted successfully!")
                return True
            return False
            
        except Exception as e:
            print(f"Error deleting account: {str(e)}")
            return False 