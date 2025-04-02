from pymongo import MongoClient
from dotenv import load_dotenv
import os
import uuid
from datetime import datetime
import bcrypt
from bson.binary import Binary
from bson import ObjectId

# Load environment variables
load_dotenv()

class UserDataManager:
    def __init__(self, user_data):
        """Initialize the UserDataManager with user data"""
        if not isinstance(user_data, dict):
            raise ValueError("User data must be a dictionary")
            
        if not user_data.get('id'):
            raise ValueError("User data must contain an 'id' field")
            
        self.user_id = str(user_data['id'])
        self.client = MongoClient(os.getenv('MONGODB_URI', 'mongodb://localhost:27017/'))
        self.db = self.client[os.getenv('DB_NAME', 'password_manager')]
        self.credentials = self.db.credentials
        
        # Create credentials collection if it doesn't exist
        if 'credentials' not in self.db.list_collection_names():
            self.db.create_collection('credentials')
            
    def get_user_data(self):
        """Get all data for the current user"""
        try:
            if not self.user_id or not isinstance(self.user_id, str):
                print("Invalid user ID")
                return []
                
            user_data = self.db.users.find_one({"_id": ObjectId(self.user_id)})
            return user_data.get("data", []) if user_data else []
        except Exception as e:
            print(f"Error getting user data: {str(e)}")
            return []
        
    def add_data(self, data):
        """Add new data for the current user"""
        try:
            if not data:
                return False
                
            if not self.user_id or not isinstance(self.user_id, str):
                print("Invalid user ID")
                return False
                
            result = self.db.users.update_one(
                {"_id": ObjectId(self.user_id)},
                {"$push": {"data": data}}
            )
            return result.modified_count > 0
        except Exception as e:
            print(f"Error adding data: {str(e)}")
            return False
        
    def delete_data(self, record_id):
        """Delete data for the current user"""
        try:
            if not self.user_id or not isinstance(self.user_id, str):
                print("Invalid user ID")
                return False
                
            result = self.db.users.update_one(
                {"_id": ObjectId(self.user_id)},
                {"$pull": {"data": {"record_id": record_id}}}
            )
            return result.modified_count > 0
        except Exception as e:
            print(f"Error deleting data: {str(e)}")
            return False
        
    def update_data(self, record_id, new_data):
        """Update existing data for the current user"""
        try:
            if not self.user_id or not isinstance(self.user_id, str):
                print("Invalid user ID")
                return False
                
            result = self.db.users.update_one(
                {
                    "_id": ObjectId(self.user_id),
                    "data.record_id": record_id
                },
                {"$set": {"data.$.info": new_data}}
            )
            return result.modified_count > 0
        except Exception as e:
            print(f"Error updating data: {str(e)}")
            return False
        
    def get_user_passwords(self):
        """Get all passwords for the current user"""
        try:
            # Find all credentials for the user
            cursor = self.credentials.find({"userId": ObjectId(self.user_id)})
            return list(cursor)
        except Exception as e:
            print(f"Error getting passwords: {str(e)}")
            return []
            
    def add_password(self, website, username, password, notes=""):
        """Add a new password entry"""
        try:
            # Validate inputs
            if not all(isinstance(x, str) for x in [website, username, password]):
                print("Invalid input types")
                return False
                
            # Create new credential document
            credential = {
                "userId": ObjectId(self.user_id),
                "website": website,
                "loginEntries": [{
                    "username": username,
                    "password": password,  # Store password as is for now
                    "notes": notes,
                    "createdAt": datetime.now(),
                    "updatedAt": datetime.now()
                }]
            }
            
            # Insert credential
            result = self.credentials.insert_one(credential)
            return bool(result.inserted_id)
            
        except Exception as e:
            print(f"Error adding password: {str(e)}")
            return False
            
    def update_password(self, website, old_username, new_username, new_password, new_notes=""):
        """Update an existing password entry"""
        try:
            # Validate inputs
            if not all(isinstance(x, str) for x in [website, old_username, new_username, new_password]):
                print("Invalid input types")
                return False
                
            # Find and update the credential
            result = self.credentials.update_one(
                {
                    "userId": ObjectId(self.user_id),
                    "website": website,
                    "loginEntries.username": old_username
                },
                {
                    "$set": {
                        "loginEntries.$.username": new_username,
                        "loginEntries.$.password": new_password,
                        "loginEntries.$.notes": new_notes,
                        "loginEntries.$.updatedAt": datetime.now()
                    }
                }
            )
            
            return result.modified_count > 0
            
        except Exception as e:
            print(f"Error updating password: {str(e)}")
            return False
            
    def delete_password(self, website, username):
        """Delete a password entry"""
        try:
            # Validate inputs
            if not all(isinstance(x, str) for x in [website, username]):
                print("Invalid input types")
                return False
                
            # Find and delete the credential
            result = self.credentials.delete_one({
                "userId": ObjectId(self.user_id),
                "website": website,
                "loginEntries.username": username
            })
            
            return result.deleted_count > 0
            
        except Exception as e:
            print(f"Error deleting password: {str(e)}")
            return False
            
    def search_passwords(self, query):
        """Search for passwords by website or username"""
        try:
            # Validate input
            if not isinstance(query, str):
                print("Invalid input type")
                return []
                
            # Create case-insensitive regex pattern
            pattern = {"$regex": query, "$options": "i"}
            
            # Find matching credentials
            cursor = self.credentials.find({
                "userId": ObjectId(self.user_id),
                "$or": [
                    {"website": pattern},
                    {"loginEntries.username": pattern}
                ]
            })
            
            return list(cursor)
            
        except Exception as e:
            print(f"Error searching passwords: {str(e)}")
            return []
            
    def get_categories(self):
        """Get all unique categories (websites) for the current user"""
        try:
            # Find distinct websites
            websites = self.credentials.distinct(
                "website",
                {"userId": ObjectId(self.user_id)}
            )
            return sorted(websites)
            
        except Exception as e:
            print(f"Error getting categories: {str(e)}")
            return []
            
    def get_passwords_by_category(self, website):
        """Get all passwords in a specific category"""
        try:
            # Validate input
            if not isinstance(website, str):
                print("Invalid input type")
                return []
                
            # Find credentials for the website
            cursor = self.credentials.find({
                "userId": ObjectId(self.user_id),
                "website": website
            })
            
            return list(cursor)
            
        except Exception as e:
            print(f"Error getting passwords by category: {str(e)}")
            return []
            
    def get_websites(self):
        """Get all websites for the current user"""
        try:
            if not self.user_id or not isinstance(self.user_id, str):
                print("Invalid user ID")
                return []
                
            websites = self.credentials.distinct(
                "website",
                {"userId": ObjectId(self.user_id)}
            )
            return sorted(websites)
        except Exception as e:
            print(f"Error getting websites: {str(e)}")
            return []
            
    def get_passwords_by_website(self, website):
        """Get all passwords for a specific website"""
        try:
            if not self.user_id or not isinstance(self.user_id, str):
                print("Invalid user ID")
                return []
                
            credential = self.credentials.find_one({
                "userId": ObjectId(self.user_id),
                "website": website
            })
            return credential.get("loginEntries", []) if credential else []
        except Exception as e:
            print(f"Error getting passwords by website: {str(e)}")
            return [] 