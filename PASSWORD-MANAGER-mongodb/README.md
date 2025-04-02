# Password Manager

A secure password manager application with a modern GUI interface built using Python and CustomTkinter.

## Features

- User authentication with email verification
- Secure password storage with encryption
- Password management (add, edit, delete, search)
- Category organization
- Password generator
- Import/Export functionality
- Modern and intuitive GUI

## Prerequisites

- Python 3.8 or higher
- MongoDB database
- Gmail account (for email verification)

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd password-manager
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the root directory with the following variables:
```
MONGODB_URI=your_mongodb_connection_string
DB_NAME=your_database_name
SENDER_EMAIL=your_gmail_address
EMAIL_PASSWORD=your_gmail_app_password
```

Note: For the Gmail app password, you'll need to:
1. Enable 2-factor authentication on your Gmail account
2. Generate an app password for this application
3. Use that app password in the EMAIL_PASSWORD variable

## Running the Application

1. Start the application:
```bash
python main.py
```

2. Register a new account or login with existing credentials

## Usage

### Adding Passwords
1. Click "Add New Password" from the dashboard
2. Enter website, username, and password
3. Optionally select a category
4. Click "Save Password"

### Managing Passwords
- View all passwords in the "Passwords" section
- Search passwords using the search bar
- Edit or delete passwords using the action buttons
- Organize passwords into categories

### Security Features
- Passwords are encrypted before storage
- Email verification required for registration
- Secure password reset process
- Session management

## Security Considerations

- Never share your master password
- Use strong, unique passwords
- Enable 2-factor authentication when available
- Regularly update your passwords
- Keep your application up to date

## Support

For support or feature requests, please open an issue in the repository or contact support@passwordmanager.com

## License

This project is licensed under the MIT License - see the LICENSE file for details.
