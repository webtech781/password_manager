import sys
import os
from gui import main as gui_main
from auth.auth_new import AuthManager

def main():
    try:
        # Initialize the authentication system
        auth = AuthManager()
        
        # Start the GUI with the auth instance
        gui_main(auth)
        
    except KeyboardInterrupt:
        print("\n\nExiting Password Manager. Goodbye!")
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
