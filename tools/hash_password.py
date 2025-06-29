# hash_password.py
import bcrypt
import getpass

def main():
    """Generates a bcrypt hash for a given password."""
    try:
        password = getpass.getpass("Enter the password to hash: ")
        if not password:
            print("Password cannot be empty.")
            return

        confirm_password = getpass.getpass("Confirm the password: ")
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            return

        # Encode the password to bytes, generate a salt, and hash it
        password_bytes = password.encode('utf-8')
        hashed_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

        # Decode the hash back to a string for easy copying
        hashed_string = hashed_bytes.decode('utf-8')

        print("\nSUCCESS!")
        print("Store the following hash in your PROXY_PASSWORD environment variable:")
        print("--------------------------------------------------------------------")
        print(hashed_string)
        print("--------------------------------------------------------------------")

    except Exception as e:
        print(f"\nAn error occurred: {e}")

if __name__ == "__main__":
    main()