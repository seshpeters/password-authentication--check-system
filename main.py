import hashlib
import re

# ==============================
# Password Security Component
# ==============================
class PasswordSecurity:
    """
    Handles password strength validation
    and secure hashing before storage.
    """

    def validate_strength(self, password):
        """
        Validates password strength using:
        - Minimum length (8 characters)
        - Uppercase letter
        - Lowercase letter
        - Number
        """

        if len(password) < 8:
            return False, "Password must be at least 8 characters long."

        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."

        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."

        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one number."

        return True, "Password is strong."

    def hash_password(self, password):
        """
        Hashes password using SHA-256 algorithm.
        Plain-text passwords are NEVER stored.
        """
        return hashlib.sha256(password.encode()).hexdigest()


# ==============================
# User Component
# ==============================
class User:
    """
    Represents a system user.
    Stores username and hashed password only.
    """

    def __init__(self, username, hashed_password):
        self.username = username
        self.hashed_password = hashed_password


# ==============================
# Authentication System Component
# ==============================
class AuthenticationSystem:
    """
    Handles user registration and login authentication.
    Demonstrates access control logic.
    """

    def __init__(self):
        self.registered_users = {}

    def register(self, username, password):
        security = PasswordSecurity()

        # Input validation
        if not username.strip():
            return False, "Username cannot be empty."

        valid, message = security.validate_strength(password)

        if not valid:
            return False, message

        # Hash password before storing
        hashed_password = security.hash_password(password)

        # Store securely (only hashed password)
        self.registered_users[username] = User(username, hashed_password)

        return True, "Registration successful."

    def login(self, username, password):
        security = PasswordSecurity()

        if username not in self.registered_users:
            return False, "User does not exist."

        hashed_input = security.hash_password(password)

        stored_user = self.registered_users[username]

        # Authentication logic
        if hashed_input == stored_user.hashed_password:
            return True, "Login successful. Access granted."
        else:
            return False, "Invalid password. Access denied."


# ==============================
# Program Execution
# ==============================
if __name__ == "__main__":

    auth_system = AuthenticationSystem()

    print("=== Simple Password Strength Checker & Authentication System ===")

    # Registration
    username = input("Enter username: ")
    password = input("Enter password: ")

    success, message = auth_system.register(username, password)
    print(message)

    if success:
        print("\n--- Login Attempt ---")
        login_user = input("Enter username: ")
        login_pass = input("Enter password: ")

        login_success, login_message = auth_system.login(login_user, login_pass)
        print(login_message)
