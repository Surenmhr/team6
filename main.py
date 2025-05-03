import json
import re
import random
import string

# Caesar cipher encryption and decryption functions (pre-implemented)
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Password strength checker function (optional)
def is_strong_password(password):
    if len(password) < 8:
        return False
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/" for c in password)

    return has_lower and has_upper and has_digit and has_special

# Password generator function (optional)
def generate_password(length):
    if length < 8:
        print("Password length should be at least 8 for strength.")
        return ""
    
    # Define possible characters
    all_characters = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?/"

    # Randomly select characters
    password = ''.join(random.choice(all_characters) for _ in range(length))

    return password

# Initialize empty lists to store encrypted passwords, websites, and usernames
encrypted_passwords = []
websites = []
usernames = []

# In-memory password storage
passwords = {}

SHIFT = 3  # Caesar cipher shift value

def add_password(service, username, password):
    """
    Add or update a password for a given service.
    Encrypt the password before storing.
    """
    encrypted_password = caesar_encrypt(password, SHIFT)
    passwords[service] = {
        "username": username,
        "password": encrypted_password
    }

def get_password(service):
    """
    Retrieve and decrypt the password for a given service.
    Returns None if the service is not found.
    """
    entry = passwords.get(service)
    if not entry:
        return None
    decrypted_password = caesar_decrypt(entry["password"], SHIFT)
    return {
        "username": entry["username"],
        "password": decrypted_password
    }

# Function to save passwords to a JSON file 
def save_passwords():
    try:
        with open("vault.txt", "w", encoding="utf-8") as file:
            for website, username, encrypted_password in zip(websites, usernames, encrypted_passwords):
                file.write(f"{website},{username},{encrypted_password}\n")
        print("Passwords saved successfully!")
    except Exception as e:
        print("Oops, something went wrong while saving:", e)

# Function to load passwords from a JSON file

# Function to load passwords from a text file
def load_passwords():
    """
    Load passwords from a text file into the password vault.

    This function reads the "vault.txt" file and populates the
    websites, usernames, and encrypted_passwords lists.
    """
    try:
        with open("vault.txt", "r", encoding="utf-8") as file:
            for line in file:
                parts = line.strip().split(",")
                if len(parts) == 3:
                    website, username, encrypted_password = parts
                    websites.append(website)
                    usernames.append(username)
                    encrypted_passwords.append(encrypted_password)
        print("Passwords loaded successfully!")
    except FileNotFoundError:
        print("No saved passwords found. Starting fresh!")
    except Exception as e:
        print("Oops, something went wrong while loading:", e)

# Main method
def main():
    """
    Main function to implement the user interface.
    """
    while True:
        print("\nPassword Manager Menu:")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Save Passwords")
        print("4. Load Passwords")
        print("5. Quit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            print("Add Password functionality is not implemented yet.")
        elif choice == "2":
            print("Get Password functionality is not implemented yet.")
        elif choice == "3":
            save_passwords()
        elif choice == "4":
            load_passwords()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")

# Execute the main function when the program is run
if __name__ == "__main__":
    main()