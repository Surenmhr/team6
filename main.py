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

# Function to add a new password 
def add_password():
    """
    Add a new password to the password manager.

    This function should prompt the user for the website, username,  and password and store them to lits with same index. Optionally, it should check password strengh with the function is_strong_password. It may also include an option for the user to
    generate a random strong password by calling the generate_password function.

    return None
    """

# Function to retrieve a password 
def get_password():
    """
    Retrieve a password for a given website.

    This function should prompt the user for the website name and
    then display the username and decrypted password for that website.

    Returns:
        None
    """

# Function to save passwords to a JSON file 
def save_passwords():
    """
    Saves the websites, usernames, and encrypted passwords to 'vault.txt' in JSON format.
    """

    try:
        # Combine all data into a list of dictionaries
        data_to_save = []
        for i in range(len(websites)):
            entry = {
                "website": websites[i],
                "username": usernames[i],
                "password": encrypted_passwords[i]
            }
            data_to_save.append(entry)
          # Write the data to 'vault.txt' using JSON
        with open("vault.txt", "w", encoding="utf-8") as file:
            json.dump(data_to_save, file, indent=4)
        
        print("Passwords saved successfully!")

    except Exception as e:
        print("Oops, something went wrong while saving:", e)
        
# Function to load passwords from a JSON file

def load_passwords():
    """
    Loads websites, usernames, and encrypted passwords from 'vault.txt' JSON file.
    Populates the global lists: websites, usernames, and encrypted_passwords.
    """

    global websites, usernames, encrypted_passwords  # needed to update global variables

    try:
        with open("vault.txt", "r", encoding="utf-8") as file:
            loaded_data = json.load(file)

            # Clear existing lists first
            websites.clear()
            usernames.clear()
            encrypted_passwords.clear()

            # Fill the lists with loaded data
            for entry in loaded_data:
                websites.append(entry["website"])
                usernames.append(entry["username"])
                encrypted_passwords.append(entry["password"])
        
        print("Passwords loaded successfully!")

    except FileNotFoundError:
        print("No saved password file found (vault.txt).")
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