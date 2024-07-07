import re

def check_password_strength(password):
    length_criteria = len(password) >= 8
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    digit_criteria = bool(re.search(r'\d', password))
    special_char_criteria = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    strength = sum([length_criteria, uppercase_criteria, lowercase_criteria, digit_criteria, special_char_criteria])
    
    if strength == 5:
        return "Very Strong", "Your password is very strong."
    elif strength == 4:
        return "Strong", "Your password is strong."
    elif strength == 3:
        return "Moderate", "Your password is moderate."
    elif strength == 2:
        return "Weak", "Your password is weak."
    else:
        return "Very Weak", "Your password is very weak."

def main():
    print("Password Complexity Checker")
    password = input("Enter a password to check its strength: ").strip()

    strength, message = check_password_strength(password)
    print(f"Password Strength: {strength}")
    print(message)

if __name__ == "__main__":
    main()
