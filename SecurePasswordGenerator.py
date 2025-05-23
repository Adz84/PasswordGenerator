# secure_password_generator.py

import string
import secrets
import sys
import math
import argparse

ALLOWED_SPECIAL_CHARS = "!$*-.=?@_'"


# Input/Validation utilities
def get_validated_input(prompt, validation_func=lambda x: True, error_msg="Invalid input. Please try again."):
    while True:
        try:
            user_input = input(prompt).strip()
            if validation_func(user_input):
                return user_input
            else:
                print(error_msg)
        except EOFError:
            print("\nExiting. End of input received.")
            sys.exit(0)
        except KeyboardInterrupt:
            print("\nStopping password generation.")
            sys.exit(0)
        except ValueError:
            print(error_msg)


# Entropy and strength analysis
def calculate_entropy(password, char_pool_used):
    if not char_pool_used:
        return 0.0
    char_space = len(char_pool_used)
    return math.log2(char_space ** len(password))

def password_strength(password, char_pool_used):
    entropy = calculate_entropy(password, char_pool_used)
    if entropy < 28:
        return "Very Weak (Less than 28 bits of entropy)"
    elif entropy < 36:
        return "Weak (28-35 bits of entropy)"
    elif entropy < 60:
        return "Medium (36-59 bits of entropy)"
    elif entropy < 128:
        return "Strong (60-127 bits of entropy)"
    else:
        return "Very Strong (128+ bits of entropy)"


# Character picking with CSPRNG
def csprng_choice(char_set):
    return secrets.choice(char_set)


# Pattern detection to avoid weak passwords
def is_common_pattern(password):
    p_lower = password.lower()
    weak_patterns = [
        "1234", "abcd", "password", "qwerty", "letmein", "admin", "asdf",
        "2023", "123123", "abcabc", "password123", "qwerty123",
        "1111", "2222", "aaaa", "bbbb", "cccc", "dddd",
        "guest", "user", "root", "secret", "changeme", "welcome"
        "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999", "0000",
        "12345", "abcdef", "password123", "qwerty123", "123456", "123456789",
        "azerty", "poiuy", "zxcvb", "1qaz", "wsxedc", "qawsed", "plokmijn",
        "2023", "2024", "2025", "1990", "1980", "2000", "1970",
        "01011990", "311299", "121212", "123123", "abcabc", "abcd1234",
        "aa1234", "aaa111", "111aaa", "qweasd", "asdfasdf", "123qwe", "321cba",
        "superman", "batman", "pokemon", "starwars", "harrypotter",
        "football", "liverpool", "arsenal", "chelsea", "monkey", "dragon", "tigger",
        "firstname", "surname", "fullname", "john123", "emma456", "michael1",
        "adminadmin", "password1", "admin1234", "root1234", "login123", "letmein1", "enter123",
        "backdoor", "malware", "virus", "firewall",
        "lastpass", "keepass", "dashlane", "securelogin", "mypassword", "passwordpassword",
        "qwertyu", "asdfghj", "zxcvbn", "qazwsx", "1q2w3e", "1q2w3e4r", "1234abcd",
        "1122", "1212", "abab", "aaaa", "bbbb", "cccc", "dddd",
        "guest", "user", "root", "secret", "pa$$word", "pass123", "passwrd",
        "admin1", "user1", "test", "test1", "welcome", "changeme", "master", "access",
        "default", "login", "secure", "private", "public", "support", "online", "system",
        "network", "server", "client", "database", "security", "protect", "hidden",
        "strong", "securepassword",
    ]
    keyboard_walks = ["qwe", "wer", "ert", "asd", "sdf", "dfg", "zxc", "xcv", "cvb"]
    
    for pattern in weak_patterns:
        if pattern in p_lower:
            return True

    for i in range(len(p_lower) - 2):
        sub = p_lower[i:i+3]
        if sub[0] == sub[1] == sub[2]:
            return True
        if sub in keyboard_walks:
            return True
        if sub.isdigit():
            if (int(sub[0]) + 1 == int(sub[1]) and int(sub[1]) + 1 == int(sub[2])):
                return True

    return False


# Password generator core
def password_generator(pass_len, num_upper=1, num_lower=1, num_digits=1, num_special=0, exclude_similar=False, special_chars_option="all"):
    if pass_len < 8:
        raise ValueError("Password length should be at least 8 characters.")

    total_required = num_upper + num_lower + num_digits + num_special
    if total_required > pass_len:
        raise ValueError("Sum of specified character counts exceeds password length.")

    if special_chars_option == "custom":
        selected_special_chars = ALLOWED_SPECIAL_CHARS
    elif special_chars_option == "all":
        selected_special_chars = string.punctuation
    else:
        selected_special_chars = ""

    char_sets_info = {
        "uppercase": (string.ascii_uppercase, num_upper),
        "lowercase": (string.ascii_lowercase, num_lower),
        "digits": (string.digits, num_digits),
        "special": (selected_special_chars, num_special)
    }

    if exclude_similar:
        similar_chars = "Il1Oo0"
        for k in char_sets_info:
            char_sets_info[k] = (''.join(c for c in char_sets_info[k][0] if c not in similar_chars), char_sets_info[k][1])

    for k, (s, n) in char_sets_info.items():
        if n > 0 and not s:
            raise ValueError(f"No characters left in set '{k}' after exclusions.")

    password_chars = []
    for char_set, count in char_sets_info.values():
        password_chars.extend(csprng_choice(char_set) for _ in range(count))

    char_pool = ''.join([s for s, _ in char_sets_info.values() if s])
    remaining = pass_len - len(password_chars)

    if remaining > 0:
        password_chars.extend(csprng_choice(char_pool) for _ in range(remaining))

    secrets.SystemRandom().shuffle(password_chars)
    password = ''.join(password_chars)

    retries = 0
    while is_common_pattern(password) and retries < 50:
        password_chars = []
        for char_set, count in char_sets_info.values():
            password_chars.extend(csprng_choice(char_set) for _ in range(count))
        if remaining > 0:
            password_chars.extend(csprng_choice(char_pool) for _ in range(remaining))
        secrets.SystemRandom().shuffle(password_chars)
        password = ''.join(password_chars)
        retries += 1

    return password, char_pool


# Interactive CLI
if __name__ == '__main__':
    try:
        while True:
            pass_count = int(get_validated_input("How many passwords would you like to generate? ", lambda x: x.isdigit() and int(x) > 0))
            pass_len = int(get_validated_input("Password length (min 8): ", lambda x: x.isdigit() and int(x) >= 8))

            include_special = get_validated_input("Include special characters? (y/n) [y]: ", lambda x: x.lower() in ('y', 'n', ''), "y").lower() != 'n'
            special_chars_option = "all" if include_special else "none"

            if include_special:
                choice = get_validated_input("Use all special characters or limited set? (1=All, 2=Custom) [1]: ", lambda x: x in ('1', '2', ''), "1")
                special_chars_option = "custom" if choice == '2' else "all"

            exclude_similar = get_validated_input("Exclude similar characters (e.g., 1/l/I)? (y/n) [n]: ", lambda x: x.lower() in ('y', 'n', ''), "n").lower() == 'y'

            use_custom = get_validated_input("Custom character counts? (y/n) [n]: ", lambda x: x.lower() in ('y', 'n', ''), "n").lower() == 'y'

            if use_custom:
                num_upper = int(get_validated_input("Number of uppercase: ", lambda x: x.isdigit()))
                num_lower = int(get_validated_input("Number of lowercase: ", lambda x: x.isdigit()))
                num_digits = int(get_validated_input("Number of digits: ", lambda x: x.isdigit()))
                num_special = int(get_validated_input("Number of special characters: ", lambda x: x.isdigit())) if include_special else 0
            else:
                num_upper = 1
                num_lower = 1
                num_digits = 1
                num_special = 1 if include_special else 0

            for _ in range(pass_count):
                try:
                    password, pool = password_generator(
                        pass_len,
                        num_upper=num_upper,
                        num_lower=num_lower,
                        num_digits=num_digits,
                        num_special=num_special,
                        exclude_similar=exclude_similar,
                        special_chars_option=special_chars_option
                    )
                    print(f"\nGenerated password: {password} (Strength: {password_strength(password, pool)})\n")
                except ValueError as e:
                    print(f"Error: {e}")
                    break

            if get_validated_input("Generate more? (y/n) [n]: ", lambda x: x.lower() in ('y', 'n', ''), "n").lower() != 'y':
                break

    except KeyboardInterrupt:
        print("\nStopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)