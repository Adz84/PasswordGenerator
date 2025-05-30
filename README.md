# Secure Password Generator

A robust and customisable command-line password generator built with Python's secrets module for cryptographic randomness. This tool focuses on generating strong, unique, and memorable passwords, providing control over character sets and offering entropy-based strength assessments.

## Features

Cryptographically Secure Randomness: Utilises Python's secrets module, ensuring passwords are generated using your operating system's most secure random number generator (CSPRNG).
Customisable Password Length: Define the exact length for your generated passwords (minimum 8 characters).
- Character Set Control: Choose to include:
  -Uppercase letters (A-Z)
  -Lowercase letters (a-z)
  -Digits (0-9)
- Special characters (from two distinct sets: all standard punctuation or a custom, commonly-used subset: !$*-.=?@_')
- Exclude Similar Characters: Option to remove characters that can be easily confused (e.g., I, l, 1, O, o, 0) to improve readability and reduce transcription errors.
- Custom Character Counts: Precisely specify the number of uppercase, lowercase, digit, and special characters to include.
- Common Pattern Detection: Automatically re-generates passwords if they contain common weak patterns, dictionary words, or simple sequential characters (e.g., "password", "123", "abc").
- Entropy-Based Strength Assessment: Each generated password comes with a strength rating (Very Weak, Weak, Medium, Strong, Very Strong) based on its calculated cryptographic entropy, giving you a clear understanding of its resilience against brute-force attacks.
- User-Friendly Interface: Interactive command-line prompts guide you through the password generation process.

## Why Use This Generator?
Many online password generators or simpler scripts rely on less secure random number generators. This tool prioritises security through cryptographic randomness, ensuring the unpredictability essential for robust passwords. The built-in entropy calculation and common pattern detection further empower you to create truly strong and unique credentials.

## Getting Started
Prerequisites
- Python 3.6+ installed on your system.

Installation
Clone the repository (or download the script directly):

- git clone https://github.com/EvilBeautyUK/SecurePasswordGenerator.git
- cd secure-password-generator

No further installation is required! This script uses only standard Python libraries.

Usage
Run the script from your Bash terminal:

- python password_generator.py

Follow the on-screen prompts to configure your password generation preferences:

- Number of passwords to generate: 1
- Desired password length (minimum 8): 16
- Include special characters (y/n) [y]: y
- Choose special character set:
  1. All standard special characters
  2. Only custom special characters ('!$*-.=?@_'')
  [1]: 2
- Exclude similar characters (y/n) [n]: y
  (e.g., I,l,1,O,o,0 will be excluded)
- Use custom character counts (e.g., specific number of uppercase, digits etc.) (y/n) [n]: n

- Your password is: r_x*@!S9-m3L=54F (Strength: Strong (60-127 bits of entropy))

- Generate more passwords? (y/n) [n]: n

## Security Considerations

- secrets Module: The core of this generator's security lies in Python's secrets module, which is designed for generating cryptographically strong random numbers suitable for managing secrets like passwords, authentication tokens, and security keys.
- No Logging: This script does not log or store generated passwords in any way. Once displayed on your console, they are not retained by the script.
- Local Execution: Running the script locally on your machine ensures that your password generation process is not dependent on external servers or network connections, reducing exposure risks.
- Pattern Avoidance: The is_common_pattern function is a vital security feature, designed to prevent the generation of passwords that, despite being random, might inadvertently form easily guessable patterns (like dictionary words, names, or simple sequences). While comprehensive, no such check is truly exhaustive against all possible weak patterns. Longer passwords with diverse character sets remain your best defense.

## Contributing
I'm currently learning Python, and this is my script that I'm releasing into the wild. Please feel free to fork this repository, submit pull requests, or open issues if you have suggestions for improvements or find any bugs.

## License
This project is open-source and available under the MIT License.
