## Warrior's Vault: Password Cracker🛡️⚔️

**Warrior's Vault** is a powerful password cracking tool designed to help users recover lost passwords using various methods, including brute force, dictionary attacks, and hybrid approaches. It supports both MD5 and SHA256 hash types.

### Features

- **Password Strength Evaluation**: Assesses the strength of a given password based on length and complexity.
- **Brute Force Cracking Method**: Attempts to crack passwords using a brute-force approach by generating possible combinations.
- **Dictionary Attack**: Cracks passwords using a predefined wordlist to find matches.
- **Hybrid Cracking Method**: Combines dictionary and brute-force methods, allowing for suffixes to be appended to words in the dictionary.
- **MD5 Hash Generator**: Generates MD5 hashes for input strings.
- **SHA-256 Hash Generator**: Generates SHA-256 hashes for input strings.
- **Logging**: Records successful password cracks and their strength in a log file for reference.
- **User-Friendly CLI**: An engaging command-line interface that guides users through the password cracking process.

### Hash Generators

This project includes two hash generator functions that allow users to generate MD5 and SHA-256 hashes from input strings. These functions provide a straightforward way to obtain hashed representations of passwords or any other text, enhancing the tool's utility for security analysis and password management.

- **MD5 Hash Generator**: Generates an MD5 hash from a given input string. While MD5 is fast, it is considered cryptographically broken and unsuitable for further use in security-sensitive applications.

- **SHA-256 Hash Generator**: Produces a SHA-256 hash, a member of the SHA-2 family, which is significantly more secure than MD5 and widely used in various security applications and protocols.


### Requirements

- Python 3.x
- `pyopencl` for GPU acceleration (optional)

### Installation

1.Clone this repository:
   
   ```bash
   git clone https://github.com/YourUsername/password-cracker.git
   ```

2.Install any necessary dependencies. For pyopencl, you can use:
 ```
cd password-cracker
```

### Usage

1.Run the password cracker tool:
```
python password_cracker.py
```

2.Follow the prompts to:
- Enter the hash type (e.g., md5 or sha256).
- Input the password hash you want to crack.
- Choose a cracking method:
i.Brute Force
ii.Dictionary Attack
iii.Hybrid Attack

### Example Usage
<pre>
This is Warrior's Vault: Password Cracker!
Enter the hash type (e.g., md5, sha256): md5
Enter the password hash: 5f4dcc3b5aa765d61d8327deb882cf99
Choose a cracking method:
1. Brute Force
2. Dictionary Attack
3. Hybrid Attack
Enter the number of your choice: 2
</pre>


### Logging
Found passwords and their strengths will be logged in password_cracker.log.

### License
This project is licensed under the MIT License. See the LICENSE file for details.

### Disclaimer
**Warrior's Vault: Password Cracker** is intended for educational and ethical hacking purposes only. This tool should only be used on passwords or systems that you own or have explicit permission to test. Unauthorized use against any system is illegal and may lead to severe consequences, including legal action.

By using this tool, you acknowledge that you are solely responsible for any consequences arising from its use. The author and contributors of this project are not liable for any damages, losses, or legal issues resulting from the misuse of this tool.
