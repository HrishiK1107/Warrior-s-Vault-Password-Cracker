import hashlib

# Replace 'your_password' with the password you want to hash
password = 'dragon'
hashed_password = hashlib.md5(password.encode()).hexdigest()
print(f'MD5 Hash of "{password}": {hashed_password}')
