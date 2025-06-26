from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

plain_password = "Space@123"

hashed_pw = bcrypt.generate_password_hash(plain_password).decode('utf-8')

print(hashed_pw)