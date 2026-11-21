
from database import register_user, get_user_by_email
from security import hash_password, verify_password


def create_account(username, email, password):
    hashed_password = hash_password(password)

    return register_user(
        username,
        email,
        hashed_password
    )


def login_user(email, password):
    user = get_user_by_email(email)

    if user is None:
        return None

    user_id, username, email, password_hash = user

    if not verify_password(password, password_hash):
        return None

    return {
        "id": user_id,
        "username": username,
        "email": email
    }
