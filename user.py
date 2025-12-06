from flask_login import UserMixin

class User(UserMixin):
    """Simple user model for flask-login.

    Keeps the same constructor signature used in `app.py`.
    """
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

    def __repr__(self):
        return f"<User id={self.id} username={self.username!r}>"
    