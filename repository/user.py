
from sqlalchemy.orm import Session
from model.models import UserInDB
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def create_user(db: Session, username: str, password: str, email: str = None, full_name: str = None):
    hashed_password = get_password_hash(password)
    db_user = UserInDB(username=username, hashed_password=hashed_password, email=email, full_name=full_name, disabled=False)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
