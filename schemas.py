# schemas.py

from pydantic import BaseModel
from typing import Optional

# Token schema used when the token is issued
class Token(BaseModel):
    access_token: str
    token_type: str

# TokenData schema used when decoding a JWT token
class TokenData(BaseModel):
    username: Optional[str] = None

# User schema used for creating a new user
class UserCreate(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    password: str
    
class User(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None  # Add the 'disabled' field

    class Config:
        orm_mode = True
        from_attributes = True
