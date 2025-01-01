from fastapi import FastAPI
from routes.auth_router import router as auth_router
from routes.user_router import router as user_router  # Assuming you also have a user router
from database.database import engine, Base

app = FastAPI()

Base.metadata.create_all(bind=engine)

# Include the authentication router with the prefix "/api/auth"
app.include_router(auth_router, prefix="/api/auth", tags=["auth"])

# Include the user management router with the prefix "/api"
app.include_router(user_router, prefix="/api", tags=["users"])
