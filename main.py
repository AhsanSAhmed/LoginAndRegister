import os
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
import jwt
import datetime
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

# MongoDB connection (using environment variable)
MONGO_DETAILS = os.getenv("MONGO_DB_URL")  # Get MongoDB URL from environment variable
client = MongoClient(MONGO_DETAILS)
db = client.user_db
users_collection = db.users

# FastAPI app
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# User model
class User(BaseModel):
    username: str
    password: str

class UserInDB(User):
    hashed_password: str

# Utility functions
def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_user(username: str):
    user = users_collection.find_one({"username": username})
    return user

def create_access_token(data: dict, expires_delta: datetime.timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, "your_jwt_secret", algorithm="HS256")

# Registration endpoint
@app.post("/register")
def register(user: User):
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    users_collection.insert_one({"username": user.username, "password": hashed_password})

    return {"message": "User registered successfully!"}

# Login endpoint
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    
    if not user or not verify_password(form_data.password, user['password']):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    access_token = create_access_token(data={"sub": user['username']})
    return {"access_token": access_token, "token_type": "bearer"}

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)  # Run on all network interfaces
