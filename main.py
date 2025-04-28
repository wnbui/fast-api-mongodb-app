from fastapi import FastAPI, HTTPException, Depends, Request, Response, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
from starlette.middleware.sessions import SessionMiddleware
from pymongo import MongoClient
from bson import ObjectId
import datetime as dt
from datetime import date, datetime
import jwt, os, re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
SECRET_KEY = os.getenv('JWT_SECRET_KEY')
SESSION_SECRET_KEY = os.getenv('SESSION_SECRET_KEY')
ALGORITHM = os.getenv('JWT_ALGORITHM')
ACCESS_TOKEN_EXPIRY = int(os.getenv('ACCESS_TOKEN_EXPIRY', 30))
SESSION_MAX_AGE = int(os.getenv('SESSION_MAX_AGE', 3600))
MONGODB_URI = os.getenv('MONGODB_URI')
MONGODB_DB_NAME = os.getenv('MONGO_DB_NAME', 'inventory_management')

if not SECRET_KEY or not ALGORITHM or not SESSION_SECRET_KEY:
    raise RuntimeError("Environmental variables JWT_SECRET_KEY, JWT_ALGORITHM, and SESSION_SECRET_KEY must be set in .env")

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI environmental variable is required.")

# MongoDB setup
client = MongoClient(MONGODB_URI)
db = client[MONGODB_DB_NAME]
users_collection = db["users"]
items_collection = db["inventory"]

# Indexing
users_collection.create_index("username", unique=True)
items_collection.create_index("user_id")

# App and middleware
app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    session_cookie="session",
    max_age=SESSION_MAX_AGE,
    same_site='lax',
    path="/",
    https_only=False
)
security = HTTPBearer()

# Serialize Mongo document to dict with string id for JSON serialization
def serialize_item(doc: dict) -> dict:
    return {
        "id": str(doc.get("_id")),
        "user_id": doc.get("user_id"),
        "name": doc.get("name"),
        "description": doc.get("description"),
        "price": float(doc.get("price")),
        "quantity": int(doc.get("quantity")),
        "condition": doc.get("condition"),
        "last_updated": doc.get("last_updated") if isinstance(doc.get("last_updated"), str) else doc.get("last_updated").isoformat()
    }

# Pydantic Schemas
class UserCreate(BaseModel):
    username: str = Field(..., min_length=5, max_length=50)
    password: str = Field(..., min_length=8, max_length=255)
    email: EmailStr
    role: str

    @field_validator('role', mode='after')
    @classmethod
    def role_validation(cls, role: str) -> str:
        if not (role == "user" or role == "admin"):
            raise ValueError("Role must either be 'user' or 'admin'")
        return role

    @field_validator('password', mode='after')
    @classmethod
    def password_validation(cls, password: str) -> str:
        if not re.search(r'\d', password):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r'[A-Z]', password):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', password):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not re.search(r'[\W_]', password):
            raise ValueError("Password must contain at least one special character.")
        return password
    
class UserOut(BaseModel):
    username: str
    password: str # Ideally you want to hide this
    email: EmailStr # Ideally you want to hide this
    role: str # Ideally you want to hide this

    model_config = ConfigDict()

class UserRead(BaseModel):
    username: str
    password: str

class ItemCreate(BaseModel):
    user_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1, max_length=50)
    description: str = Field(..., min_length=1, max_length=250)
    price: float = Field(gt=0, description="The price must be greater than zero.")
    quantity: int = Field(gt=0, description="The quantity must be greater than zero.")
    condition: str = Field(..., pattern="^(new|used|refurbished)$", description="Must be one of: new, used or refurbished.")
    last_updated: date = Field(..., description="The date must be in format YYY-MM-DD")

class ItemOut(BaseModel):
    id: str
    user_id: str
    name: str
    description: str
    price: float
    quantity: int
    condition: str
    last_updated: str

    model_config = ConfigDict()

    # JWT
def create_access_token(data: dict, expires_delta: dt.timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = dt.datetime.now(dt.timezone.utc) + (expires_delta or dt.timedelta(minutes=ACCESS_TOKEN_EXPIRY))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# JWT Dependency
def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict[str, str]:
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=401, detail="Token is missing.")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username: str = payload.get("username")
        role: str = payload.get("role")
        if not username or not role:
            raise HTTPException(status_code=401, detail="Invalid token payload.")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.")
    return {"username": username, "role": role}

# Convert and validate ObjectId, used to validate _id for items
def validate_object_id(id_str: str) -> ObjectId:
    if not ObjectId.is_valid(id_str):
        raise HTTPException(status_code=400, detail="Invalid item ID.")
    return ObjectId(id_str)

# /register POST
@app.post("/register", response_model=UserOut, status_code=201)
def register_user(user: UserCreate) -> UserOut:
    if users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already exists.")
    
    user_dict = user.model_dump()
    users_collection.insert_one(user_dict)
    return user_dict

# /login POST
@app.post("/login", status_code=200)
def login_user(request: Request, response: Response, user: UserRead) -> dict:
    db_user = users_collection.find_one({"username": user.username})
    
    if not db_user or db_user["password"] != user.password:
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    
    access_token = create_access_token({"username": db_user["username"], "role": db_user["role"]})

    request.session["username"] = db_user["username"]
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRY*60
    )

    return {"message": "Login successful", "access_token": access_token, "token_type": "bearer"}

# /logout POST
@app.post("/logout", status_code=200)
def logout(request: Request, response: Response):
    request.session.clear()
    response.delete_cookie("session")
    return {"message": "Logged out successfully"}

## User Routes

# /inventory GET
@app.get("/inventory", response_model=list[ItemOut], status_code=200)
def get_all_items(current_user: dict = Depends(get_current_user)) -> list[ItemOut]:
    docs = items_collection.find({"user_ider": current_user["username"]})
    return [serialize_item(doc) for doc in docs]

# /inventory/item_id GET
@app.get("/inventory/{item_id}", response_model=ItemOut, status_code=200)
def get_item(item_id: str, current_user: dict = Depends(get_current_user)) -> ItemOut:
    oid = validate_object_id(item_id)
    doc = items_collection.find_one({"_id": oid})
    
    if not doc:
        raise HTTPException(status_code=404, detail="Item not found.")
    if doc["user_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="Not authorized to access item.")
    
    return serialize_item(doc)

# /inventory POST
@app.post("/inventory", response_model=ItemOut, status_code=201)
def add_item(item_in: ItemCreate, current_user: dict = Depends(get_current_user)) -> ItemOut:
    if item_in.user_id != current_user["username"]:
        raise HTTPException(status_code=403, detail="Cannot create item for another user.")
    
    data = item_in.model_dump()
    data["user_id"] = current_user["username"]
    data["last_updated"] = data["last_updated"].isoformat()
    result = items_collection.insert_one(data)
    return serialize_item(items_collection.find_one({"_id": result.inserted_id}))

# /inventory/item_id PUT
@app.put("/inventory/{item_id}", response_model=ItemOut, status_code=200)
def update_item(item_id: str, updated_item: ItemCreate, current_user: dict = Depends(get_current_user)) -> ItemOut:
    oid = validate_object_id(item_id)
    doc = items_collection.find_one({"_id": oid})
    
    if not doc:
        raise HTTPException(status_code=404, detail="Item not found.")
    if doc["user_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="Not authorized to edit item.")
    
    data = updated_item.model_dump()
    data["last_updated"] = data["last_updated"].isoformat()
    items_collection.update_one({"_id": oid}, {"$set": data})
    return serialize_item(items_collection.find_one({"_id": oid}))

# /inventory/item_id DELETE
@app.delete("/inventory/{item_id}")
def delete_item(item_id: str, current_user: dict = Depends(get_current_user)) -> dict:
    oid = validate_object_id(item_id)
    doc = items_collection.find_one({"_id": oid})
    
    if not doc:
        raise HTTPException(status_code=404, detail="Item not found.")
    if doc["user_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="Not authorized to delete item.")
    
    items_collection.delete_one({"_id": oid})
    return {"message": "Item deleted successfully"}

## Admin routes

# Helper function to veify role
def require_admin(role: str):
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")

# /admin/inventory GET
@app.get("/admin/inventory", response_model=list[ItemOut], status_code=200)
def admin_get_all_items(current_user: dict = Depends(get_current_user)) -> list[ItemOut]:
    require_admin(current_user["role"])
    
    docs = items_collection.find()
    return [serialize_item(doc) for doc in docs]

# /admin/inventory/user GET
@app.get("/admin/inventory/{user}", response_model=list[ItemOut], status_code=200)
def admin_get_all_user_items(user: str, current_user: dict = Depends(get_current_user)) ->list[ItemOut]:
    require_admin(current_user["role"])
    
    if not users_collection.find_one({"username": user}):
        raise HTTPException(status_code=404, detail="User does not exist.")
    
    docs = items_collection.find({"user_id": user})
    return [serialize_item(doc) for doc in docs]

# /admin/inventory/user/item_id GET
@app.get("/admin/inventory/{user}/{item_id}", response_model=ItemOut, status_code=200)
def admin_get_user_item(user: str, item_id: str, current_user: dict = Depends(get_current_user)) -> ItemOut:
    require_admin(current_user["role"])
    
    if not users_collection.find({"user_id": user}):
        raise HTTPException(status_code=404, detail="User does not exist.")
    
    oid = validate_object_id(item_id)
    doc = items_collection.find_one({"_id": oid, "user_id": user})
    
    if not doc:
        raise HTTPException(status_code=404, detail="Item not found for specified user.")
    
    return serialize_item(doc)

# /admin/inventory/user POST
@app.post("/admin/inventory/{user}", response_model=ItemOut, status_code=201)
def admin_add_item(user: str, item_in: ItemCreate, current_user: dict = Depends(get_current_user)) -> ItemOut:
    require_admin(current_user["role"])
    
    if item_in.user_id != user:
        raise HTTPException(status_code=403, detail="user_id mismatch.")
    if not users_collection.find_one({"username": user}):
        raise HTTPException(status_code=404, detail="User does not exist.")
    
    data = item_in.model_dump()
    data["user_id"] = user
    data["last_updated"] = data["last_updated"].isoformat()
    result = items_collection.insert_one(data)
    return serialize_item(items_collection.find_one({"_id": result.inserted_id}))

# /admin/inventory/user/item_id PUT
@app.put("/admin/inventory/{user}/{item_id}", response_model=ItemOut, status_code=200)
def admin_update_item(user: str, item_id: str, updated_item: ItemCreate, current_user: dict = Depends(get_current_user)) -> ItemOut:
    require_admin(current_user["role"])
    
    if updated_item.user_id != user:
        raise HTTPException(status_code=403, detail="user_id mismatch.")
    if not users_collection.find_one({"username": user}):
        raise HTTPException(status_code=404, detail="User does not exist.")
    
    oid = validate_object_id(item_id)
    if not items_collection.find_one({"_id": oid, "user_id": user}):
        raise HTTPException(status_code=404, detail="Item not found for specified user.")
    
    data = updated_item.model_dump()
    data["last_updated"] = data["last_updated"].isoformat()
    items_collection.update_one({"_id": oid}, {"$set": data})
    return serialize_item(items_collection.find_one({"_id": oid}))

# /admin/inventory/user/item_id DELETE
@app.delete("/admin/inventory/{user}/{item_id}")
def admin_delete_item(user: str, item_id: str, current_user: dict = Depends(get_current_user)) -> dict:
    require_admin(current_user["role"])
    
    if not users_collection.find_one({"username": user}):
        raise HTTPException(status_code=404, detail="User does not exist.")
    
    oid = validate_object_id(item_id)
    if not items_collection.find_one({"_id": oid, "user_id": user}):
        raise HTTPException(status_code=404, detail="Item not found for specified user.")
    
    items_collection.delete_one({"_id": oid})
    return {"message": "Item deleted successfully"}