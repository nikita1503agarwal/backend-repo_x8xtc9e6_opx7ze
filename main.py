import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

# Database helpers
from database import db as _db

# Optional: Cloudinary
import cloudinary
import cloudinary.uploader

SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

# Cloudinary config (optional)
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True,
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

app = FastAPI(title="Swish API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ DB Guard ------------------

def get_db():
    if _db is None:
        raise HTTPException(status_code=503, detail="Database not configured. Set DATABASE_URL and DATABASE_NAME.")
    return _db


def coll(name: str):
    return get_db()[name]

# ------------------ Utilities ------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: Optional[str] = None


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = Field("STUDENT", pattern="^(STUDENT|FACULTY|ADMIN)$")


class UserPublic(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str
    avatar: Optional[str] = None
    bio: Optional[str] = None
    department: Optional[str] = None
    year: Optional[str] = None
    followers: int = 0
    following: int = 0


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    u = coll("user").find_one({"_id": ObjectId(user_id)})
    if not u:
        raise credentials_exception
    return u


def require_roles(*roles):
    def checker(user=Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker


# ------------------ Auth Routes ------------------

@app.post("/api/auth/signup", response_model=UserPublic)
def signup(payload: UserCreate):
    # basic campus email check
    if not payload.email.endswith((".edu", ".ac.in", ".edu.in")):
        raise HTTPException(status_code=400, detail="Campus email required")

    if coll("user").find_one({"email": payload.email}):
        raise HTTPException(status_code=409, detail="Email already registered")

    user_doc = {
        "name": payload.name,
        "email": str(payload.email).lower(),
        "password": get_password_hash(payload.password),
        "role": payload.role,
        "avatar": None,
        "bio": "",
        "department": None,
        "year": None,
        "followers": [],
        "following": [],
        "is_blocked": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "is_verified": True  # simplified verification for demo
    }
    res = coll("user").insert_one(user_doc)
    uid = str(res.inserted_id)

    return UserPublic(
        id=uid,
        name=user_doc["name"],
        email=user_doc["email"],
        role=user_doc["role"],
        avatar=user_doc["avatar"],
        bio=user_doc["bio"],
        department=user_doc["department"],
        year=user_doc["year"],
        followers=0,
        following=0,
    )


@app.post("/api/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = coll("user").find_one({"email": form_data.username.lower()})
    if not user or not verify_password(form_data.password, user.get("password", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("is_blocked"):
        raise HTTPException(status_code=403, detail="User is blocked")

    token = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=token)


@app.post("/api/auth/verify")
def verify_placeholder():
    return {"status": "ok"}


# ------------------ Users ------------------

class UserUpdate(BaseModel):
    name: Optional[str] = None
    avatar: Optional[str] = None
    bio: Optional[str] = None
    department: Optional[str] = None
    year: Optional[str] = None


@app.get("/api/users/{id}", response_model=UserPublic)
def get_user(id: str, current=Depends(get_current_user)):
    u = coll("user").find_one({"_id": ObjectId(id)})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return UserPublic(
        id=str(u["_id"]),
        name=u.get("name"),
        email=u.get("email"),
        role=u.get("role"),
        avatar=u.get("avatar"),
        bio=u.get("bio"),
        department=u.get("department"),
        year=u.get("year"),
        followers=len(u.get("followers", [])),
        following=len(u.get("following", [])),
    )


@app.patch("/api/users/{id}")
def update_user(id: str, payload: UserUpdate, user=Depends(get_current_user)):
    if str(user["_id"]) != id and user.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="Cannot edit other profiles")
    update = {k: v for k, v in payload.model_dump(exclude_none=True).items()}
    update["updated_at"] = datetime.now(timezone.utc)
    coll("user").update_one({"_id": ObjectId(id)}, {"$set": update})
    return {"status": "updated"}


@app.post("/api/users/{id}/follow")
def follow_user(id: str, user=Depends(get_current_user)):
    if str(user["_id"]) == id:
        raise HTTPException(status_code=400, detail="Cannot follow yourself")
    coll("user").update_one({"_id": ObjectId(id)}, {"$addToSet": {"followers": user["_id"]}})
    coll("user").update_one({"_id": user["_id"]}, {"$addToSet": {"following": ObjectId(id)}})
    # notification
    coll("notification").insert_one({
        "to": ObjectId(id),
        "type": "follow",
        "from": user["_id"],
        "created_at": datetime.now(timezone.utc),
        "read": False,
    })
    return {"status": "followed"}


@app.post("/api/users/{id}/unfollow")
def unfollow_user(id: str, user=Depends(get_current_user)):
    coll("user").update_one({"_id": ObjectId(id)}, {"$pull": {"followers": user["_id"]}})
    coll("user").update_one({"_id": user["_id"]}, {"$pull": {"following": ObjectId(id)}})
    return {"status": "unfollowed"}


# ------------------ Posts ------------------

class CommentIn(BaseModel):
    text: str


class PostCreate(BaseModel):
    caption: Optional[str] = None
    hashtags: List[str] = []
    location: Optional[str] = None
    privacy: str = Field("public", pattern="^(public|followers)$")
    image_url: Optional[str] = None


@app.post("/api/posts")
async def create_post(
    caption: Optional[str] = Form(None),
    hashtags: Optional[str] = Form(None),  # comma separated
    location: Optional[str] = Form(None),
    privacy: str = Form("public"),
    image: Optional[UploadFile] = File(None),
    user=Depends(get_current_user),
):
    image_url = None
    if image is not None:
        try:
            upload = cloudinary.uploader.upload(image.file, folder="swish/posts")
            image_url = upload.get("secure_url")
        except Exception:
            image_url = None

    post_doc = {
        "author": user["_id"],
        "caption": caption,
        "hashtags": [h.strip() for h in (hashtags or "").split(",") if h.strip()],
        "location": location,
        "privacy": privacy,
        "image_url": image_url,
        "likes": [],
        "comments": [],
        "views": 0,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = coll("post").insert_one(post_doc)
    return {"id": str(res.inserted_id)}


@app.get("/api/posts")
def list_posts(q: Optional[str] = None, mode: Optional[str] = None, current=Depends(get_current_user)):
    query = {}
    if mode == "following":
        query["author"] = {"$in": current.get("following", [])}
    if q:
        query["$or"] = [
            {"caption": {"$regex": q, "$options": "i"}},
            {"hashtags": {"$in": [q]}}
        ]
    posts = coll("post").find(query).sort("created_at", -1).limit(50)
    out = []
    for p in posts:
        out.append({
            "id": str(p["_id"]),
            "author": str(p["author"]),
            "caption": p.get("caption"),
            "hashtags": p.get("hashtags", []),
            "location": p.get("location"),
            "privacy": p.get("privacy"),
            "image_url": p.get("image_url"),
            "likes": len(p.get("likes", [])),
            "comments": len(p.get("comments", [])),
            "views": p.get("views", 0),
            "created_at": p.get("created_at"),
        })
    return out


@app.get("/api/posts/{id}")
def get_post(id: str, user=Depends(get_current_user)):
    p = coll("post").find_one({"_id": ObjectId(id)})
    if not p:
        raise HTTPException(status_code=404, detail="Not found")
    return {
        "id": str(p["_id"]),
        "author": str(p["author"]),
        "caption": p.get("caption"),
        "hashtags": p.get("hashtags", []),
        "location": p.get("location"),
        "privacy": p.get("privacy"),
        "image_url": p.get("image_url"),
        "likes": [str(x) for x in p.get("likes", [])],
        "comments": p.get("comments", []),
        "views": p.get("views", 0),
        "created_at": p.get("created_at"),
    }


@app.post("/api/posts/{id}/like")
def like_post(id: str, user=Depends(get_current_user)):
    coll("post").update_one({"_id": ObjectId(id)}, {"$addToSet": {"likes": user["_id"]}})
    # notify
    p = coll("post").find_one({"_id": ObjectId(id)})
    if p and p.get("author") != user["_id"]:
        coll("notification").insert_one({
            "to": p["author"],
            "type": "like",
            "from": user["_id"],
            "post": p["_id"],
            "created_at": datetime.now(timezone.utc),
            "read": False,
        })
    return {"status": "liked"}


@app.post("/api/posts/{id}/comment")
def comment_post(id: str, payload: CommentIn, user=Depends(get_current_user)):
    comment = {"_id": ObjectId(), "text": payload.text, "author": user["_id"], "created_at": datetime.now(timezone.utc)}
    coll("post").update_one({"_id": ObjectId(id)}, {"$push": {"comments": comment}})
    # notify
    p = coll("post").find_one({"_id": ObjectId(id)})
    if p and p.get("author") != user["_id"]:
        coll("notification").insert_one({
            "to": p["author"],
            "type": "comment",
            "from": user["_id"],
            "post": p["_id"],
            "created_at": datetime.now(timezone.utc),
            "read": False,
        })
    return {"status": "commented"}


@app.delete("/api/posts/{id}")
def delete_post(id: str, user=Depends(get_current_user)):
    p = coll("post").find_one({"_id": ObjectId(id)})
    if not p:
        raise HTTPException(status_code=404, detail="Not found")
    if p.get("author") != user["_id"] and user.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="Not allowed")
    coll("post").delete_one({"_id": ObjectId(id)})
    return {"status": "deleted"}


# ------------------ Explore ------------------

@app.get("/api/explore/trending")
def trending(current=Depends(get_current_user)):
    # naive trending by like count in last 7 days
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    pipeline = [
        {"$match": {"created_at": {"$gte": week_ago}}},
        {"$addFields": {"like_count": {"$size": {"$ifNull": ["$likes", []]}}}},
        {"$sort": {"like_count": -1, "created_at": -1}},
        {"$limit": 30},
    ]
    posts = list(coll("post").aggregate(pipeline))
    return [
        {
            "id": str(p["_id"]),
            "image_url": p.get("image_url"),
            "caption": p.get("caption"),
            "hashtags": p.get("hashtags", []),
            "likes": len(p.get("likes", [])),
        }
        for p in posts
    ]


# ------------------ Notifications ------------------

@app.get("/api/notifications")
def get_notifications(user=Depends(get_current_user)):
    items = coll("notification").find({"to": user["_id"]}).sort("created_at", -1).limit(50)
    out = []
    for n in items:
        out.append({
            "id": str(n["_id"]),
            "type": n.get("type"),
            "from": str(n.get("from")),
            "post": str(n.get("post")) if n.get("post") else None,
            "created_at": n.get("created_at"),
            "read": n.get("read", False)
        })
    return out


@app.patch("/api/notifications/{id}/read")
def mark_notification_read(id: str, user=Depends(get_current_user)):
    coll("notification").update_one({"_id": ObjectId(id), "to": user["_id"]}, {"$set": {"read": True}})
    return {"status": "read"}


# ------------------ Reports & Admin ------------------

class ReportIn(BaseModel):
    target_type: str = Field(..., pattern="^(post|comment)$")
    target_id: str
    reason: str


@app.post("/api/reports")
def report_item(payload: ReportIn, user=Depends(get_current_user)):
    doc = {
        "target_type": payload.target_type,
        "target_id": payload.target_id,
        "reason": payload.reason,
        "status": "open",
        "reporter": user["_id"],
        "created_at": datetime.now(timezone.utc),
    }
    coll("report").insert_one(doc)
    return {"status": "reported"}


@app.get("/api/admin/reports")
def list_reports(admin=Depends(require_roles("ADMIN"))):
    reps = coll("report").find({}).sort("created_at", -1).limit(100)
    return [
        {
            "id": str(r["_id"]),
            "target_type": r.get("target_type"),
            "target_id": r.get("target_id"),
            "reason": r.get("reason"),
            "status": r.get("status"),
            "reporter": str(r.get("reporter")),
            "created_at": r.get("created_at"),
        }
        for r in reps
    ]


@app.patch("/api/admin/reports/{id}")
def resolve_report(id: str, status: str = "resolved", admin=Depends(require_roles("ADMIN"))):
    coll("report").update_one({"_id": ObjectId(id)}, {"$set": {"status": status}})
    return {"status": status}


@app.get("/api/admin/users")
def admin_users(admin=Depends(require_roles("ADMIN"))):
    users = coll("user").find({}).sort("created_at", -1).limit(100)
    return [
        {"id": str(u["_id"]), "name": u.get("name"), "email": u.get("email"), "role": u.get("role"), "blocked": u.get("is_blocked", False)}
        for u in users
    ]


@app.patch("/api/admin/users/{id}/block")
def block_user(id: str, blocked: bool = True, admin=Depends(require_roles("ADMIN"))):
    coll("user").update_one({"_id": ObjectId(id)}, {"$set": {"is_blocked": blocked}})
    return {"status": "blocked" if blocked else "unblocked"}


# ------------------ Health/Test ------------------

@app.get("/")
def root():
    return {"name": "Swish API", "status": "ok"}


@app.get("/test")
def test_database():
    try:
        collections = get_db().list_collection_names()
        return {"backend": "running", "database": "Connected", "collections": collections[:10]}
    except HTTPException as he:
        return {"backend": "running", "database": "Not Connected", "detail": he.detail}
    except Exception as e:
        return {"backend": "running", "database": f"Error: {str(e)[:60]}"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
