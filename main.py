import fastapi
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext

# Create the FastAPI app
app = fastapi.FastAPI()

# Define the SQLAlchemy database connection
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a base class for our SQLAlchemy models
Base = declarative_base()


# Define the User model
class User(Base):
    __table_name__: str = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)


# Create the database tables
Base.metadata.create_all(bind=engine)


# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Pydantic models for input validation
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserInDB(UserCreate):
    hashed_password: str


# API endpoint for user registration
@app.post("/users/", response_model=UserInDB)
def create_user(user: UserCreate, db: Session = fastapi.Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise fastapi.HTTPException(status_code=400, detail="Username already registered")
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise fastapi.HTTPException(status_code=400, detail="Email already registered")
    hashed_password = pwd_context.hash(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# API endpoint for user sign-in
@app.post("/login/")
def login(username: str, password: str, db: Session = fastapi.Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        raise fastapi.HTTPException(status_code=fastapi.status.HTTP_401_UNAUTHORIZED,
                                    detail="Incorrect username or password")
    return {"message": "Login successful"}
