from sqlalchemy.orm import Session
from fastapi import FastAPI, Depends, HTTPException, Path, status
import models

from database import engine
from routers import auth, todos

app = FastAPI()

models.Base.metadata.create_all(bind=engine) # will create a sqlite Database

app.include_router(auth.router)
app.include_router(todos.router)
