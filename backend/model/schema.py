from pydantic import BaseModel
from fastapi import APIRouter, Request, UploadFile, File

class TextRequest(BaseModel):
    plaintext: str
    key: str
    iv: str