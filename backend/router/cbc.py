from typing import Annotated, Optional
from fastapi import APIRouter, Form, Request, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from backend.cipher.modes import cbc_decrypt, cbc_encrypt

router = APIRouter(
    prefix="/cbc",
    tags=["cbc"],
    responses={404: {"description": "Not found"}},
)

@router.post("/encrypt")
async def encrypt(request: Request, file: Optional[UploadFile] = File(None)):
    try:
      # get request body
      body = await request.json()
      # get plaintext and key from request body
      plaintext, key, iv = body['plaintext'], body['key'], body['iv']

      return JSONResponse(
          content={"ciphertext": cbc_encrypt(plaintext, key, iv)},
          status_code=200
      )

    except Exception as e:
      # return error message
      return JSONResponse(
          content={"error": str(e)},
      )

@router.post("/decrypt")
async def decrypt(request: Request, file: Optional[UploadFile] = File(None)):
    try:
      # get request body
      body = await request.json()
      # get ciphertext and key from request body
      ciphertext, key, iv = body['ciphertext'], body['key'], body['iv']

      return JSONResponse(
          content={"ciphertext": cbc_decrypt(ciphertext, key, iv)},
          status_code=200
      )

    except Exception as e:
      # return error message
      return JSONResponse(
          content={"error": str(e)},
      )