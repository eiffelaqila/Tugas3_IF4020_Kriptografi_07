from typing import Optional
from fastapi import APIRouter, Request, UploadFile, File
from fastapi.responses import JSONResponse

from backend.cipher.modes import counter_decrypt, counter_encrypt

router = APIRouter(
    prefix="/counter",
    tags=["counter"],
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
          content={"ciphertext": counter_encrypt(plaintext, key, iv)},
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
          content={"ciphertext": counter_decrypt(ciphertext, key, iv)},
          status_code=200
      )

    except Exception as e:
      # return error message
      return JSONResponse(
          content={"error": str(e)},
      )