import binascii
import time
from typing import Optional
from fastapi import APIRouter, Request, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse

from backend.cipher.modes import ecb_decrypt, ecb_encrypt

router = APIRouter(
    prefix="/ecb",
    tags=["ecb"],
    responses={404: {"description": "Not found"}},
)

@router.post("/encrypt")
async def encrypt(request: Request, file: Optional[UploadFile] = File(None)):
    try:
      if file:
        #  get key and iv from request form data
        key = await request.form()
        key = key['key']

        # read file content
        plaintext = await file.read()

        # calculate ciphertext
        start_time = time.time()
        ciphertext = ecb_encrypt(plaintext, key)
        end_time = time.time()

        return StreamingResponse(
          iter([ciphertext]),
          media_type="application/octet-stream",
          headers={"X-Response-Time": str(end_time - start_time)}
        )

      # get request body
      body = await request.json()
      # get plaintext and key from request body
      plaintext, key = body['inputText'], body['key']

      start_time = time.time()
      ciphertext = ecb_encrypt(bytes(plaintext, 'utf-8'), key)
      end_time = time.time()

      return JSONResponse(
          content={
            "ciphertext": binascii.hexlify(ciphertext).decode('utf-8'),
            "time": end_time - start_time
          },
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
      if file:
        #  get key and iv from request form data
        key = await request.form()
        key = key['key']

        # read file content
        ciphertext = await file.read()

        # calculate plaintext
        start_time = time.time()
        plaintext = ecb_decrypt(ciphertext, key)
        end_time = time.time()

        return StreamingResponse(
          iter([plaintext]),
          media_type="application/octet-stream",
          headers={"X-Response-Time": str(end_time - start_time)}
        )

      # get request body
      body = await request.json()
      # get ciphertext and key from request body
      ciphertext, key = body['inputText'], body['key']

      start_time = time.time()
      plaintext = ecb_decrypt(bytes.fromhex(ciphertext), key)
      end_time = time.time()

      return JSONResponse(
          content={
              "plaintext": plaintext.decode('utf-8'),
              "time": end_time - start_time
          },
          status_code=200
      )

    except Exception as e:
      print(e)
      # return error message
      return JSONResponse(
          content={"error": str(e)},
      )