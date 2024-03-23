import binascii
import time
from typing import Optional
from fastapi import APIRouter, Request, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse

from backend.cipher.modes import counter_decrypt, counter_encrypt

router = APIRouter(
    prefix="/counter",
    tags=["counter"],
    responses={404: {"description": "Not found"}},
)

@router.post("/encrypt")
async def encrypt(request: Request, file: Optional[UploadFile] = File(None)):
    try:
      if file:
        #  get key and counter from request form data
        key = await request.form()
        key = key['key']
        counter = await request.form()
        counter = counter['counter']

        # read file content
        plaintext = await file.read()

        # calculate ciphertext
        start_time = time.time()
        ciphertext = counter_encrypt(plaintext, key, counter)
        end_time = time.time()

        return StreamingResponse(
          iter([ciphertext]),
          media_type="application/octet-stream",
          headers={"X-Response-Time": str(end_time - start_time)}
        )

      # get request body
      body = await request.json()
      # get plaintext and key from request body
      plaintext, key, counter = body['inputText'], body['key'], body['counter']

      start_time = time.time()
      ciphertext = counter_encrypt(bytes(plaintext, 'utf-8'), key, counter)
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
        #  get key and counter from request form data
        key = await request.form()
        key = key['key']
        counter = await request.form()
        counter = counter['counter']

        # read file content
        ciphertext = await file.read()

        # calculate plaintext
        start_time = time.time()
        plaintext = counter_decrypt(ciphertext, key, counter)
        end_time = time.time()

        return StreamingResponse(
          iter([plaintext]),
          media_type="application/octet-stream",
          headers={"X-Response-Time": str(end_time - start_time)}
        )

      # get request body
      body = await request.json()
      # get ciphertext and key from request body
      ciphertext, key, counter = body['inputText'], body['key'], body['counter']

      start_time = time.time()
      plaintext = counter_decrypt(bytes.fromhex(ciphertext), key, counter)
      end_time = time.time()

      return JSONResponse(
          content={
              "plaintext": plaintext.decode('utf-8'),
              "time": end_time - start_time
          },
          status_code=200
      )

    except Exception as e:
      # return error message
      return JSONResponse(
          content={"error": str(e)},
      )