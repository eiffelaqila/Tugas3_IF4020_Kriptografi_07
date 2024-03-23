import binascii
import time
from typing import Optional
from fastapi import APIRouter, Request, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse

from backend.cipher.modes import cfb_decrypt, cfb_encrypt

router = APIRouter(
    prefix="/cfb",
    tags=["cfb"],
    responses={404: {"description": "Not found"}},
)

@router.post("/encrypt")
async def encrypt(request: Request, file: Optional[UploadFile] = File(None)):
    try:
      if file:
        #  get key and iv from request form data
        key = await request.form()
        key = key['key']
        iv = await request.form()
        iv = iv['iv']

        # read file content
        content = await file.read()
        plaintext = content.decode('utf-8')

        # calculate ciphertext
        start_time = time.time()
        ciphertext = cfb_encrypt(plaintext, key, iv)
        end_time = time.time()

        return StreamingResponse(
          iter([ciphertext]),
          media_type="application/octet-stream",
          headers={"X-Response-Time": str(end_time - start_time)}
        )

      # get request body
      body = await request.json()
      # get plaintext and key from request body
      plaintext, key, iv = body['plaintext'], body['key'], body['iv']

      start_time = time.time()
      ciphertext = cfb_encrypt(plaintext, key, iv)
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
        iv = await request.form()
        iv = iv['iv']

        # read file content
        ciphertext = await file.read()

        # calculate plaintext
        start_time = time.time()
        plaintext = cfb_decrypt(ciphertext, key, iv)
        end_time = time.time()
        plaintext = plaintext.encode('utf-8')

        return StreamingResponse(
          iter([plaintext]),
          media_type="application/octet-stream",
          headers={"X-Response-Time": str(end_time - start_time)}
        )

      # get request body
      body = await request.json()
      # get ciphertext and key from request body
      ciphertext, key, iv = body['ciphertext'], body['key'], body['iv']

      start_time = time.time()
      plaintext = cfb_decrypt(ciphertext, key, iv)
      end_time = time.time()

      return JSONResponse(
          content={
              "plaintext": plaintext,
              "time": end_time - start_time
          },
          status_code=200
      )

    except Exception as e:
      # return error message
      return JSONResponse(
          content={"error": str(e)},
      )