import binascii
import time
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
    # try:
      if file:
        #  get key and iv from request form data
        key = await request.form()
        key = key['key']
        iv = await request.form()
        iv = iv['iv']

        # read file content
        plaintext = await file.read()

        # calculate ciphertext
        start_time = time.time()
        ciphertext = cbc_encrypt(plaintext, key, iv)
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
      ciphertext = cbc_encrypt(bytes(plaintext, 'utf-8'), key, iv)
      end_time = time.time()

      return JSONResponse(
          content={
              "ciphertext": binascii.hexlify(ciphertext).decode('utf-8'),
              "time": end_time - start_time
              },
          status_code=200
      )

    # except Exception as e:
    #   # return error message
    #   return JSONResponse(
    #       content={"error": str(e)},
    #   )

@router.post("/decrypt")
async def decrypt(request: Request, file: Optional[UploadFile] = File(None)):
    # try:
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
        plaintext = cbc_decrypt(ciphertext, key, iv)
        end_time = time.time()

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
      plaintext = cbc_decrypt(bytes.fromhex(ciphertext), key, iv)
      end_time = time.time()

      return JSONResponse(
          content={
              "plaintext": plaintext.decode('utf-8'),
              "time": end_time - start_time
          },
          status_code=200
      )

    # except Exception as e:
    #   # return error message
    #   return JSONResponse(
    #       content={"error": str(e)},
    #   )