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
        content = await file.read()
        plaintext = content.decode('utf-8')

        # calculate ciphertext
        ciphertext = counter_encrypt(plaintext, key, counter)
        ciphertext = ciphertext.encode('utf-8')

        return StreamingResponse(
          iter([ciphertext]),
          media_type="application/octet-stream",
        )

      # get request body
      body = await request.json()
      # get plaintext and key from request body
      plaintext, key, counter = body['plaintext'], body['key'], body['counter']

      return JSONResponse(
          content={"ciphertext": counter_encrypt(plaintext, key, counter)},
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
        content = await file.read()
        ciphertext = content.decode('utf-8')

        # calculate plaintext
        plaintext = counter_decrypt(ciphertext, key, counter)
        plaintext = plaintext.encode('utf-8')

        return StreamingResponse(
          iter([plaintext]),
          media_type="application/octet-stream",
        )

      # get request body
      body = await request.json()
      # get ciphertext and key from request body
      ciphertext, key, counter = body['ciphertext'], body['key'], body['counter']

      return JSONResponse(
          content={"ciphertext": counter_decrypt(ciphertext, key, counter)},
          status_code=200
      )

    except Exception as e:
      # return error message
      return JSONResponse(
          content={"error": str(e)},
      )