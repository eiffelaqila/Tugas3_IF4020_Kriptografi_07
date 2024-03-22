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
      # get request body
      body = await request.json()
      # get plaintext and key from request body
      plaintext, key, iv = body['plaintext'], body['key'], body['iv']

      return JSONResponse(
          content={"ciphertext": ecb_encrypt(plaintext, key, iv)},
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
        content = await file.read()
        ciphertext = content.decode('utf-8')

        # calculate plaintext
        plaintext = ecb_decrypt(ciphertext, key, iv)
        plaintext = plaintext.encode('utf-8')

        return StreamingResponse(
          iter([plaintext]),
          media_type="application/octet-stream",
        )


      # get request body
      body = await request.json()
      # get ciphertext and key from request body
      ciphertext, key, iv = body['ciphertext'], body['key'], body['iv']

      return JSONResponse(
          content={"ciphertext": ecb_decrypt(ciphertext, key, iv)},
          status_code=200
      )

    except Exception as e:
      # return error message
      return JSONResponse(
          content={"error": str(e)},
      )