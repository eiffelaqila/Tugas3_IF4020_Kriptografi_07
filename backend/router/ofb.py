from fastapi import APIRouter, Request, UploadFile, File

from backend.cipher.modes import ofb_decrypt, ofb_encrypt

router = APIRouter(
    prefix="/ofb",
    tags=["ofb"],
    responses={404: {"description": "Not found"}},
)

@router.post("/encrypt")
async def encrypt(request: Request):
    try:
      # get request body
      body = await request.json()
      # get plaintext and key from request body
      plaintext, key, iv = body['plaintext'], body['key'], body['iv']

      return {
          "ciphertext": ofb_encrypt(plaintext, key, iv)
      }

    except Exception as e:
      # return error message
      return {
          "error": str(e)
      }

@router.post("/decrypt")
async def decrypt(request: Request):
    try:
      # get request body
      body = await request.json()
      # get ciphertext and key from request body
      ciphertext, key, iv = body['ciphertext'], body['key'], body['iv']

      return {
        "ciphertext": ofb_decrypt(ciphertext, key, iv)
      }

    except Exception as e:
      # return error message
      return {
          "error": str(e)
      }