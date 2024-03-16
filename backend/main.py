from fastapi import FastAPI, Request

from backend.router import cbc, cfb, counter, ecb, ofb

app = FastAPI()

app.include_router(cbc.router)
app.include_router(cfb.router)
app.include_router(counter.router)
app.include_router(ecb.router)
app.include_router(ofb.router)

@app.get("/")
def read_root(request: Request):
    return {"message": "Tugas Besar 3 IF4020"}