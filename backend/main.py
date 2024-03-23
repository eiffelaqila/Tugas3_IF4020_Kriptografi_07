from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from backend.router import cbc, cfb, counter, ecb, ofb

app = FastAPI(
    title="API Tugas Besar 3 IF4020",
    description="API Tugas Besar 3 IF4020",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.include_router(cbc.router)
app.include_router(cfb.router)
app.include_router(counter.router)
app.include_router(ecb.router)
app.include_router(ofb.router)

@app.get("/")
def read_root(request: Request):
    return {"message": "Tugas Besar 3 IF4020"}