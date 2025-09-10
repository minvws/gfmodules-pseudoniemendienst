from fastapi.responses import Response
from fastapi import FastAPI, HTTPException
from models import BlindRequest
from processor import process_blind

app = FastAPI(docs_url="/docs")

@app.post("/")
async def post_blind(req: BlindRequest):
    try:
        jwe = process_blind(req)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return Response(content=jwe, status_code=200, headers={"Content-Type": "application/json+jose"})
