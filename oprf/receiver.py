from fastapi.responses import JSONResponse
from fastapi import FastAPI
from jwtoken import decrypt_jwe
from models import PseudonymRequest
import pyoprf
import base64


app = FastAPI(docs_url="/docs")

@app.post("/")
async def post_request(data: PseudonymRequest):
    jwe_data = decrypt_jwe(data.jwe)

    if jwe_data['subject'].startswith("eval:") is False:
        return JSONResponse(content={"error": "invalid subject"}, status_code=400)
    subj = jwe_data['subject'].split(":")[1]

    subj = base64.urlsafe_b64decode(subj)
    bf = base64.urlsafe_b64decode(data.bf)

    pseudonym = base64.urlsafe_b64encode(pyoprf.unblind(bf, subj))


    return JSONResponse(content={"status": "received the pseudonym"}, status_code=200)
