from pydantic import BaseModel, field_validator
import os


class BigIP(BaseModel):
    hostname: str
    username: str
    password: str
    waf_policy: str
    as3_declaration: str

    @field_validator("password")
    @classmethod
    def resolve_password(cls, v: str) -> str:
        if v == "RESOLVE":
            v = os.environ.get("BIGIP_PASSWORD")
        return v


class F5XC(BaseModel):
    tenant: str
    important: str


class NGINX(BaseModel):
    hostname: str
    important: str


class Targets(BaseModel):
    bigip: BigIP
    f5xc: F5XC
    nginx: NGINX
