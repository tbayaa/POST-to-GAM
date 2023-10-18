from pydantic import BaseModel, EmailStr


class User(BaseModel):
    email: EmailStr = "user@bayzat.com"
    redirect_to: str | None = None
    dest_ou: str | None = "/!Offboarded Users"


class Command(BaseModel):
    command: list[str] | list[list[str]]


class ResponsePartial(BaseModel):
    command: list[str]
    stdout: str | None


class ResponseOutput(BaseModel):
    output: list[ResponsePartial]
