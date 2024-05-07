
from fastapi import FastAPI, HTTPException, Form
from starlette.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from app.database import Database
from app.dependencies import get_settings
from app.routers import user_routes
from app.utils.api_description import getDescription
from app.models.user_model import User, UserRole
from app.services.jwt_service import create_access_token


app = FastAPI(
    title="User Management",
    description=getDescription(),
    version="0.0.1",
    contact={
        "name": "API Support",
        "url": "http://www.example.com/support",
        "email": "support@example.com",
    },
    license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
)


# CORS middleware configuration
# This middleware will enable CORS and allow requests from any origin
# It can be configured to allow specific methods, headers, and origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # List of origins that are allowed to access the server, ["*"] allows all
    allow_credentials=True,  # Support credentials (cookies, authorization headers, etc.)
    allow_methods=["*"],  # Allowed HTTP methods
    allow_headers=["*"],  # Allowed HTTP headers
)


@app.on_event("startup")
async def startup_event():
    settings = get_settings()
    Database.initialize(settings.database_url, settings.debug)


@app.exception_handler(Exception)
async def exception_handler(request, exc):
    return JSONResponse(status_code=500, content={"message": "An unexpected error occurred."})


app.include_router(user_routes.router)


@app.post("/register/")
async def register(email: str = Form(...), password: str = Form(...), role: UserRole = Form(...)):
    # Add your logic to register a new user
    # For example, create a new user object, hash the password, save it to the database, etc.
    # Return a response indicating success or failure
    pass


@app.post("/login/")
async def login(username: str = Form(...), password: str = Form(...)):
    # Add your logic to authenticate the user
    # For example, retrieve the user from the database, validate the password, generate and return an access token, etc.
    # Return appropriate responses based on authentication success or failure
    pass




