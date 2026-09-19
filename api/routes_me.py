from fastapi import APIRouter

from .models import CurrentUser

router = APIRouter()


# Frontend has a hardcoded user signal; mirror it here so /api/me works without a real auth flow.
_STUB_USER = CurrentUser(
    username="jchen",
    display_name="Jamie Chen",
    email="jchen@contoso.com",
)


@router.get("/me", response_model=CurrentUser)
async def me() -> CurrentUser:
    return _STUB_USER
