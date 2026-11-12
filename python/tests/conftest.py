import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from web_login import DbPolicy, FernetCipher, LoginConfig, LoginKit, MemoryLimiter, StaticPolicy, build_models
from web_login.api import AuthDeps, create_admin_router, create_router, install_problem_handlers

PASSWORD = "correct horse battery staple"
KEY = "test-key-test-key-test-key-test-key"


class Outbox:
    def __init__(self):
        self.sent = []

    def enqueue(self, db, to, kind, data):
        self.sent.append((to, kind, data))
        return True

    def last(self, kind):
        return next((d for _, k, d in reversed(self.sent) if k == kind), None)


class Stack:
    """One app wired the way a service would: its own Base and engine, the library's tables, routes and a mail outbox."""

    def __init__(self, *, policy=None, db_policy=False, transport=None, config=None, limiter=None, **kw):
        class Base(DeclarativeBase):
            pass

        self.models = build_models(Base)
        self.engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self.make = sessionmaker(self.engine, expire_on_commit=False)
        self.outbox = Outbox()
        pol = DbPolicy(self.models) if db_policy else (policy or StaticPolicy(registration_open=True))
        self.kit = LoginKit(
            models=self.models, cipher=FernetCipher(KEY), config=config or LoginConfig(web_base_url="https://app.example.test", allow_http_issuer=False),
            policy=pol, mailer=self.outbox, limiter=limiter or MemoryLimiter(), http_transport=transport, **kw,
        )
        self.auth = AuthDeps(self.kit, self.get_session)
        self.app = FastAPI()
        install_problem_handlers(self.app)
        self.app.include_router(create_router(self.kit, self.get_session, self.auth))
        self.app.include_router(create_admin_router(self.kit, self.get_session, self.auth))
        self.client = TestClient(self.app)

    def get_session(self):
        with self.make() as db:
            yield db

    def db(self) -> Session:
        return self.make()

    def h(self, token):
        return {"Authorization": f"Bearer {token}"}

    def register(self, email="first@example.test", password=PASSWORD, name="First"):
        r = self.client.post("/v1/auth/register", json={"email": email, "password": password, "name": name})
        assert r.status_code == 201, r.text
        return r.json()["token"]

    def login(self, email="first@example.test", password=PASSWORD):
        return self.client.post("/v1/auth/login", json={"email": email, "password": password})


@pytest.fixture
def stack():
    return Stack()
