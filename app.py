import bjoern
import fanstatic
import pathlib
import importscan
import uvcreha
import uvcreha.api
import uvcreha.user
import uvcreha.browser
import uvcreha.contents
import uvcreha.emailer
import uvcreha.plugins
import uvcreha.request
import reiter.auth.meta
import reiter.auth.filters
import reiter.auth.components
import reiter.auth.utilities
import reha.sql

from dataclasses import field
from reha.prototypes.workflows.user import user_workflow
from reiter.application.app import Application, BrowserApplication
from reiter.application.browser import TemplateLoader


### Middlewares

# Session
session = uvcreha.plugins.session_middleware(
    cache=pathlib.Path("var/sessions"),
    cookie_name="uvcreha.cookie",
    cookie_secret="secret",
    environ_key="uvcreha.test.session"
)

# authentication
class User(uvcreha.user.User):

    def __init__(self, login):
        self.id = login
        self.title = f"User <{login}>"


class Source(reiter.auth.meta.Source):

    def __init__(self, users: dict):
        self._users = users

    def find(self, credentials: dict):
        if credentials['login'] in self._users:
            if self._users[credentials['login']] == credentials['password']:
                return User(credentials['login'])

    def fetch(self, loginname):
        if loginname in self._users:
            return User(loginname)


authentication = reiter.auth.components.Auth(
    user_key="uvcreha.principal",
    session_key=session.environ_key,
    sources=[Source({"test": "test"})],
    filters=(
        reiter.auth.filters.security_bypass([
            "/login"
        ]),
        reiter.auth.filters.secured(path="/login"),
        reiter.auth.filters.filter_user_state(states=(
            user_workflow.states.inactive,
            user_workflow.states.closed
        )),
        reiter.auth.filters.TwoFA(path="/2FA")
    )
)


### Utilities

# flash
flash = uvcreha.plugins.flash_messages(
  session_key=session.environ_key
)


# webpush
webpush = uvcreha.plugins.webpush_plugin(
    public_key=pathlib.Path("identities/public_key.pem"),
    private_key=pathlib.Path("identities/private_key.pem"),
    vapid_claims={
        "sub": "mailto:cklinger@novareto.de",
        "aud": "https://updates.push.services.mozilla.com"
    }
)

# Email
emailer = uvcreha.emailer.SecureMailer(
    user=None,
    password=None,
    emitter="uvcreha@novareto.de"
)

# 2FA
twoFA = reiter.auth.utilities.TwoFA(
  session_key=session.environ_key
)


# SQL engine
from reha.sql.crud import SQLCRUD
from uvcreha.database import Database
from roughrider.sqlalchemy.component import SQLAlchemyEngine


database = Database(
    engine=SQLAlchemyEngine.from_url(
        name="sql",
        url="sqlite:///example.db"
    ),
    binder=SQLCRUD
)


# Request
class SQLRequest(uvcreha.request.Request):

    def __init__(self, session, *args, **kwargs):
        self.session = session
        super().__init__(*args, **kwargs)

    def get_database(self):
        return self.session

    def get_crud(self, name):
        ct = self.app.utilities['contents'][name]
        binder = self.app.utilities['database'].binder
        crud = binder(ct.model, self.app, self.session)
        return ct, crud


# Application
class SQLResolver:

    def resolve(self, path: str, environ: dict):
        route = self.routes.match_method(path, environ['REQUEST_METHOD'])
        if route is not None:
            with self.utilities['database'].engine.session() as session:
                request = SQLRequest(session, self, environ, route)
                return route.endpoint(request, **route.params)


class SQLApplication(SQLResolver, BrowserApplication):
    pass


class SQLAPI(SQLResolver, Application):
    pass


browser_app = SQLApplication(
    ui=uvcreha.browser.ui,
    routes=uvcreha.browser.routes,
    request_factory=SQLRequest,
    utilities={
        "webpush": webpush,
        "emailer": emailer,
        "flash": flash,
        "authentication": authentication,
        "twoFA": twoFA,
        "database": database,
        "contents": uvcreha.contents.registry,
    }
)

api_app = SQLAPI(
    routes=uvcreha.api.routes,
    request_factory=SQLRequest,
    utilities={
        "webpush": webpush,
        "emailer": emailer,
        "database": database,
        "contents": uvcreha.contents.registry,
    }
)

# Backend
import reha.client
import reha.client.app

admin_authentication = reiter.auth.components.Auth(
    user_key="backend.principal",
    session_key=session.environ_key,
    sources=[Source({"admin": "admin"})],
    filters=(
        reiter.auth.filters.security_bypass([
            "/login"
        ]),
        reiter.auth.filters.secured(path="/login"),
        reiter.auth.filters.filter_user_state(states=(
            user_workflow.states.inactive,
            user_workflow.states.closed
        )),
    )
)

class SQLAdminRequest(reha.client.app.AdminRequest, SQLRequest):
    pass


backend_app = SQLApplication(
    ui=uvcreha.browser.ui,
    routes=reha.client.app.routes,
    request_factory=SQLAdminRequest,
    utilities={
        "webpush": webpush,
        "emailer": emailer,
        "flash": flash,
        "authentication": admin_authentication,
        "database": database,
        "contents": uvcreha.contents.registry,
    }
)


# My views
TEMPLATES = TemplateLoader(".")


@browser_app.routes.register('/')
class Index(uvcreha.browser.Page):

    template = TEMPLATES['index']

    def GET(self):
        return {}

importscan.scan(reha.prototypes)
importscan.scan(reha.sql)  # gathering content types
importscan.scan(uvcreha.browser)  # gathering routes elements.
importscan.scan(uvcreha.api)  # added API routes.
importscan.scan(reha.client)  # backend


# import themes
# import reha.siguv_theme
import reha.ukh_theme

importscan.scan(reha.ukh_theme)  # Collecting UI elements


# create tables
reha.sql.mappers.metadata.create_all(database.engine.engine)


# Load content types
from uvcreha.contents import load_content_types

load_content_types(pathlib.Path("./content_types"))


# URL Mapping
from horseman.mapping import Mapping


# Run me
bjoern.run(
    host="0.0.0.0",
    port=8080,
    reuse_port=True,
    wsgi_app=Mapping({
        "/": fanstatic.Fanstatic(
            session(
                authentication(
                    browser_app
                )
            ),
            compile=True,
            recompute_hashes=True,
            bottom=True,
            publisher_signature="static"
        ),
        "/backend": fanstatic.Fanstatic(
            session(
                admin_authentication(
                    backend_app
                )
            ),
            compile=True,
            recompute_hashes=True,
            bottom=True,
            publisher_signature="static"
        ),
        "/api": api_app
    })
)
