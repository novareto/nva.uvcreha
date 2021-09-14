import bjoern
import fanstatic
import pathlib
import importscan
import uvcreha
import uvcreha.user
import uvcreha.browser
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
from reiter.application.app import BrowserApplication
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

    _users = {
        'admin': "admin"
    }

    def find(self, credentials: dict):
        if credentials['login'] in self._users:
            if self._users[credentials['login']] == credentials['password']:
                return User(credentials['login'])

    def fetch(self, loginname):
        if loginname in self._users:
            return User(loginname)


authentication = reiter.auth.components.Auth(
    user_key="test.principal",
    session_key=session.environ_key,
    sources=[Source()],
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
from roughrider.sqlalchemy.component import SQLAlchemyEngine


sql = SQLAlchemyEngine.from_url(
    name="sql",
    url="sqlite:///example.db"
)


# Request
class SQLRequest(uvcreha.request.Request):

    def __init__(self, session, *args, **kwargs):
        self.session = session
        super().__init__(*args, **kwargs)

    def get_database(self):
        return self.session


# Application
class SQLApplication(BrowserApplication):

    def resolve(self, path: str, environ: dict):
        route = self.routes.match_method(path, environ['REQUEST_METHOD'])
        if route is not None:
            with self.utilities['sqlengine'].session() as session:
                request = SQLRequest(session, self, environ, route)
                return route.endpoint(request, **route.params)


app = SQLApplication(
    ui=uvcreha.browser.ui,
    routes=uvcreha.browser.routes,
    utilities={
        "webpush": webpush,
        "emailer": emailer,
        "flash": flash,
        "authentication": authentication,
        "twoFA": twoFA,
        "sqlengine": sql,
        "contents": reha.sql.contents,
    }
)


# My views
TEMPLATES = TemplateLoader(".")


@app.routes.register('/')
class Index(uvcreha.browser.Page):

    template = TEMPLATES['index']

    def GET(self):
        return {}


importscan.scan(reha.sql)  # gathering content types
importscan.scan(uvcreha.browser)  # gathering UI elements.


# create tables
reha.sql.mappers.metadata.create_all(sql.engine)


# Run me
bjoern.run(
    host="0.0.0.0",
    port=8080,
    reuse_port=True,
    wsgi_app=fanstatic.Fanstatic(
        session(
            authentication(
                app
            )
        ),
        compile=True,
        recompute_hashes=True,
        bottom=True,
        publisher_signature="static"
    )
)
