import bjoern
import fanstatic
import pathlib
import importscan
import uvcreha.app
import uvcreha.user
import uvcreha.browser
import uvcreha.emailer
import reiter.view.utils
import reiter.auth.meta
import reiter.auth.filters
import reiter.auth.components
import reiter.auth.utilities


from reha.prototypes.workflows.user import user_workflow
from reiter.application.app import BrowserApplication
from reiter.application.browser import TemplateLoader
from reiter.events.meta import Subscribers
from roughrider.routing.route import NamedRoutes
from uvcreha import plugins, user
from uvcreha.request import Request


### Middlewares

# Session
session = plugins.session_middleware(
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
flash = plugins.flash_messages(
  session_key=session.environ_key
)


# webpush
webpush = plugins.webpush_plugin(
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


# Application
app = BrowserApplication(
    ui=uvcreha.app.ui,
    routes=NamedRoutes(extractor=reiter.view.utils.routables),
    request_factory=Request,
    utilities={
        "webpush": webpush,
        "emailer": emailer,
        "flash": flash,
        "authentication": authentication,
        "twoFA": twoFA
    }
)


# my routes
import uvcreha.browser.login
import uvcreha.browser.twoFA

app.routes.register('/login')(uvcreha.browser.login.LoginForm)
app.routes.register('/2FA')(uvcreha.browser.twoFA.TwoFA)


TEMPLATES = TemplateLoader(".")


@app.routes.register('/')
class Index(uvcreha.browser.Page):

    template = TEMPLATES['index']

    def GET(self):
        return {}



importscan.scan(uvcreha.browser.layout)  # gathering UI elements.

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
