import bjoern
import fanstatic
import pathlib
import uvcreha.app
import uvcreha.auth
import uvcreha.emailer

from reha.prototypes.workflows.user import user_workflow
from reiter.application.app import BrowserApplication
from uvcreha import plugins
from uvcreha.auth import filters as auth_filters


### Middlewares

# Session
session = plugins.session_middleware(
    cache=pathlib.Path("var/sessions"),
    cookie_name="uvcreha.cookie",
    cookie_secret="secret",
    environ_key="uvcreha.test.session"
)

# authentication


authentication = uvcreha.auth.Auth(
    user_key="test.principal",
    session_key=session.environ_key,
    sources=None,
    filters=(
        auth_filters.security_bypass("/login"),
        auth_filters.secured(path="/login"),
        auth_filters.filter_user_state(states=(
            user_workflow.states.inactive,
            user_workflow.states.closed
        )),
        auth_filters.TwoFA(path="/2FA")
    )
)


# Static assets
assets = fanstatic.Fanstatic(
    compile=True,
    recompute_hashes=True,
    bottom=True,
    publisher_signature="static"
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
    user=None
    password=None,
    emitter="uvcreha@novareto.de"
)

# 2FA
twoFA = uvcreha.auth.utilities.TwoFA(
  session_key=session.environ_key
)


# Application
uvcreha = BrowserApplication(
    ui=uvcreha.app.ui,
    utilities={
        "webpush": webpush,
        "emailer": emailer,
        "flash": flash,
        "authentication": authentication,
        "twoFA": twoFA
    }
)


uvcreha.route(



# Run me
bjoern.run(
    host="0.0.0.0",
    port="8080",
    reuse_port=True,
    wsgi_app=assets(
        session(
            authentication(
                uvcreha
            )
        )
    )
)
