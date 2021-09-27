import bjoern
import fanstatic
import pathlib
import importscan
import uvcreha
import uvcreha.app
import uvcreha.api
import uvcreha.auth.source
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
from reha.prototypes.contents import User, File, Document
from reha.prototypes.workflows.user import user_workflow
from reiter.application.browser import TemplateLoader
from database.arango import database


uvcreha.contents.registry.register('user')(User)
uvcreha.contents.registry.register('file')(File)
uvcreha.contents.registry.register('document')(Document)


# Load essentials
importscan.scan(reha.prototypes)
importscan.scan(uvcreha.browser)
importscan.scan(uvcreha.api)


### Middlewares

# Session
session = uvcreha.plugins.session_middleware(
    cache=pathlib.Path("var/sessions"),
    cookie_name="uvcreha.cookie",
    cookie_secret="secret",
    environ_key="uvcreha.test.session"
)

session_getter = reiter.auth.components.session_from_environ(
    session.environ_key
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


# Auth
authentication = reiter.auth.components.Auth(
    user_key="uvcreha.principal",
    session_getter=session_getter,
    sources=[uvcreha.auth.source.DatabaseSource(database)],
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

browser_app = uvcreha.app.Application(
    ui=uvcreha.browser.ui,
    routes=uvcreha.browser.routes,
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

api_app = uvcreha.app.API(
    routes=uvcreha.api.routes,
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
import reiter.auth.testing

admin_authentication = reiter.auth.components.Auth(
    user_key="backend.principal",
    session_getter=session_getter,
    sources=[reiter.auth.testing.DictSource({"admin": "admin"})],
    filters=(
        reiter.auth.filters.security_bypass([
            "/login"
        ]),
        reiter.auth.filters.secured(path="/login"),
        #reiter.auth.filters.filter_user_state(states=(
        #    user_workflow.states.inactive,
        #    user_workflow.states.closed
        #)),
    )
)


class AdminRequest(reha.client.app.AdminRequest, uvcreha.app.Request):
    pass


backend_app = uvcreha.app.Application(
    ui=uvcreha.browser.ui,
    routes=reha.client.app.routes,
    request_factory=AdminRequest,
    utilities={
        "webpush": webpush,
        "emailer": emailer,
        "flash": flash,
        "authentication": admin_authentication,
        "database": database,
        "contents": uvcreha.contents.registry,
    }
)


importscan.scan(reha.client)  # backend

# import themes
# import reha.siguv_theme
import reha.ukh_theme

importscan.scan(reha.ukh_theme)  # Collecting UI elements


# create collections/tables
# from reha.sql import setup_contents
from reha.arango import setup_contents

setup_contents(database)


# Plugins
import uv.ozg
import uv.ozg.app

importscan.scan(uv.ozg)
uv.ozg.app.load_content_types(pathlib.Path("./content_types"))


# Load content types
from uvcreha.contents import load_content_types

load_content_types(pathlib.Path("./content_types"))


# URL Mapping
from horseman.mapping import Mapping
wsgi_app = Mapping({
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


# Run me
bjoern.run(
    host="0.0.0.0",
    port=8082,
    reuse_port=True,
    wsgi_app=wsgi_app
)
