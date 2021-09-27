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
from reiter.application.browser import TemplateLoader
from uvcreha.database import Database


# We register the content
from reha.prototypes.contents import User, File, Document

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


# Arango
from reha.arango.app import Request, Application, API
from reha.arango.crud import ArangoCRUD
from reha.arango.database import Connector
from uvcreha.database import Database

database = Database(
    engine=Connector.from_config(
        user="ck",
        password="ck",
        database="p2",
        url="http://127.0.0.1:8529"
    ),
    binder=ArangoCRUD
)
from uvcreha.contents import registry

class ArangoSource(reiter.auth.meta.Source):

    def __init__(self, db):
        self.db = db

    def find(self, credentials: dict):
        db = self.db.engine.get_database()
        cur = db['users'].find(dict(loginname=credentials['login']))
        if cur.count() == 1:
            user = cur.next()
            if user['password'] == credentials['password']:
                model = registry['user'].model
                return model.factory(**user)

    def fetch(self, loginname):
        db = self.db.engine.get_database()
        cur = db['users'].find(dict(loginname=loginname))
        if cur.count() == 1:
            user = cur.next()
            model = registry['user'].model
            return model.factory(**user)



authentication = reiter.auth.components.Auth(
    user_key="uvcreha.principal",
    session_key=session.environ_key,
    sources=[ArangoSource(database)],
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

# SQL engine
# from reha.sql.app import Request
# from reha.sql.app import Application, API
# from reha.sql.crud import SQLCRUD
# from roughrider.sqlalchemy.component import SQLAlchemyEngine

# database = Database(
#     engine=SQLAlchemyEngine.from_url(
#         name="sql",
#         url="sqlite:///example.db"
#     ),
#     binder=SQLCRUD
# )


browser_app = Application(
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

api_app = API(
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

class AdminRequest(reha.client.app.AdminRequest, Request):
     pass


backend_app = Application(
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


# My views
TEMPLATES = TemplateLoader(".")


#@browser_app.routes.register('/')
#class Index(uvcreha.browser.Page):
#
#    template = TEMPLATES['index']
#
#    def GET(self):
#        return {}



#importscan.scan(reha.sql)  # gathering content types
importscan.scan(reha.arango)  # gathering content types
importscan.scan(reha.client)  # backend
#importscan.scan(uvcreha)  # backend


# import themes
# import reha.siguv_theme
import reha.ukh_theme

importscan.scan(reha.ukh_theme)  # Collecting UI elements


# create tables
# reha.sql.mappers.metadata.create_all(database.engine.engine)

# create collections
from reha.arango import KEY

db = database.engine.get_database()
for name, content in uvcreha.contents.registry:
    if collection := content.metadata.get(KEY):
        print(f'{content.model.__name__} can be fetched through Arango')
        if not db.has_collection(collection):
            db.create_collection(collection)


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


# Run me
bjoern.run(
    host="0.0.0.0",
    port=8082,
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
