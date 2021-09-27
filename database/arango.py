# Arango
from reha.arango.crud import ArangoCRUD
from reiter.arango.connector import Connector
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
