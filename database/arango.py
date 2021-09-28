# Arango
from reha.arango import Database
from reiter.arango.connector import Connector


database = Database(
    Connector.from_config(
        user="ck",
        password="ck",
        database="p2",
        url="http://127.0.0.1:8529"
    )
)
