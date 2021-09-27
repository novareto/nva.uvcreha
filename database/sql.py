# SQL engine
from reha.sql.crud import SQLCRUD
from roughrider.sqlalchemy.component import SQLAlchemyEngine


engine = SQLAlchemyEngine.from_url(
    name="sql",
    url="sqlite:///example.db"
)


database = Database(
    engine=engine,
    binder=SQLCRUD,
    context_manager=engine.session
)
