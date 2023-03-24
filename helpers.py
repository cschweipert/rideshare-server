from datetime import time
from sqlalchemy.orm import class_mapper


def model_to_dict(model):
    """Converts a SQLAlchemy model to a dictionary."""
    columns = class_mapper(model.__class__).columns
    result = {}

    for column in columns:
        value = getattr(model, column.name)
        if isinstance(value, time):
            result[column.name] = value.strftime('%H:%M:%S')
        else:
            result[column.name] = value
    return result
