# -*- coding: utf-8 -*-
from flask import Blueprint
# URL prefix or template can be configured if separated
admin = Blueprint('admin', __name__)
#blueprint package initialization.
from flaskblog.admin import routes
