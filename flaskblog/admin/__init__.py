# -*- coding: utf-8 -*-
from flask import Blueprint

admin = Blueprint('admin', __name__)

from flaskblog.admin import routes
