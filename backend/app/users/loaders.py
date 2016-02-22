# -*- coding: utf-8 -*-

from app import login_manager

from .models import User


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
