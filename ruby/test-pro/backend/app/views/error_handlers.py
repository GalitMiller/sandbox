# -*- coding: utf-8 -*-

from flask import render_template

from app import app, db


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    # If an operation with db was performed, we need to rollback session
    # changes
    db.session.rollback()
    return render_template('500.html'), 500
