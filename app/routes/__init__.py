from flask import Flask
from app.routes.views import views_bp
from app.routes.api import api_bp
from app.routes.targets import targets_bp
from app.routes.diagnostics import diagnostics_bp
from app.routes.acme import acme_bp
from app.routes.events import events_bp

def register_blueprints(app: Flask):
    app.register_blueprint(views_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(targets_bp)
    app.register_blueprint(diagnostics_bp)
    app.register_blueprint(acme_bp)
    app.register_blueprint(events_bp)
