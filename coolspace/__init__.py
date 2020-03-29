import os

from flask import Flask


def create_app(test_config=None):
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        # a default secret that should be overridden by instance config
        SECRET_KEY="dev",
        # store the database in the instance folder
        DATABASE=os.path.join(app.instance_path, "coolspace.sqlite"),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.update(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.route("/hello")
    def hello():
        return "Hello, World!"

    # register the database commands
    from coolspace import db

    db.init_app(app)

    # apply the blueprints to the app
    from coolspace import auth, post

    app.register_blueprint(auth.bp)
    app.register_blueprint(post.bp)

    # make url_for('index') == url_for('post.index')
    # in another app, you might define a separate main index here with
    # app.route, while giving the post blueprint a url_prefix.
    app.add_url_rule("/", endpoint="index")

    return app
