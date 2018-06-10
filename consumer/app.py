from sqlalchemy.orm.exc import NoResultFound
from flask import Flask, flash, redirect, render_template, url_for
from flask_dance.consumer import OAuth2ConsumerBlueprint, oauth_authorized, oauth_error
from flask_dance.consumer.backend.sqla import OAuthConsumerMixin, SQLAlchemyBackend
from flask_login import (
    LoginManager, UserMixin, current_user,
    login_required, login_user, logout_user
)
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.secret_key = 'randomstring'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///multi.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
provider = OAuth2ConsumerBlueprint(
    'provider', __name__,
    client_id='bnbnf4LJTH7pztRTupZ34hDOqXUxs0l9q58leced',
    client_secret='ebyiJOqN9OxUvcZnR9OvoT3dB48Zgk9mxBcRc3ksdjAQ7uHQkd9KWM6mD5063ALTGwgyW3fqCb2XR7tqtstnv159r7ijTiIsccSMHVgvdWaYFx7757Cm0k0SLTuRk0E6',
    base_url='http://localhost:8000',
    token_url='http://localhost:8000/o/token/',
    authorization_url='http://localhost:8000/o/authorize/',
)
app.register_blueprint(provider, url_prefix='/login')


login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'


db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(256), unique=True)
    email = db.Column(db.String(120), index=True, unique=True)


class OAuth(OAuthConsumerMixin, db.Model):
    provider_user_id = db.Column(db.String(256), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship(User)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


provider.backend = SQLAlchemyBackend(OAuth, db.session, user=current_user)


@oauth_authorized.connect
def logged_in(blueprint, token):
    if not token:
        flash('Failed to log in with provider.', category='error')
        return False

    resp = blueprint.session.get('/api/me')
    if not resp.ok:
        msg = 'Failed to fetch user info from provider.'
        flash(msg, category='error')
        return False

    info = resp.json()
    user_id = str(info['id'])

    # Find this OAuth token in the database, or create it
    query = OAuth.query.filter_by(
        provider=blueprint.name,
        provider_user_id=user_id,
    )
    try:
        oauth = query.one()
    except NoResultFound:
        oauth = OAuth(
            provider=blueprint.name,
            provider_user_id=user_id,
            token=token,
        )

    if oauth.user:
        login_user(oauth.user)
        flash('Successfully signed in with GitHub.')

    else:
        # Create a new local user account for this user
        user = User(
            # Remember that `email` can be None.
            email=info['email'],
            username=info['username'],
        )
        # Associate the new local user account with the OAuth token
        oauth.user = user
        # Save and commit our database models
        db.session.add_all([user, oauth])
        db.session.commit()
        # Log in the new local user account
        login_user(user)
        flash('Successfully signed in with provider.')

    # Disable Flask-Dance's default behavior for saving the OAuth token
    return False


@app.route('/')
def index():
    return render_template('index.html')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
