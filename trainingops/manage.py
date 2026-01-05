import os

from app import create_app
from app.extensions import db
from app.models import seed_demo_data


def main():
    # default: production se non settato
    env = os.getenv("FLASK_ENV", "production")
    app = create_app(env)
    with app.app_context():
        db.create_all()
        seed_demo_data()
        print("DB inizializzato (create_all + seed).")


if __name__ == "__main__":
    main()
