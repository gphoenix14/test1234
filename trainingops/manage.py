import os
from app import create_app
from app.extensions import db
from app.models import seed_demo_data

def main():
    app = create_app(os.getenv("FLASK_ENV", "development"))
    with app.app_context():
        db.create_all()
        seed_demo_data()
        print("DB inizializzato (create_all + seed).")

if __name__ == "__main__":
    main()
