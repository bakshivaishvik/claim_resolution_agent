import os
import sys
from flask import Flask

# Add root directory to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from server.database import init_db
from ledger.audit_ledger import audit_ledger
from server.routes import main_bp, api_bp

def create_app():
    template_dir = os.path.join(BASE_DIR, "templates")
    static_dir = os.path.join(BASE_DIR, "static")

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir
    )

    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "cra-governed-secret-key-2026")

    # Initialize Database and Seed Sample Data
    init_db(seed_sample_data=True)

    # Initialize Ledger if empty
    if not audit_ledger.read_all_entries():
        audit_ledger.reset_to_genesis()

    # Register Blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "True").lower() in ["true", "1"]
    app.run(host="0.0.0.0", port=port, debug=debug)
