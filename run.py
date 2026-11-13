import os
from server.app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "True").lower() in ["true", "1"]
    print(f"🚀 Claims Resolution Agent (PS2) running on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
