# wsgi.py
from server import app, socketio 
import os

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1" 
    print(f"Starting SocketIO server via wsgi.py on port {port} with debug={debug_mode}")
    socketio.run(app, host='0.0.0.0', port=port, debug=debug_mode, use_reloader=debug_mode)
