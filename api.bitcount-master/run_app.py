import os

from api.main import app

# Check mainb
if __name__ == '__main__':
    # Enables debug message, use false on production
    app.debug = True
    # Secretkey
    app.config['SECRET_KEY'] = 'yXn0saPfPYhy8LqjFOTIVPMFKwVhhGGQ'
    # Host environment ip
    host = os.environ.get('EXPOSE_IP', '0.0.0.0')
    # Host environment port
    port = int(os.environ.get('EXPOSE_PORT', 5000))
    # Run app
    app.run(host=host, port=port)
