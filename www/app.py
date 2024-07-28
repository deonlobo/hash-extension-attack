from flask import Flask
from lab import bp
from config import Config  # Import the Config class

app = Flask(__name__)
app.config.from_object(Config)  # Apply the configuration from the Config class
app.register_blueprint(bp)

if __name__ == '__main__':
    app.run(debug=True)