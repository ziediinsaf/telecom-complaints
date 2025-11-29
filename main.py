from website import create_app
from flask import Flask
from flask_talisman import Talisman

app = create_app()

talisman = Talisman(
    app,
    content_security_policy={
        'frame-ancestors': '\'self\''
    },
    force_https=False  
)
if __name__ == '__main__':
    app.run(debug=False)
