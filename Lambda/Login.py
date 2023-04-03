from flask import Flask, jsonify, request

from flask_jwt_extended import JWTManager, jwt_required, create_access_token

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'super-secret'  # change this to your secret key

jwt = JWTManager(app)

# simulate user data in a dictionary

users = {

    "user1": {

        "password": "password1",

        "email": "user1@example.com",

        "name": "User One"

    },

    "user2": {

        "password": "password2",

        "email": "user2@example.com",

        "name": "User Two"

    }

}

# route for user authentication

@app.route('/auth', methods=['POST'])

def auth():

    username = request.json.get('username')

    password = request.json.get('password')

    if not username or not password:

        return jsonify({"message": "username and password are required", "error": True}), 400

    user = users.get(username)

    if not user or user['password'] != password:

        return jsonify({"message": "invalid username or password", "error": True}), 401

    access_token = create_access_token(identity=username)

    return jsonify({"message": "success", "error": False, "data": {"access_token": access_token}})

# protected route for user information

@app.route('/user', methods=['GET'])

@jwt_required

def user():

    username = request.args.get('username')

    user = users.get(username)

    if not user:

        return jsonify({"message": "user not found", "error": True}), 404

    return jsonify({"message": "success", "error": False, "data": user})

if __name__ == '__main__':

    app.run(debug=True)

