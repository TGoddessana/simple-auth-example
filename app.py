from datetime import timedelta

from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import create_access_token, create_refresh_token

from users import users

app = Flask(__name__)

jwt = JWTManager(app)

app.config["JWT_SECRET_KEY"] = "something_secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(minutes=5)


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return (
        jsonify({"message": "토큰이 만료되었습니다."}),
        401,
    )


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return (
        jsonify({"message": "잘못된 토큰입니다."}),
        401,
    )


@jwt.unauthorized_loader
def missing_token_callback(error):
    return (
        jsonify(
            {
                "message": "토큰 정보가 필요합니다.",
            }
        ),
        401,
    )


@app.route("/login/", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username and password:
        for user in users:
            if user["username"] == username and user["password"] == password:
                return {
                    "access": create_access_token(identity=username),
                    "refresh": create_refresh_token(identity=username),
                }, 200
        else:
            return {"message": "아이디와 비밀번호를 확인하세요."}, 401
    else:
        return {"message": "아이디와 비밀번호가 서버로 전달되지 않았습니다."}, 401


@app.route("/refresh/", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    username = get_jwt_identity()
    return {
        "access": create_access_token(identity=username),
        "refresh": create_refresh_token(identity=username),
    }, 200


@app.route("/protected/", methods=["GET"])
@jwt_required()
def protected():
    username = get_jwt_identity()
    return {"message": f"{username} 의 토큰을 사용해서 로그인된 상태입니다."}, 200


@app.route("/unprotected/", methods=["GET"])
def unprotected():
    return {"message": "JWT 인증 정보 없이도 조회가 가능한 데이터입니다."}, 200


if __name__ == "__main__":
    app.run(debug=True)
