from flask import Flask, render_template, request
import requests
import hashlib

app = Flask(__name__)


def request_api_data(query_char):
    url = f"https://api.pwnedpasswords.com/range/{query_char}"
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check the API and try again")
    return res


# Function to check if the password hash exists in breached databases
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return int(count)
    return 0


# Function to check password breaches
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
#     password.encode('utf-8') The SHA-1 hashing algorithm operates on binary (byte) data, not directly on string (text) data.
# Since Python strings are Unicode by default, we must convert (encode) the string into bytes before applying the SHA-1 algorithm.

    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


# Route for the home page
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        password = request.form["password"]
        count = pwned_api_check(password)

        if count:
            result = f"⚠️ Warning: This password has been found {count} times! Change it ASAP."
        else:
            result = "✅ Great! This password has NOT been found in data breaches."

        return render_template("html.html", result=result)
    return render_template("html.html", result="")


if __name__ == "__main__":
    app.run(debug=True)
