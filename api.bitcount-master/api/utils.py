from flask import make_response

# Utilities

# Returns json response
def json_response(data='', status=200, headers=None):
    headers = headers or {}
    if 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'

    return make_response(data, status, headers)
