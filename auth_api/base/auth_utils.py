import jwt, datetime
from rest_framework import exceptions

def create_access_token(id):
    return jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        'iat': datetime.datetime.utcnow()
    }, 'access_secret', algorithm='HS256')



def decode_access_token(token):
    try:
        #print("|||||||||||", token)
        payload = jwt.decode(token, 'access_secret', algorithms='HS256')
        #print(payload)
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('unauthenticated')