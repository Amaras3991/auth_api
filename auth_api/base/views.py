from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import APIException, AuthenticationFailed
from rest_framework.authentication import get_authorization_header
from .auth_utils import decode_access_token, create_access_token
from .serializers import UserSerializer
from .models import User


class RegisterAPIView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)




class UsersApiView(APIView):
    def get(self, request):
        """
        Return a list of all users.
        """
        usernames = [{'name': user.name, "email": user.email, "password": user.password} for user in User.objects.all()]
        return Response(usernames)



class LoginAPIView(APIView):
    def post(self, request):
        user = User.objects.filter( email=request.data[ 'email']).first()
        if not user:
            raise APIException( 'Invalid credentials!' )
        if not user.check_password(request.data[ 'password' ]):
            raise APIException( 'Invalid credentials!' )
        access_token = create_access_token(user.id)
        response = Response()
        response.data = {
            'token': access_token
        }
        return response




class UserAPIView(APIView):
    def get(self, request):
        print(get_authorization_header(request))
        auth = get_authorization_header(request).split()
        print(auth)
        if auth and len(auth) == 2:
            token = auth[1].decode('utf-8')
            id = decode_access_token(token)
            user = User.objects.filter(pk=id).first()
            return Response(UserSerializer(user).data)
        raise AuthenticationFailed('unauthenticated')