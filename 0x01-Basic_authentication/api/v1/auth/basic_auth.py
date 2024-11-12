#!/usr/bin/env python3
"""Basic authentification module
"""

from .auth import Auth
import base64


class BasicAuth(Auth):
    """Basic authentification class
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ returns the Base64 part of the
        Authorization header for a Basic Authentication
        """
        if authorization_header is None or \
                not isinstance(authorization_header, str):
            return None
        authorization_header_split = authorization_header.split(' ')
        if authorization_header_split[0] != 'Basic':
            return None
        return authorization_header_split[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """returns the decoded value
        of a Base64 string base64_authorization_header
        """
        if base64_authorization_header is None or\
                not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            decoded_str = decoded_bytes.decode('utf-8')
            return decoded_str
        except Exception as e:
            return None
