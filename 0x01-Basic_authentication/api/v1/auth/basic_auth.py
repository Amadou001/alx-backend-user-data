#!/usr/bin/env python3
"""Basic authentification module
"""

from .auth import Auth


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
