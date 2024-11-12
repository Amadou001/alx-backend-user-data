#!/usr/bin/env python3
""" Module for Authentification
"""
from flask import request


class Auth():
    """template for all authentication system
    """

    def require_auth(self, path: str, excluded_paths: list[str]) -> bool:
        """ Authentification management for routes
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != '/':
            path = path + '/'
        if path in excluded_paths:
            return False
        else:
            return True
    
    def authorization_header(self, request=None) -> str:
        """
            args: request: Flask request object
        """
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']
    
    def current_user(self, request=None) -> type('User'):
        """
            args: request: Flask request object
        """
        return None
