def authenticate(**credentials):
    """
    If the given credentials are valid, return a User object.
    """
    pass

def login(request, user):
    """
    Persist a user id and a backend in the request. This way a user doesn't
    have to reauthenticate on every request.
    """
    pass

def logout(request):
    """
    Removes the authenticated user's ID from the request and flushes their
    session data.
    """
    pass

def get_user(request):
    pass
