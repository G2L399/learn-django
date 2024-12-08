from django.core.cache import cache

def add_user_to_redis(key, data, timeout=300):
    """
    Add user data to Redis with a timeout (default: 5 minutes).
    """
    cache.set(key, data, timeout)

def get_user_from_redis(key):
    """
    Retrieve user data from Redis.
    """
    return cache.get(key)

def delete_user_from_redis(key):
    """
    Delete user data from Redis.
    """
    cache.delete(key)
