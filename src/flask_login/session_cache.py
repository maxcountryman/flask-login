class BaseSessionCache:
    """
    Abstract class for session cache.
    Starting with python 3.8 we can change this to a protocol.
    """

    def get(self, key):
        pass

    def set(self, key, value):
        pass
