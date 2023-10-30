from abc import ABC
from abc import abstractmethod


class BaseSessionCache(ABC):
    """
    Abstract class for session cache.
    Starting with python 3.8 we can change this to a protocol.
    """

    @abstractmethod
    def get(self, key):
        pass

    @abstractmethod
    def set(self, key, value):
        pass
