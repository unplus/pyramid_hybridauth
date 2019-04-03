from abc import ABCMeta, abstractmethod


class Service(metaclass=ABCMeta):
    @abstractmethod
    def get_authorization_url(self, request, config, callback_url):
        pass

    @abstractmethod
    def get_user(self, request, config, callback_url):
        pass


class User:
    def __init__(self, uid, display_name, data):
        self._uid = uid
        self._display_name = display_name
        self._data = data

    def __str__(self):
        return (
            f"uid:{self._uid}, "
            f"display_name:{self._display_name}, "
            f"data:{self._data}"
        )

    @property
    def uid(self):
        return self._uid

    @property
    def display_name(self):
        return self._display_name

    @property
    def data(self):
        return self._data
