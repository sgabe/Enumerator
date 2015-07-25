#!/usr/bin/env python
# coding=utf-8

from configobj import ConfigObj
from configobj import ConfigObjError


class Config(object):
    """Build config obj from contents of config.ini.  Sets the
    section titles as member attributes with the values as dicts.
    """
    def __init__(self):
        try:
            self.config = ConfigObj("../config.ini")
            [setattr(self, section, self.config[section])
             for section in self.config.keys()]
        except (ConfigObjError, IOError), e:
            print e # This needs to be handled somehow...
