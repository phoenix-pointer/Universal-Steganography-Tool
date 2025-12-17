# unisteg/plugins/__init__.py

from ..plugin_base import register_plugin

from .image_lsb import ImageLSBPlugin
from .image_metadata import ImageMetadataPlugin
from .image_appended import ImageAppendedPlugin

from .audio_lsb import AudioLSBPlugin
from .audio_metadata import AudioMetadataPlugin
from .audio_appended import AudioAppendedPlugin

from .text_lsb import TextLSBPlugin
from .text_metadata import TextMetadataPlugin
from .text_appended import TextAppendedPlugin


# Register all plugins at import time
register_plugin(ImageLSBPlugin())
register_plugin(ImageMetadataPlugin())
register_plugin(ImageAppendedPlugin())

register_plugin(AudioLSBPlugin())
register_plugin(AudioMetadataPlugin())
register_plugin(AudioAppendedPlugin())

register_plugin(TextLSBPlugin())
register_plugin(TextMetadataPlugin())
register_plugin(TextAppendedPlugin())
