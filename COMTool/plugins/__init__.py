from . import dbg
from . import protocol
from .import terminal
from . import graph
from . import bootloader
# from . import myplugin

pluginClasses = [dbg.Plugin, protocol.Plugin, terminal.Plugin, graph.Plugin, bootloader.Plugin]
# pluginClasses.append(myplugin.Plugin)

builtinPlugins = {}
for c in pluginClasses:
    builtinPlugins[c.id] = c
