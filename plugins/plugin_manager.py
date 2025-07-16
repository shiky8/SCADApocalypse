import logging
import os
import importlib

logger = logging.getLogger('scada_brute.plugin_manager')

class PluginManager:
    def __init__(self, base_path='plugins'):
        self.base_path = base_path
        self.scanners = {}
        self.exploits = {}
        self.fuzzers = {}

    def load_plugins(self):
        self.scanners = self._load_plugins_from_dir('scanners')
        self.exploits = self._load_plugins_from_dir('exploits')
        self.fuzzers = self._load_plugins_from_dir('fuzzers')

    def _load_plugins_from_dir(self, subdir):
        plugins = {}
        path = os.path.join(self.base_path, subdir)
        if not os.path.isdir(path):
            logger.warning(f"Plugin directory {path} does not exist")
            return plugins

        for filename in os.listdir(path):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]
                full_module_name = f"plugins.{subdir}.{module_name}"
                try:
                    module = importlib.import_module(full_module_name)
                    plugins[module_name] = module
                    logger.info(f"Loaded plugin: {full_module_name}")
                except Exception as e:
                    logger.error(f"Failed to load plugin {full_module_name}: {e}")
        return plugins

    def run_scanner(self, name, target, **kwargs):
        if name in self.scanners:
            try:
                return self.scanners[name].scan(target, **kwargs)
            except Exception as e:
                logger.error(f"Error running scanner {name}: {e}")
        else:
            logger.error(f"Scanner plugin {name} not found")
        return None

    def run_exploit(self, name, target, **kwargs):
        if name in self.exploits:
            try:
                return self.exploits[name].exploit(target, **kwargs)
            except Exception as e:
                logger.error(f"Error running exploit {name}: {e}")
        else:
            logger.error(f"Exploit plugin {name} not found")
        return None

    def run_fuzzer(self, name, target, **kwargs):
        if name in self.fuzzers:
            try:
                return self.fuzzers[name].fuzz(target, **kwargs)
            except Exception as e:
                logger.error(f"Error running fuzzer {name}: {e}")
        else:
            logger.error(f"Fuzzer plugin {name} not found")
        return None