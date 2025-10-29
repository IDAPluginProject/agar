import ida_netnode
import json

class Config:
    _INTERNAL_ATTRS = {'node', '_INTERNAL_ATTRS', '_data', '_CONFIG_KEY'}
    _CONFIG_KEY = 'agar_config_data'
    
    def __init__(self):
        object.__setattr__(self, 'node', ida_netnode.netnode("$ agar_config", 0, True))
        object.__setattr__(self, '_data', self._load_data())
    
    def _load_data(self):
        """Load all configuration data from the netnode."""
        node = object.__getattribute__(self, 'node')
        config_key = object.__getattribute__(self, '_CONFIG_KEY')
        value_str = node.hashstr(config_key)
        
        if value_str is not None:
            try:
                return json.loads(value_str)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}
    
    def _save_data(self):
        """Save all configuration data to the netnode."""
        node = object.__getattribute__(self, 'node')
        config_key = object.__getattribute__(self, '_CONFIG_KEY')
        data = object.__getattribute__(self, '_data')
        value_str = json.dumps(data)
        node.hashset(config_key, value_str.encode('utf-8'))
    
    def __getattribute__(self, name):
        if name in Config._INTERNAL_ATTRS or name.startswith('_'):
            return object.__getattribute__(self, name)
        
        data = object.__getattribute__(self, '_data')
        return data.get(name, False)
    
    def __setattr__(self, name, value):
        if name in Config._INTERNAL_ATTRS or name.startswith('_'):
            object.__setattr__(self, name, value)
            return
        
        data = object.__getattribute__(self, '_data')
        data[name] = value
        self._save_data()
    
    def clear(self):
        """Clear all configuration data."""
        node = object.__getattribute__(self, 'node')
        node.kill()
        object.__setattr__(self, 'node', ida_netnode.netnode("$ agar_config", 0, True))
        object.__setattr__(self, '_data', {})