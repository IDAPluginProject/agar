"""Trie data structure implementation supporting both prefix and suffix matching."""

class TrieNode:
    def __init__(self):
        self.children = {}
        self.values = []

class Trie:
    """A trie data structure for efficient prefix and suffix matching."""
    
    def __init__(self, reverse=False):
        self.root = TrieNode()
        self.reverse = reverse
        self.size = 0
    
    def insert(self, key: str, value=None):
        node = self.root
        key_to_insert = reversed(key) if self.reverse else key
        
        for ch in key_to_insert:
            node = node.children.setdefault(ch, TrieNode())
        
        if value is not None:
            node.values.append(value)
        else:
            node.values.append(key)
        self.size += 1
    
    def insert_many(self, keys_values: dict):
        for key, values in keys_values.items():
            for value in values:
                self.insert(key, value)
    
    def search_prefix(self, prefix: str) -> list:
        if self.reverse:
            raise ValueError("Cannot search by prefix in a suffix trie")
        
        node = self.root
        for ch in prefix:
            if ch not in node.children:
                return []
            node = node.children[ch]
        
        return self._collect_all_values(node)
    
    def search_suffix(self, suffix: str, strip_trailing_digits=True) -> list:
        if not self.reverse:
            raise ValueError("Cannot search by suffix in a prefix trie")
        
        search_str = suffix
        if strip_trailing_digits:
            search_str = suffix.rstrip("_1234567890")
        
        node = self.root
        matches = []
        
        for ch in reversed(search_str):
            if ch not in node.children:
                break
            node = node.children[ch]
            if node.values:
                matches.extend(node.values)
        
        return matches
    
    def _collect_all_values(self, node: TrieNode) -> list:
        values = list(node.values)
        for child in node.children.values():
            values.extend(self._collect_all_values(child))
        return values


class PrefixTrie(Trie):
    """Convenience class for prefix matching."""
    
    def __init__(self):
        super().__init__(reverse=False)
    
    def search(self, prefix: str) -> list:
        return self.search_prefix(prefix)


class SuffixTrie(Trie):
    """Convenience class for suffix matching."""
    
    def __init__(self):
        super().__init__(reverse=True)
    
    def search(self, suffix: str, strip_trailing_digits=True) -> list:
        return self.search_suffix(suffix, strip_trailing_digits)


def find_suffix_matches(keys_values: dict[str, list], search_keys: list[str]) -> dict[str, list]:
    """Find all suffix matches between a dictionary of keys with values and a list of search keys."""
    trie = SuffixTrie()
    trie.insert_many(keys_values)
    
    result = {}
    for key in search_keys:
        matches = trie.search(key)
        if matches:
            result[key] = matches
    
    return result
