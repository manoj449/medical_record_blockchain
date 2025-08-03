from datetime import datetime

class Blockchain:
       def __init__(self):
           self.chain = []
           self.create_genesis_block()

       def create_genesis_block(self):
           genesis_block = {'user_id': 0, 'ipfs_hash': '0', 'prev_hash': '0', 'block_hash': '0', 'timestamp': datetime.utcnow()}
           self.chain.append(genesis_block)

       def get_previous_hash(self):
           if not self.chain:
               return '0'
           return self.chain[-1]['block_hash']

       def add_block(self, user_id, ipfs_hash, prev_hash, block_hash, timestamp):
           block = {
               'user_id': user_id,
               'ipfs_hash': ipfs_hash,
               'prev_hash': prev_hash,
               'block_hash': block_hash,
               'timestamp': timestamp
           }
           self.chain.append(block)
           return block_hash

       def is_chain_valid(self):
           for i in range(1, len(self.chain)):
               current_block = self.chain[i]
               previous_block = self.chain[i-1]
               if current_block['prev_hash'] != previous_block['block_hash']:
                   return False
           return True