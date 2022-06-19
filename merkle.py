# Ben Levi, 318811304, Roei Gehassi, 208853754

import hashlib
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


# -----------------------------------------------------------
# Class MerkleTree
#   Hold list of nodes and another list of leaves.
# -----------------------------------------------------------
class MerkleTree:
    def __init__(self):
        self.nodes = []
        self.leaves_lst = []

    # Insert new leave.
    def insert_leave(self, value):
        # Clear nodes list because now the root will change.
        self.nodes = []
        # Create new node - the index is the amount of leaves.
        node = MerkleNode(hashlib.sha256(value.encode("utf-8")).hexdigest(),
                          len(self.leaves_lst), len(self.leaves_lst),
                          None, None)
        self.leaves_lst.append(node)

    # Calculate and return the root.
    def root(self):
        # Empty tree.
        if len(self.leaves_lst) == 0:
            return ""
        self.nodes = self.leaves_lst.copy()
        # The last node after the creation is the root.
        while len(self.nodes) != 1:
            evens = []
            odds = []
            for i in range(0, len(self.nodes), 2):
                evens.append(self.nodes[i])
            for i in range(1, len(self.nodes), 2):
                odds.append(self.nodes[i])
            self.nodes.clear()
            # Create father for each brothers pair.
            for node_i, node_j in zip(evens, odds):
                parent_node = MerkleNode(hashlib.
                                         sha256((node_i.get_hash_value() + node_j.get_hash_value()).
                                                encode("utf-8")).hexdigest(), node_i.get_start(),
                                         node_j.get_end(), node_i, node_j)
                self.nodes.append(parent_node)
            # If remain single node -> add him.
            if len(evens) > len(odds):
                self.nodes.append(evens[-1])
            elif len(odds) > len(evens):
                self.nodes.append(odds[-1])
        # The last node after the creation is the root.
        return self.nodes[0].get_hash_value()

    # Create proof for specific leave.
    def create_proof(self, index):
        # Create the root if not exist.
        if len(self.nodes) == 0:
            self.root()
        root = self.nodes[0]
        proof_lst = []
        current_node = root
        # Advance to the node and add the second node on each level.
        while not (current_node.get_start() == index and current_node.get_end() == index):
            right = current_node.get_right()
            left = current_node.get_left()
            if left.get_start() <= index <= left.get_end():
                current_node = left
                proof_lst.append("1" + right.get_hash_value())
            else:
                current_node = right
                proof_lst.append("0" + left.get_hash_value())
        # Proof start with the root.
        proof = self.nodes[0].get_hash_value()
        # From the last level to the root.
        for element in reversed(proof_lst):
            proof += " "
            proof += element
        return proof

    # Check Merkle Tree Proof for value.
    def check_proof(self, lst):
        # Save hash value of the leave.
        hash_value = hashlib.sha256(lst[0].encode("utf-8")).hexdigest()
        result = hash_value
        root = lst[1]
        lst = lst[2:]

        for element in lst:
            if element[0] == 0:
                result = element[1:] + result
            else:
                result = result + element[1:]
            # Join the values (from right or left) and start hash.
            result = hashlib.sha256(result.encode("utf-8")).hexdigest()

        if root == result:
            return True
        return False


# ----------------------------------------------------------------------------
# Class MerkleNode
#   Hold hash value, right child, left child and range (start,end) of leaves.
# ----------------------------------------------------------------------------
class MerkleNode:
    def __init__(self, hash_value, start, end, left_child, right_child):
        self.hash_value = hash_value
        self.start = start
        self.end = end
        self.right_child = right_child
        self.left_child = left_child

    def get_hash_value(self):
        return self.hash_value

    def get_start(self):
        return self.start

    def get_end(self):
        return self.end

    def get_right(self):
        return self.right_child

    def get_left(self):
        return self.left_child


# Create private and public keys - RSA.
def create_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(pem_private.decode('utf-8'))
    print(pem_public.decode('utf-8'))


# Sign on the root by key.
def sign(string_key, root_value):
    key = serialization.load_pem_private_key(string_key.encode('utf-8'), password=None)
    try:
        sig = key.sign(
            root_value,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(base64.b64encode(sig).decode())
    except:
        pass


# Verify signature is valid.
def verify(key, sig, data):
    verification_key = serialization.load_pem_public_key(key.encode('utf-8'))
    try:
        verification_key.verify(
            sig,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("True")
    except InvalidSignature:
        print("False")
