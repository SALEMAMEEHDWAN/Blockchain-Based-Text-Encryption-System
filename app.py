from flask import Flask, render_template, request, jsonify
import hashlib
import json
import time
import random
import string
from threading import Thread

app = Flask(__name__)

# تعريف فئة البلوكشين
class Blockchain:
    def __init__(self, node_id):
        self.chain = []
        self.node_id = node_id
        self.nodes = set()
        # إنشاء كتلة جينيسيس
        self.create_block(proof=1, previous_hash='0', data="Genesis Block")
    
    def create_block(self, proof, previous_hash, data):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'proof': proof,
            'previous_hash': previous_hash,
            'data': data,
            'node': self.node_id
        }
        self.chain.append(block)
        return block
    
    def get_previous_block(self):
        return self.chain[-1]
    
    def proof_of_work(self, previous_proof, data):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(
                str(new_proof**2 - previous_proof**2 + hash(data)).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof
    
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    def register_node(self, node_id):
        self.nodes.add(node_id)
    
    def encrypt_text(self, text):
        chunks = []
        # تقسيم النص إلى أجزاء
        chunk_size = max(1, len(text) // 3)
        for i in range(0, len(text), chunk_size):
            chunks.append(text[i:i+chunk_size])
        
        encrypted_chunks = []
        for chunk in chunks:
            # الحصول على الكتلة السابقة وإنشاء كتلة جديدة لكل جزء
            previous_block = self.get_previous_block()
            previous_proof = previous_block['proof']
            previous_hash = self.hash(previous_block)
            proof = self.proof_of_work(previous_proof, chunk)
            
            # إنشاء مفتاح تشفير باستخدام قيمة الإثبات
            encryption_key = hashlib.sha256(str(proof).encode()).hexdigest()[:16]
            
            # تشفير النص
            encrypted_chunk = self._simple_encrypt(chunk, encryption_key)
            encrypted_chunks.append({
                'original': chunk,
                'encrypted': encrypted_chunk,
                'key': encryption_key,
                'previous_hash': previous_hash  # إضافة قيمة previous_hash هنا
            })
            
            # إنشاء كتلة جديدة بالنص المشفر
            self.create_block(proof, previous_hash, {
                'original_text': chunk,
                'encrypted_text': encrypted_chunk,
                'encryption_key': encryption_key
            })
        
        return {
            'chunks': encrypted_chunks,
            'blockchain_length': len(self.chain)
        }
    
    def _simple_encrypt(self, text, key):
        # تشفير بسيط باستخدام XOR
        encrypted = []
        for i in range(len(text)):
            key_char = key[i % len(key)]
            encrypted_char = chr(ord(text[i]) ^ ord(key_char))
            encrypted.append(encrypted_char)
        return ''.join(encrypted)
    
    def _simple_decrypt(self, encrypted, key):
        # فك التشفير (نفس عملية التشفير بالضبط لأننا نستخدم XOR)
        return self._simple_encrypt(encrypted, key)
    
    def decrypt_text(self, encrypted_chunks):
        decrypted_text = ""
        for chunk in encrypted_chunks:
            decrypted_chunk = self._simple_decrypt(chunk['encrypted'], chunk['key'])
            decrypted_text += decrypted_chunk
        return decrypted_text
    
    def crack_encryption(self, encrypted_chunks):
        # محاكاة عملية كسر التشفير
        cracked_chunks = []
        for chunk in encrypted_chunks:
            # في سيناريو حقيقي، هذا سيكون أكثر تعقيدًا بكثير
            # هنا نقوم بمحاكاة عملية الكسر عن طريق الوصول المباشر للمفتاح
            key = chunk['key']
            decrypted = self._simple_decrypt(chunk['encrypted'], key)
            cracked_chunks.append({
                'encrypted': chunk['encrypted'],
                'cracked': decrypted,
                'key_found': key
            })
        return cracked_chunks

# إنشاء عدة نقاط (nodes) في الشبكة
nodes = {}
for i in range(3):
    node_id = f"node_{i+1}"
    nodes[node_id] = Blockchain(node_id)

# تسجيل العقد مع بعضها البعض
for node_id, blockchain in nodes.items():
    for other_id in nodes:
        if node_id != other_id:
            blockchain.register_node(other_id)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    text = data['text']
    
    # اختيار عقدة عشوائية للتشفير
    node_ids = list(nodes.keys())
    selected_node = random.choice(node_ids)
    
    # تشفير النص
    result = nodes[selected_node].encrypt_text(text)
    result['node_id'] = selected_node
    
    return jsonify(result)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    encrypted_chunks = data['chunks']
    node_id = data['node_id']
    
    # فك التشفير
    decrypted_text = nodes[node_id].decrypt_text(encrypted_chunks)
    
    return jsonify({'decrypted_text': decrypted_text})

@app.route('/crack', methods=['POST'])
def crack():
    data = request.get_json()
    encrypted_chunks = data['chunks']
    
    # محاكاة كسر التشفير
    cracked_chunks = nodes[list(nodes.keys())[0]].crack_encryption(encrypted_chunks)
    
    return jsonify({'cracked_chunks': cracked_chunks})

# حذف الطريقة التالية من app.py
@app.route('/blockchain_status', methods=['GET'])
def blockchain_status():
    status = {}
    for node_id, blockchain in nodes.items():
        status[node_id] = {
            'chain_length': len(blockchain.chain),
            'last_block': blockchain.get_previous_block() if blockchain.chain else None
        }
    return jsonify(status)

if __name__ == '__main__':
    app.run(debug=True)