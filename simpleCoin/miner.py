import time
import hashlib
import json
import requests
import base64
from flask import Flask, request
from multiprocessing import Process, Pipe
import ecdsa

from miner_config import MINER_ADDRESS, MINER_NODE_URL, PEER_NODES

node = Flask(__name__)


class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        """Возвращает новый объект Block. Каждый блок «привязан» к предыдущему по
         уникальному хэшу
        Аргументы:
            index (int): Номер блока.
            timestamp (int): Timestamp создания блока.
            data (str): Данные для отправки.
            previous_hash(str): Строка с хэшем предыдущего блока.
        Атрибуты:
            index (int): Номер блока.
            timestamp (int): Timestamp создания блока.
            data (str): Данные для отправки.
            previous_hash(str): Строка с хэшем предыдущего блока.
            hash(str): Хэш текущего блока.
        """
        
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        """Создание уникального хэша для блока при помощи sha256."""
        sha = hashlib.sha256()
        sha.update((str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash)).encode('utf-8'))
        return sha.hexdigest()


def create_genesis_block():
    """Для создания нового блока. ему нужен хэш предыдущего. Первыйблок не знает хэш 
    предыдущего, поэтому его нужно создать руками (нулевой индекс и произвольный хэш)"""
    return Block(0, time.time(), {
        "proof-of-work": 9,
        "transactions": None},
        "0")


# Копирование блокчейн-ноды
BLOCKCHAIN = [create_genesis_block()]

""" Тут хранятся транзакции, которые относятся к текущей ноде. Если нода, которой была 
отправлена транзакция добавляет новый блок, он успешно принимается, но есть вероятность того,
что заявка будет отклонена и транзакция вернется """
NODE_PENDING_TRANSACTIONS = []


def proof_of_work(last_proof, blockchain):
    # Создаем переменную, которая будет использоваться для проверки работы
    incrementer = last_proof + 1
    # Получаем время начала
    # Продолжаем увеличивать инкрементатор до тех пор, пока он не будет равен числу, которое 
    # делится на 9, и доказательству работы предыдущего блока 
    start_time = time.time()
    while not (incrementer % 7919 == 0 and incrementer % last_proof == 0):
        incrementer += 1
        # Каждые 60сек проверяем, нашла ли нода подтверждение работы
        if int((time.time()-start_time) % 60) == 0:
            # Если нашла - прекращаем проверку
            new_blockchain = consensus(blockchain)
            if new_blockchain:
                #(False:другая нода первая нашла подтверждение работы)
                return False, new_blockchain
    # Как только число найдено, можно вернуть его как доказательство
    return incrementer, blockchain


def mine(a, blockchain, node_pending_transactions):
    BLOCKCHAIN = blockchain
    NODE_PENDING_TRANSACTIONS = node_pending_transactions
    while True:
        """Майнинг - единственный способ создания новых монет.
         Чтобы предотвратить создание большого количества монет, процесс
         замедляется с помощью алгоритма доказательства работы.
        """
        # Получаем последнее доказательство
        last_block = BLOCKCHAIN[-1]
        last_proof = last_block.data['proof-of-work']
        # Ищем доказательство работы в текущем блоке
        # Программа будет ждать пока новое подтверждение не будет найдено
        proof = proof_of_work(last_proof, BLOCKCHAIN)
        # Если доказательство не нашлось - начинаем майнить опять
        if not proof[0]:
            # Обновляем блокчейн и сохраняемся в файл
            BLOCKCHAIN = proof[1]
            a.send(BLOCKCHAIN)
            continue
        else:
            # Как только мы найдем действительное доказательство работы, мы можем разбить блок,
            # и добавить транзакцию
            # Загружаем все ожидающие транзакции и отправляем их на сервер
            NODE_PENDING_TRANSACTIONS = requests.get(url = MINER_NODE_URL + '/txion', params = {'update':MINER_ADDRESS}).content
            NODE_PENDING_TRANSACTIONS = json.loads(NODE_PENDING_TRANSACTIONS)
            # Затем добавляется вознаграждение за майнинг
            NODE_PENDING_TRANSACTIONS.append({
                "from": "network",
                "to": MINER_ADDRESS,
                "amount": 1})
            # Теперь мы можем собрать данные, необходимые для создания нового блока
            new_block_data = {
                "proof-of-work": proof[0],
                "transactions": list(NODE_PENDING_TRANSACTIONS)
            }
            new_block_index = last_block.index + 1
            new_block_timestamp = time.time()
            last_block_hash = last_block.hash
            # Список пустых транзакций
            NODE_PENDING_TRANSACTIONS = []
            # Теперь создаем новый блок
            mined_block = Block(new_block_index, new_block_timestamp, new_block_data, last_block_hash)
            BLOCKCHAIN.append(mined_block)
           # Сообщаем клиентам, что нода готова майнить
            print(json.dumps({
              "index": new_block_index,
              "timestamp": str(new_block_timestamp),
              "data": new_block_data,
              "hash": last_block_hash
            }) + "\n")
            a.send(BLOCKCHAIN)
            requests.get(url = MINER_NODE_URL + '/blocks', params = {'update':MINER_ADDRESS})

def find_new_chains():
    # Получаем данные о других нодах
    other_chains = []
    for node_url in PEER_NODES:
        # Получаем их цепочки GET-запросом
        block = requests.get(url = node_url + "/blocks").content
        # Конвертим объект JSON в словарь Python
        block = json.loads(block)
        # Проверяем, чтобы другая нода была корректной
        validated = validate_blockchain(block)
        if validated:
             # Добавляем ее в наш список
            other_chains.append(block)
    return other_chains


def consensus(blockchain):
    # Получаем блоки из других нод
    other_chains = find_new_chains()
    # Если наша цепочка не самая длинная, то мы сохраняем самую длинную цепочку
    BLOCKCHAIN = blockchain
    longest_chain = BLOCKCHAIN
    for chain in other_chains:
        if len(longest_chain) < len(chain):
            longest_chain = chain
    # Если самая длинная цепочка не наша, делаем ее самой длинной
    if longest_chain == BLOCKCHAIN:
         # Продолжаем искать подтверждение
        return False
    else:
        # Сдаемся, обновляем цепочку и ищем снова
        BLOCKCHAIN = longest_chain
        return BLOCKCHAIN


def validate_blockchain(block):
   """Проверяем отправленную цепочку. Если хэши неверны, возвращаем false
    block(str): json
    """
    return True


@node.route('/blocks', methods=['GET'])
def get_blocks():
    # Загружаем текущий блокчейн.
    if request.args.get("update") == MINER_ADDRESS:
        global BLOCKCHAIN
        BLOCKCHAIN = b.recv()
    chain_to_send = BLOCKCHAIN
    # Конвертим наши блоки в словари и можем отправить им json объект
    chain_to_send_json = []
    for block in chain_to_send:
        block = {
            "index": str(block.index),
            "timestamp": str(block.timestamp),
            "data": str(block.data),
            "hash": block.hash
        }
        chain_to_send_json.append(block)

    # Отправляем нашу цепочку тому, кто попросил
    chain_to_send = json.dumps(chain_to_send_json)
    return chain_to_send


@node.route('/txion', methods=['GET', 'POST'])
def transaction():
    """Каждая отправленная транзакция в эту ноду проверяется и отправляется.
    Потом она ждет добавления в блокчейн. Транзакции не создают новые монеты, а только 
    перемещают их.
    """
    if request.method == 'POST':
        # При каждом новом POST-запросе мы извлекаем данные транзакции
        new_txion = request.get_json()
        # Добавляем транзакцию в список
        if validate_signature(new_txion['from'], new_txion['signature'], new_txion['message']):
            NODE_PENDING_TRANSACTIONS.append(new_txion)
            # Транзакция успешно отправлена - сообщаем это в консоль
            print("New transaction")
            print("FROM: {0}".format(new_txion['from']))
            print("TO: {0}".format(new_txion['to']))
            print("AMOUNT: {0}\n".format(new_txion['amount']))
            return "Transaction submission successful\n"
        else:
            return "Transaction submission failed. Wrong signature\n"
    # Отправляем ожидающие транзакции майнеру
    elif request.method == 'GET' and request.args.get("update") == MINER_ADDRESS:
        pending = json.dumps(NODE_PENDING_TRANSACTIONS)
        # Очищаем список транзакций
        NODE_PENDING_TRANSACTIONS[:] = []
        return pending


def validate_signature(public_key, signature, message):
    """Проверяем правильность подписи. Это используется для доказательства того, что это вы
    (а не кто-то еще), пытающийся совершить транзакцию за вас. Вызывается, когда пользователь 
    пытается отправить новую транзакцию.
    """
    public_key = (base64.b64decode(public_key)).hex()
    signature = base64.b64decode(signature)
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
    try:
        return vk.verify(signature, message.encode())
    except:
        return False


def welcome_msg():
    print("""       =========================================\n
        SIMPLE COIN v1.0.0 - BLOCKCHAIN SYSTEM\n
       =========================================\n\n
        You can find more help at: https://github.com/cosme12/SimpleCoin\n
        Make sure you are using the latest version or you may end in
        a parallel chain.\n\n\n""")


if __name__ == '__main__':
    welcome_msg()
    # Запускаем майнинг
    a, b = Pipe()
    p1 = Process(target=mine, args=(a, BLOCKCHAIN, NODE_PENDING_TRANSACTIONS))
    p1.start()
    # Запускаем сервер для приема транзакций
    p2 = Process(target=node.run(), args=b)
    p2.start()
