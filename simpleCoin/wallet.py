"""Это ваш кошелек. Здесь вы можете сделать несколько вещей:
- Создать новый адрес (открытый и закрытый ключ). Вы будете использовать этот адрес 
(открытый ключ) для отправки или получения любых транзакций. У вас может быть столько адресов, 
сколько пожелаете, но если вы потеряете доступ - восстановить его вы уже не сможете.
- Отправлять монеты на другой адрес.
- Извлекать целую цепочку и проверять баланс.
Если вы впервые используете этот скрипт, не забудьте сгенерировать
новый адрес и отредактируйте файл конфигурации miner.
Временная метка захэширована. Когда вы отправляете транзакцию, она будет получена
несколькими узлами. Если какой-либо узел майнит блок, ваша транзакция будет добавлена в
blockchain, а другие узлы будут ожидать. Если какой-либо узел видит, что ваша
транзакция с той же меткой времени, они должны удалить ее из
node_pending_transactions, чтобы избежать ее обработки более 1 раза.
"""

import requests
import time
import base64
import ecdsa


def wallet():
    response = None
    while response not in ["1", "2", "3"]:
        response = input("""What do you want to do?
        1. Generate new wallet
        2. Send coins to another wallet
        3. Check transactions\n""")
    if response == "1":
        # Создаем новый кошелек
        print("""=========================================\n
IMPORTANT: save this credentials or you won't be able to recover your wallet\n
=========================================\n""")
        generate_ECDSA_keys()
    elif response == "2":
        addr_from = input("From: introduce your wallet address (public key)\n")
        private_key = input("Introduce your private key\n")
        addr_to = input("To: introduce destination wallet address\n")
        amount = input("Amount: number stating how much do you want to send\n")
        print("=========================================\n\n")
        print("Is everything correct?\n")
        print("From: {0}\nPrivate Key: {1}\nTo: {2}\nAmount: {3}\n".format(addr_from, private_key, addr_to, amount))
        response = input("y/n\n")
        if response.lower() == "y":
            send_transaction(addr_from, private_key, addr_to, amount)
    else:  
        check_transactions()


def send_transaction(addr_from, private_key, addr_to, amount):
    """Отправляем транзакцию на разные узлы. Как только главная нода начнет майнить блок,
    транзакция добавляется в блокчейн. Несмотря на это, существует небольшая вероятность того,
    что ваша транзакция будет отменена из-за других узлов, имеющих более длинную цепочку. 
    Поэтому убедитесь, что ваша транзакция глубоко в цепочке, прежде чем утверждать, 
    что она одобрена!
    """

    if len(private_key) == 64:
        signature, message = sign_ECDSA_msg(private_key)
        url = 'http://localhost:5000/txion'
        payload = {"from": addr_from,
                   "to": addr_to,
                   "amount": amount,
                   "signature": signature.decode(),
                   "message": message}
        headers = {"Content-Type": "application/json"}

        res = requests.post(url, json=payload, headers=headers)
        print(res.text)
    else:
        print("Wrong address or key length! Verify and try again.")


def check_transactions():
    """Извлекаем весь блокчейн. Тут вы можете проверить свой баланс. Если блокчейн очень 
       длинный, загрузка может занять время.
    """
    res = requests.get('http://localhost:5000/blocks')
    print(res.text)


def generate_ECDSA_keys():
    """Эта функция следит за созданием вашего private и public ключа. Очень важно не потерять
    ни один из них т.к. доступ к кошельку будет потерян. Если кто-то получит доступ к вашему
    кошельку, вы рискуете потерять свои монеты.
    private_key: str
    public_ley: base64
    """
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) # private ключ
    private_key = sk.to_string().hex() # конвертим private ключ в hex
    vk = sk.get_verifying_key() # public ключ
    public_key = vk.to_string().hex()
    # кодируем public ключ, чтобы сделать его короче
    public_key = base64.b64encode(bytes.fromhex(public_key))

    filename = input("Write the name of your new address: ") + ".txt"
    with open(filename, "w") as f:
        f.write("Private key: {0}\nWallet address / Public key: {1}".format(private_key, public_key.decode()))
    print("Your new address and private key are now in the file {0}".format(filename))

def sign_ECDSA_msg(private_key):
    """Подписываем сообщение для отправки
    private ключ должен быть hex
    return
    signature: base64
    message: str
    """
    # получаем timestamp, округляем, переводим в строку и кодируем
    message = str(round(time.time()))
    bmessage = message.encode()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    signature = base64.b64encode(sk.sign(bmessage))
    return signature, message


if __name__ == '__main__':
    print("""       =========================================\n
        SIMPLE COIN v1.0.0 - BLOCKCHAIN SYSTEM\n
       =========================================\n\n
        You can find more help at: https://github.com/cosme12/SimpleCoin\n
        Make sure you are using the latest version or you may end in
        a parallel chain.\n\n\n""")
    wallet()
    input("Press ENTER to exit...")
