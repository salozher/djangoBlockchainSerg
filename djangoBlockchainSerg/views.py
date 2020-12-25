# S.Melchakov
# Blockchain (final assignment)
# December 2020
# https://github.com/salozher/djangoBlockchainSerg



from django.http import JsonResponse
import json
from django.http import StreamingHttpResponse
import hashlib
import requests
from datetime import datetime
from urllib.parse import urlparse
from .models import Node, TransactionsBuffer, Block, Picture
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from uuid import uuid4
from django.core import serializers
from django.forms.models import model_to_dict
from threading import Thread

node_identifier = str('node1')
# node_identifier = str(uuid4()).replace('-', '')
print('node_identifier = ' + node_identifier)


def home_view(request):
    context = {

    }
    return render(request, 'home.html', context)


def nodes_list():
    all_nodes_list = {
        'nodes': get_all_nodes_json(),
        'length': Node.objects.all().count(),
    }
    return all_nodes_list


def get_nodes_list(request):
    if request.method == 'GET':
        block = nodes_list()
        response = JsonResponse(block, status=200)
        return response


def chain_list():
    block = {
        'chain': get_complete_blockchain_json(),
        'length': Block.objects.all().count(),
    }
    return block


def get_full_chain(request):
    if request.method == 'GET':
        block = chain_list()
        response = JsonResponse(block, status=200)
        return response


def transactions_buffer():
    block = {
        'transaction': get_transactions_buffer_json(),
        'length': TransactionsBuffer.objects.all().count(),
    }
    return block


def get_transactions_buffer(request):
    if request.method == 'GET':
        block = transactions_buffer()
        response = JsonResponse(block, status=200)
        return response


def resolve(request):
    if request.method == 'GET':
        replaced = resolve_conflicts()

        if replaced:
            block = {
                'message': 'Our chain was replaced',
                'new_chain': get_complete_blockchain_json()
            }
        else:
            block = {
                'message': 'Our chain is authoritative',
                'chain': get_complete_blockchain_json()
            }

        response = JsonResponse(block, status=200)
        return response


@csrf_exempt
def mine(request):
    if request.method == 'GET':
        # We run the proof of work algorithm to get the next proof...
        latest_block = get_last_block()
        proof = proof_of_work(latest_block)

        # We must receive a reward for finding the proof.
        # The sender is "0" to signify that this node has mined a new coin.
        new_transaction2 = TransactionsBuffer()
        new_transaction2.unique_id = 'mining_payment'
        new_transaction2.sender = '0'
        new_transaction2.recipient = str(node_identifier)
        new_transaction2.amount = int(1)
        success = True
        try:
            new_transaction2.save()
        except Exception as e7:
            success = False
            print(str(e7))

        # Forge the new Block by adding it to the chain
        try:
            previous_hash = hash_it(latest_block)
        except Exception as e1:
            print(str(e1))
        block = new_block(proof, previous_hash)

        # message = json.dumps(block)

        response = JsonResponse(block, status=200)
        return response


def push_resolve_task(node):
    try:
        response = requests.get(f'{node}/nodes/resolve/')
        print(response)
    except Exception as e4:
        print(str(e4))


def send_digest_transaction(transaction_digest):
    nodes = Node.objects.all()
    for node in nodes:
        # if node is not url_digest:
        # send a request to a known node from a list
        try:
            response = requests.post(f'{node}/transactions/new/', data=transaction_digest)
            print(response)
        except Exception as e4:
            print(str(e4))


@csrf_exempt
def new_transaction(request):
    if request.method == 'POST':

        data = request.body
        values = json.loads(data)
        # values=json.loads(request.body)
        # return StreamingHttpResponse('it was post request: ' + str(values))

        # Check that the required fields are in the POST'ed data
        required = ['unique_id', 'sender', 'recipient', 'amount']
        if not all(k in values for k in required):
            return 'Missing values', 400

        # Create a new Transaction
        new_thread = Thread(target=save_new_transaction, args=(
        values['unique_id'], values['sender'], values['recipient'], values['amount'], values,))
        new_thread.start()
        new_thread.join()

        # index = save_new_transaction(values['unique_id'], values['sender'], values['recipient'], values['amount'],
        #                              values)

        message = {'message': 'Transaction will be added to new Block'}
        response = JsonResponse(message, status=201)
        return response

        # return StreamingHttpResponse('it was post request: ' + str(values))


@csrf_exempt
def register(request):
    if request.method == 'POST':

        values = json.loads(request.body)
        nodes = values.get('nodes')
        if nodes is None:
            return "Error: Please supply a valid list of nodes", 400

        for node in nodes:
            register_node(node)

        message = {
            'message': 'New nodes have been added',
            'total_nodes': list(nodes),
        }
        response = JsonResponse(message, status=201)
        return response


def send_digest_url(url_digest):
    urls = get_all_nodes_json()
    json_to_send = json.dumps({"nodes": urls, })
    # response = JsonResponse(json_to_send, status=200)

    nodes = Node.objects.all()
    for node in nodes:
        # if node is not url_digest:
        # send a request to a known node from a list
        try:
            response = requests.post(f'{node}/nodes/register/', data=json_to_send)
            print(response)
        except Exception as e4:
            print(str(e4))


def register_node(address):
    """
    Add a new node to the list of nodes
    :param address: Address of node. Eg. 'http://192.168.0.5:5000'
    """
    new_url_to_add = address['url']
    success = True
    new_node = Node()
    parsed_url = urlparse(new_url_to_add)
    if parsed_url.netloc:
        new_node.url = 'http://' + parsed_url.netloc
        try:
            new_node.save()
        except Exception as e2:
            success = False
            print(str(e2))
        # nodes.add(parsed_url.netloc)
    elif parsed_url.path:
        # Accepts an URL without scheme like '192.168.0.5:5000'.
        new_node.url = 'http://' + parsed_url.path
        try:
            new_node.save()
        except Exception as e3:
            success = False
            print(str(e3))
    else:
        raise ValueError('Invalid URL')
    if success:
        send_digest_url(new_node.url)
        print(new_node.url)


def valid_chain(chain):
    """
    Determine if a given blockchain is valid
    :param chain: A blockchain
    :return: True if valid, False if not
    """

    current_last_block = chain[0]
    current_index = 1

    while current_index < len(chain):
        following_last_block = chain[current_index]

        # print(f'{current_last_block}')
        # print(f'{following_last_block}')
        # print("\n-----------\n")
        # Check that the hash of the block is correct
        block_string = json.dumps(current_last_block).encode()
        last_block_hash = hash_check(current_last_block)
        previous_hash = following_last_block['previous_hash']
        if previous_hash != last_block_hash:
            return False

        # Check that the Proof of Work is correct
        val1 = current_last_block['proof']
        val2 = following_last_block['proof']
        val3 = current_last_block['previous_hash']
        if not valid_proof(val1, val2, val3):
            return False

        current_last_block = following_last_block
        current_index += 1

    return True


def resolve_conflicts():
    """
    This is our consensus algorithm, it resolves conflicts
    by replacing our chain with the longest one in the network.
    :return: True if our chain was replaced, False if not
    """
    nodes = Node.objects.all()
    new_chain = None

    # We're only looking for chains longer than ours
    max_length = Block.objects.all().count()

    # Grab and verify the chains from all the nodes in our network
    for node in nodes:
        url = node.url
        # send a request to a known node from a list
        try:
            response = requests.get(f'{url}/chain')
        except Exception as e4:
            print(str(e4))
        try:
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and valid_chain(chain):
                    max_length = length
                    new_chain = chain
        except Exception as e12:
            pass

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            Block.objects.all().delete()
            for item in chain:
                print(item)
                # one_element = item.json()
                new_item = Block()
                new_item.index = item['index']
                new_item.timestamp = item['timestamp']
                new_item.transactions = item['transactions']
                new_item.proof = item['proof']
                new_item.previous_hash = item['previous_hash']
                try:
                    new_item.save()
                except Exception as e5:
                    print(str(e5))
            return True

    return False


def new_block(proof, previous_hash):
    """
    Create a new Block in the Blockchain
    :param proof: The proof given by the Proof of Work algorithm
    :param previous_hash: Hash of previous Block
    :return: New Block
    """
    if Block.objects.all().count() > 0:
        latest_block = Block.objects.get(id=Block.objects.last().id)
    list_of_transactions = get_all_transactions()

    created_new_block = Block()
    if Block.objects.all().count() < 1:
        index = 0
    if Block.objects.all().count() > 0:
        index = Block.objects.all().count()
    index = index + 1
    timestamp = str(datetime.now())
    created_new_block.index = index
    created_new_block.timestamp = timestamp
    created_new_block.transactions = list_of_transactions
    created_new_block.proof = proof
    prev_hash = str(previous_hash)
    created_new_block.previous_hash = prev_hash or hash(latest_block)
    success = True
    try:
        created_new_block.save()
    except Exception as e6:
        print(str(e6))
        success = False

    # Reset the current list of transactions
    if success:
        unready = json.loads(list_of_transactions)
        for transaction in unready:
            unique_id = json.loads(transaction)["unique_id"]
            TransactionsBuffer.objects.filter(unique_id=unique_id).delete()
        just_created_block = Block.objects.get(id=Block.objects.last().id)
        print(str(just_created_block))
        created_block = get_last_block_json()
        print(str(created_block))
        return created_block
    if not success:
        created_block = None
        return created_block


def get_last_block():
    l_b = None
    try:
        l_b = Block.objects.get(id=Block.objects.last().id)
    except Exception as e11:
        resolve_conflicts()
    if l_b is not None:
        return l_b


def get_all_transactions():
    all_transactions = []
    for action in TransactionsBuffer.objects.all():
        transactions_to_dict = model_to_dict(action, fields=['unique_id', 'sender', 'recipient', 'amount'])
        serialized = json.dumps(transactions_to_dict)
        print(serialized)
        all_transactions.append(serialized)
    ready = json.dumps(all_transactions)
    unready = json.loads(ready)
    return ready


def get_last_block_json():
    transactions_to_dict = model_to_dict(Block.objects.last(),
                                         fields=['index', 'timestamp', 'transactions', 'proof', 'previous_hash'])
    ready = json.dumps(transactions_to_dict)
    return transactions_to_dict


def get_complete_blockchain_json():
    all_blocks_in_chains = []
    for block in Block.objects.all():
        block_in_chain = model_to_dict(block,
                                       fields=['index', 'timestamp', 'transactions', 'proof', 'previous_hash'])
        all_blocks_in_chains.append(block_in_chain)
    return all_blocks_in_chains


def get_all_nodes_json():
    all_nodes = []
    for node in Node.objects.all():
        node_in_list = model_to_dict(node, fields=['url'])
        all_nodes.append(node_in_list)
    return all_nodes


def get_transactions_buffer_json():
    all_transactions = []
    for transaction in TransactionsBuffer.objects.all():
        transaction_in_list = model_to_dict(transaction, fields=['sender', 'recipient', 'amount'])
        all_transactions.append(transaction_in_list)
    return all_transactions


def save_new_transaction(unique_id, sender, recipient, amount, values):
    """
    Creates a new transaction to go into the next mined Block
    :param unique_id:
    :param sender: Address of the Sender
    :param recipient: Address of the Recipient
    :param amount: Amount
    :return: The index of the Block that will hold this transaction
    """
    new_transaction = TransactionsBuffer()
    new_transaction.unique_id = str(unique_id)
    new_transaction.sender = str(sender)
    new_transaction.recipient = str(recipient)
    new_transaction.amount = int(amount)
    success = True
    try:
        new_transaction.save()
    except Exception as e7:
        success = False
        print(str(e7))
    if success:
        data = json.dumps(values)
        # new_thread = Thread(target=send_digest_transaction, args=(data,))
        # new_thread.start()
        # new_thread.join()
    if TransactionsBuffer.objects.count() > 0:
        latest_block = get_last_block()
        proof = proof_of_work(latest_block)
        new_transaction = TransactionsBuffer()
        new_transaction.unique_id = 'mining_payment'
        new_transaction.sender = '0'
        new_transaction.recipient = str(node_identifier)
        new_transaction.amount = int(1)
        success = True
        try:
            new_transaction.save()
        except Exception as e7:
            success = False
            print(str(e7))
        try:
            previous_hash = hash_it(latest_block)
        except Exception as e1:
            print(str(e1))
        created_block = new_block(proof, previous_hash)
        if created_block is not None:
            nodes = Node.objects.all()
            for node in nodes:
                new_thread = Thread(target=push_resolve_task, args=(node,))
                new_thread.start()
                new_thread.join()
        # resolve_conflicts()

    # last_object = get_last_block()
    # index_num = last_object.index + 1
    # return index_num


def postprocessing_save_transaction():
    pass


@property
def last_block(self):
    return Chain.objects.last()


def hash_check(block):
    print(str(block))
    block_string = json.dumps(block).encode()
    try:
        digest_result = hashlib.sha256(block_string).hexdigest()
    except Exception as e8:
        print(str(e8))
    return digest_result


def hash_it(block):
    """
    Creates a SHA-256 hash of a Block
    :param block: Block
    """
    print(str(block))
    # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
    block_string = json.dumps(
        model_to_dict(block, fields=['index', 'timestamp', 'transactions', 'proof', 'previous_hash'])).encode()

    try:
        digest_result = hashlib.sha256(block_string).hexdigest()
    except Exception as e9:
        print(str(e9))
    return digest_result


def proof_of_work(last_mined_block):
    """
    Simple Proof of Work Algorithm:
     - Find a number p' such that hash(pp') contains leading 4 zeroes
     - Where p is the previous proof, and p' is the new proof

    :param self:
    :param last_mined_block: <dict> last Block
    :return: <int>
    """
    last_proof = last_mined_block.proof
    last_hash = last_mined_block.previous_hash
    print(last_hash)

    proof = 0
    while valid_proof(last_proof, proof, last_hash) is False:
        proof += 1
        print(str(proof))

    return proof


def valid_proof(last_proof, proof, last_hash):
    """
    Validates the Proof
    :param last_proof: <int> Previous Proof
    :param proof: <int> Current Proof
    :param last_hash: <str> The hash of the Previous Block
    :return: <bool> True if correct, False if not.
    """

    guess = f'{last_proof}{proof}{last_hash}'.encode()
    guess_hash = hashlib.sha256(guess).hexdigest()
    return guess_hash[:5] == "00000"


# def periodic_task():
#     pass

resolve_conflicts()

try:
    if Block.objects.all().count() < 1:
        new_block(100, 'genesis_block_of_serg_chain')
except Exception as e10:
    print(str(e10))


def image(request):
    image_file = request.FILES['image_file'].file.read()
    Picture.objects.create(image=image_file)

# @api_view(['GET', 'POST'])
# def photo_list(request)
# ...
#
#
# elif request.method == 'POST':
#     d = request.data
#     serializer = PhotoSerializer(data=d)
#     if serializer.is_valid():
#         serializer.save()
#         return JsonResponse(serializer.data, status=201)
#     return JsonResponse(serializer.errors, status=400)
